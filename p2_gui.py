"""p2_gui.py — P2 Scanner GUI (single-file).

A Tkinter front-end for p2_scanner.py: edit site config in-app (no CLI needed),
discover/scan panels, browse points, read/walk points, dump PPCL, view history,
and export results. Requires p2_scanner.py (located at runtime) and its
firmware_registry.py helper.

This file is the merge of the former p2_gui.py + p2_gui_widgets.py + p2_gui_workers.py.
"""

from __future__ import annotations

import argparse
import csv as _csv
import json
import os
import queue
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Dict, List, Optional, Tuple
import threading
import time
import traceback
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from typing import Any, Callable, Hashable, Tuple
import datetime
from tkinter import ttk
from typing import Callable, Dict, Iterable, List, Optional, Tuple

# p2_scanner is located at runtime, not import time. The GUI zip and the
# scanner zip usually get extracted to different folders; we'd rather hunt
# for it (and prompt the user if needed) than fail on a rigid assumption.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Placeholder — populated by _locate_and_import_p2_scanner() in main().
# All references to `p2.something` throughout this module resolve at call
# time, so the module-global rebind works fine.
p2 = None  # type: ignore

_SCANNER_PATH_CACHE = os.path.join(_HERE, ".p2_gui_scanner_path")


def _enable_high_dpi() -> None:
    """Tell Windows we'll handle our own DPI scaling so it stops bitmap-
    scaling us into a blurry mess on high-DPI displays. No-op elsewhere.

    Called before tk.Tk() — the Tk root reads DPI at construction time."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # Try per-monitor-aware (Windows 8.1+) first; fall back to system DPI
        # aware; fall back to the old SetProcessDPIAware API.
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except (AttributeError, OSError):
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass
    except Exception:
        pass  # Not fatal — worst case the window is just fuzzy



# ═══ inlined from p2_gui_workers.py ═══════════════════════════════════════
class QueueWriter:
    """File-like adapter. Writes into `log_queue` as (term, line) tuples.

    `term` is '\\n' for normal lines, '\\r' for carriage-return progress
    updates (which the log pane uses to overwrite in place), or '' for a
    final flush of partial buffer contents.
    """

    def __init__(self, log_queue: "queue.Queue[Tuple[str, str]]") -> None:
        self._q = log_queue
        self._buf = ""

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._buf += s
        # Drain any complete lines (terminated by \n or \r). Emit them in
        # order with their terminator; \r lines let the log pane overwrite
        # the previous line, which is how the scanner's "Verifying: 4/12"
        # progress displays work on a real terminal.
        while True:
            nl = self._buf.find("\n")
            cr = self._buf.find("\r")
            if nl < 0 and cr < 0:
                break
            if nl < 0:
                end, term = cr, "\r"
            elif cr < 0:
                end, term = nl, "\n"
            elif cr < nl:
                end, term = cr, "\r"
            else:
                end, term = nl, "\n"
            line = self._buf[:end]
            self._buf = self._buf[end + 1 :]
            self._q.put((term, line))
        return len(s)

    def flush(self) -> None:
        if self._buf:
            self._q.put(("", self._buf))
            self._buf = ""


class _ThreadLocalStdio:
    """Stream proxy that routes writes to a per-thread target.

    ``contextlib.redirect_stdout`` rebinds the process-wide ``sys.stdout``, so a
    worker thread capturing scanner output also swallows prints from the main
    thread (and from any other thread) for the duration of the task. With one
    task in flight that mostly shows up as stray GUI output landing in a task
    log; with a listener and a scan running together the two interleave, and an
    exception during teardown can leave ``sys.stdout`` pointing at a dead
    QueueWriter for the rest of the process.

    This proxy is installed on ``sys.stdout``/``sys.stderr`` once, then each
    thread registers its own sink. Threads with no sink registered fall through
    to the real stream, so the console keeps working normally.
    """

    def __init__(self, real):
        self._real = real
        self._local = threading.local()

    def set_sink(self, sink) -> None:
        self._local.sink = sink

    def clear_sink(self) -> None:
        self._local.sink = None

    def _target(self):
        return getattr(self._local, "sink", None) or self._real

    def write(self, s):
        return self._target().write(s)

    def flush(self):
        target = self._target()
        if hasattr(target, "flush"):
            target.flush()

    def isatty(self):
        return False

    def __getattr__(self, name):
        return getattr(self._real, name)


# Installed once at import. Idempotent: re-importing will not double-wrap.
if not isinstance(sys.stdout, _ThreadLocalStdio):
    sys.stdout = _ThreadLocalStdio(sys.stdout)
if not isinstance(sys.stderr, _ThreadLocalStdio):
    sys.stderr = _ThreadLocalStdio(sys.stderr)


@contextmanager
def _thread_stdio(sink):
    """Route this thread's stdout/stderr to `sink` for the duration."""
    out, err = sys.stdout, sys.stderr
    set_out = isinstance(out, _ThreadLocalStdio)
    set_err = isinstance(err, _ThreadLocalStdio)
    if set_out:
        out.set_sink(sink)
    if set_err:
        err.set_sink(sink)
    try:
        yield
    finally:
        if set_out:
            out.clear_sink()
        if set_err:
            err.clear_sink()


class TaskRunner:
    """Submits scanner calls to a single daemon worker thread.

    Results arrive on `result_queue` as tuples:
        (task_id, 'ok', return_value, elapsed_seconds)
        (task_id, 'error', (exception, traceback_str), elapsed_seconds)
        (task_id, 'cancelled', None, elapsed_seconds)

    Only one task may be in flight at once. submit() returns False if busy.

    Cancellation:
        `cancel()` sets `stop_event`. Long-running scanner functions that
        accept a stop_event can poll it and return early with a partial
        or None result. Even if the scanner doesn't cooperate, the daemon
        thread dies when the main thread exits — so closing the GUI will
        always terminate the worker.
    """

    def __init__(
        self,
        log_queue: "queue.Queue[Tuple[str, str]]",
        result_queue: "queue.Queue[tuple]",
    ) -> None:
        self.log_queue = log_queue
        self.result_queue = result_queue
        self._lock = threading.Lock()
        self._busy = False
        self._current_task: Hashable = None
        self._current_thread: threading.Thread | None = None
        # threading.Event for cooperative cancel. Long-running scanner
        # functions that take a `stop_event` kwarg can poll this.
        self.stop_event = threading.Event()

    @property
    def busy(self) -> bool:
        return self._busy

    @property
    def current_task(self) -> Hashable:
        return self._current_task

    def submit(
        self,
        task_id: Hashable,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        """Try to submit. Returns True if accepted, False if worker busy."""
        with self._lock:
            if self._busy:
                return False
            self._busy = True
            self._current_task = task_id
            # Fresh event for this task — previous cancel() shouldn't
            # leak into the next submission.
            self.stop_event = threading.Event()
        t = threading.Thread(
            target=self._run,
            args=(task_id, func, args, kwargs),
            name=f"p2-worker-{task_id}",
            daemon=True,
        )
        self._current_thread = t
        t.start()
        return True

    def cancel(self) -> None:
        """Signal the running task to stop at its next checkpoint.

        Cooperative — the running function must poll `stop_event` to
        honor it. If the function doesn't, the worker continues until
        it finishes naturally OR the main thread exits (which kills
        the daemon worker).
        """
        self.stop_event.set()

    def _run(
        self,
        task_id: Hashable,
        func: Callable[..., Any],
        args: tuple,
        kwargs: dict,
    ) -> None:
        start = time.time()
        writer = QueueWriter(self.log_queue)
        try:
            with _thread_stdio(writer):
                result = func(*args, **kwargs)
                writer.flush()
            if self.stop_event.is_set():
                # Function returned normally but cancel was requested
                # during its run. Surface as 'cancelled' so the GUI
                # can show "Cancelled" rather than "Completed".
                self.result_queue.put(
                    (task_id, "cancelled", result, time.time() - start))
            else:
                self.result_queue.put(
                    (task_id, "ok", result, time.time() - start))
        except BaseException as e:  # noqa: BLE001 - we want to surface everything
            try:
                writer.flush()
            except Exception:
                pass
            tb = traceback.format_exc()
            self.result_queue.put(
                (task_id, "error", (e, tb), time.time() - start)
            )
        finally:
            with self._lock:
                self._busy = False
                self._current_task = None

    def shutdown(self, wait: bool = False) -> None:
        """Signal current task to cancel. Worker is a daemon thread, so
        the process exits regardless when the main thread ends; this
        method just sets the cancel flag so well-behaved scanner
        functions can clean up sockets before the daemon dies.
        """
        self.stop_event.set()
        # No executor to shut down — using bare threading.Thread.

# ═══ inlined from p2_gui_widgets.py ═══════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
# WINDOW PLACEMENT HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _center_on_parent(
    win: tk.Toplevel,
    parent: tk.Misc,
    width: Optional[int] = None,
    height: Optional[int] = None,
) -> None:
    """Center `win` over its parent's top-level window, clamped to the
    visible screen. Call after the window's widgets are laid out (we do
    an update_idletasks internally) so natural sizes are reliable.

    width/height are optional; if omitted the window's current/requested
    size is used. Pass them when you've set an explicit geometry string
    (e.g. "880x480") so the size survives the subsequent geometry() call
    that sets the +x+y position.
    """
    win.update_idletasks()

    if width is None:
        w = win.winfo_width()
        if w <= 1:
            w = win.winfo_reqwidth()
        width = w
    if height is None:
        h = win.winfo_height()
        if h <= 1:
            h = win.winfo_reqheight()
        height = h

    try:
        top = parent.winfo_toplevel()
        px = top.winfo_rootx()
        py = top.winfo_rooty()
        pw = top.winfo_width()
        ph = top.winfo_height()
    except tk.TclError:
        # Parent gone / not yet mapped — fall back to screen-center
        px, py = 0, 0
        pw, ph = win.winfo_screenwidth(), win.winfo_screenheight()

    # If the parent isn't mapped yet (width 1, height 1), center on screen
    if pw <= 1 or ph <= 1:
        pw, ph = win.winfo_screenwidth(), win.winfo_screenheight()
        px, py = 0, 0

    x = px + (pw - width) // 2
    y = py + (ph - height) // 2

    # Clamp so the window is fully on-screen. Accept a small top margin
    # for the window chrome.
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = max(0, min(x, sw - width))
    y = max(0, min(y, sh - height))

    win.geometry(f"{width}x{height}+{x}+{y}")


# ═══════════════════════════════════════════════════════════════════════════
# LOG PANE
# ═══════════════════════════════════════════════════════════════════════════

class LogPane(ttk.Frame):
    """Scrolling log. Drains a queue of (term, line) tuples from the
    worker thread via a polled method called from the Tk event loop.

    A mark is kept at the start of the 'current' line so \\r progress
    updates can overwrite it without leaving trails in the buffer.
    """

    def __init__(self, parent: tk.Misc, log_queue: "queue.Queue[Tuple[str, str]]") -> None:
        super().__init__(parent)
        self._q = log_queue

        self._text = tk.Text(
            self,
            wrap="none",
            bg="#1b1b1b",
            fg="#d4d4d4",
            insertbackground="#d4d4d4",
            font=("Consolas", 9) if self._has_consolas() else ("Courier", 9),
            height=10,
            borderwidth=0,
        )
        sby = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        sbx = ttk.Scrollbar(self, orient="horizontal", command=self._text.xview)
        self._text.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)

        clear_btn = ttk.Button(self, text="Clear", command=self.clear, width=8)

        self._text.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        sbx.grid(row=1, column=0, sticky="ew")
        clear_btn.grid(row=1, column=1, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Tags for line-level coloring
        self._text.tag_configure("ts", foreground="#888")
        self._text.tag_configure("info", foreground="#d4d4d4")
        self._text.tag_configure("warn", foreground="#d1a33a")
        self._text.tag_configure("error", foreground="#e06c75")
        self._text.tag_configure("ok", foreground="#8fc974")

        self._text.mark_set("lineanchor", "1.0")
        self._text.mark_gravity("lineanchor", "left")
        self._last_was_cr = False
        self._text.configure(state="disabled")

    def _has_consolas(self) -> bool:
        try:
            import tkinter.font as tkfont
            return "Consolas" in tkfont.families()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def poll(self) -> None:
        """Drain the queue into the widget. Call periodically from the UI loop."""
        appended = False
        drained = 0
        # Cap work per poll so a flood of output doesn't freeze the UI
        while drained < 500:
            try:
                term, line = self._q.get_nowait()
            except queue.Empty:
                break
            self._append_raw(term, line)
            appended = True
            drained += 1
        if appended:
            self._text.see("end")

    def log(self, message: str, level: str = "info") -> None:
        """Write a UI-originated message to the log with timestamp + tag."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._text.configure(state="normal")
        try:
            # If we were mid-progress-line, finish it
            if self._last_was_cr:
                self._text.insert("end-1c", "\n")
                self._last_was_cr = False
            self._text.insert("end-1c", f"[{ts}] ", ("ts",))
            self._text.insert("end-1c", message + "\n", (level,))
            self._text.mark_set("lineanchor", "end-1c")
        finally:
            self._text.configure(state="disabled")
        self._text.see("end")

    def clear(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.mark_set("lineanchor", "1.0")
        self._text.configure(state="disabled")
        self._last_was_cr = False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _append_raw(self, term: str, line: str) -> None:
        self._text.configure(state="normal")
        try:
            if self._last_was_cr:
                # Overwrite from the anchor forward
                self._text.delete("lineanchor", "end-1c")
            if line:
                self._text.insert("end-1c", line)
            if term == "\n":
                self._text.insert("end-1c", "\n")
                self._text.mark_set("lineanchor", "end-1c")
                self._last_was_cr = False
            elif term == "\r":
                self._last_was_cr = True
            else:
                # Empty terminator = buffer flush at end of run
                self._text.mark_set("lineanchor", "end-1c")
                self._last_was_cr = False
        finally:
            self._text.configure(state="disabled")


# ═══════════════════════════════════════════════════════════════════════════
# POINT RESULT TABLE
# ═══════════════════════════════════════════════════════════════════════════

PTYPE_LABEL = {
    "analog_ro": "AI",
    "analog_rw": "AO",
    "digital_ro": "BI",
    "digital_rw": "BO",
}


def _format_value_cell(result: Dict) -> str:
    """Render the Value column: digital gets 'LABEL (raw)', analog gets a float."""
    val_text = result.get("value_text") or ""
    raw = result.get("value")

    if val_text:
        # Digital: "NIGHT (1)" style
        if raw is not None:
            try:
                return f"{val_text} ({int(raw)})"
            except (TypeError, ValueError):
                return val_text
        return val_text

    if raw is None:
        return "—"
    try:
        f = float(raw)
    except (TypeError, ValueError):
        return str(raw)
    if abs(f - round(f)) < 0.01:
        return f"{f:.0f}"
    return f"{f:.2f}"


class PointTable(ttk.Frame):
    """Treeview of point results. Call load(results) to replace contents."""

    COLUMNS = (
        # (key, label, width, anchor)
        ("slot", "Slot", 55, "center"),
        ("name", "Point Name", 210, "w"),
        ("value", "Value", 140, "e"),
        ("units", "Units", 70, "center"),
        ("type", "Type", 55, "center"),
        ("status", "Status", 70, "center"),
    )

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        keys = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(self, columns=keys, show="headings")
        for key, label, width, anchor in self.COLUMNS:
            self._tree.heading(
                key, text=label, command=lambda k=key: self._sort_by(k)
            )
            self._tree.column(key, width=width, anchor=anchor, stretch=(key == "name"))

        sby = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._tree.tag_configure(
            "comm_fault", background="#ffeee5", foreground="#8a2a00"
        )
        self._tree.tag_configure(
            "unknown", background="#f5f5f5", foreground="#888"
        )

        self._results: List[Dict] = []
        self._sort_key = "slot"
        self._sort_reverse = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clear(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._results = []

    def load(self, results: Iterable[Dict]) -> None:
        self._results = list(results)
        self._render()

    def results(self) -> List[Dict]:
        return list(self._results)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sort_by(self, key: str) -> None:
        if key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False
        self._render()

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)

        def sort_tuple(r: Dict):
            k = self._sort_key
            if k == "slot":
                s = r.get("point_slot")
                return (s if s is not None else 10_000, r.get("point_name", ""))
            if k == "name":
                return (r.get("point_name", "").lower(),)
            if k == "value":
                v = r.get("value")
                return (float("inf") if v is None else v,)
            if k == "units":
                return (r.get("units") or "",)
            if k == "type":
                return (((r.get("point_info") or {}).get("type")) or "",)
            if k == "status":
                return (r.get("comm_status") or "~",)
            return (r.get("point_name", ""),)

        rows = sorted(self._results, key=sort_tuple, reverse=self._sort_reverse)

        for r in rows:
            slot = r.get("point_slot")
            slot_str = f"({slot})" if slot is not None else ""
            name = r.get("point_name", "?")
            value_str = _format_value_cell(r)
            units = r.get("units") or ""
            info = r.get("point_info") or {}
            type_str = PTYPE_LABEL.get(info.get("type", ""), info.get("type") or "?")

            comm = r.get("comm_status") or ""
            if comm == "online":
                status, tag = "✓ OK", ""
            elif comm == "comm_fault":
                status, tag = "✗ #COM", "comm_fault"
            else:
                status, tag = "—", "unknown"

            self._tree.insert(
                "",
                "end",
                values=(slot_str, name, value_str, units, type_str, status),
                tags=(tag,) if tag else (),
            )


# ═══════════════════════════════════════════════════════════════════════════
# NODE / DEVICE TREE
# ═══════════════════════════════════════════════════════════════════════════

class NodeTree(ttk.Frame):
    """Hierarchical tree: Network → Nodes → Devices.

    Selection callbacks receive the node or device payload dict.
    """

    def __init__(
        self,
        parent: tk.Misc,
        on_select_node: Optional[Callable[[Dict], None]] = None,
        on_select_device: Optional[Callable[[Dict], None]] = None,
    ) -> None:
        super().__init__(parent)
        self._tree = ttk.Treeview(self, show="tree", selectmode="browse")
        sby = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Foreground color tags give the tree its online/offline legibility.
        # Kept muted enough not to overwhelm when there are 60+ rows visible.
        self._tree.tag_configure("status_online", foreground="#0a7a0a")
        self._tree.tag_configure("status_offline", foreground="#a82020")
        self._tree.tag_configure("status_unknown", foreground="#666666")
        # Amber for FLN comm-fault — distinct from a totally unreachable
        # device because the panel still has cached data and APPLICATION
        # is readable. Matches Desigo's #COM convention.
        self._tree.tag_configure("status_comm_fault", foreground="#a06010")
        # Node-level status tags. Same color palette as devices but
        # rendered in bold so the panel's own state stands out from the
        # devices hanging off it. A node can be online (PXC responding to
        # P2 handshakes) or offline (TCP refused / handshake failed) —
        # this lets the user spot a dead PXC even when it has zero FLN
        # devices, which the device-level Verify can't show.
        try:
            import tkinter.font as _tkfont
            _default = _tkfont.nametofont("TkDefaultFont")
            _bold = (_default.cget("family"), _default.cget("size"), "bold")
            self._tree.tag_configure(
                "node_online", foreground="#0a7a0a", font=_bold
            )
            self._tree.tag_configure(
                "node_offline", foreground="#a82020", font=_bold
            )
            self._tree.tag_configure(
                "node_unknown", foreground="#666666", font=_bold
            )
        except Exception:
            self._tree.tag_configure("node_online", foreground="#0a7a0a")
            self._tree.tag_configure("node_offline", foreground="#a82020")
            self._tree.tag_configure("node_unknown", foreground="#666666")
        try:
            import tkinter.font as tkfont
            default = tkfont.nametofont("TkDefaultFont")
            bold = (default.cget("family"), default.cget("size"), "bold")
            self._tree.tag_configure("network_root", font=bold)
        except Exception:
            pass

        self._on_select_node = on_select_node
        self._on_select_device = on_select_device
        self._tree.bind("<<TreeviewSelect>>", self._handle_select)

        # iid -> (kind, payload)
        self._data: Dict[str, Tuple[str, Dict]] = {}
        self._network_iid: Optional[str] = None
        self._node_iid_by_name: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_network(self, network_name: str) -> None:
        """Reset the tree and set (or refresh) the network root label."""
        self._tree.delete(*self._tree.get_children())
        self._data.clear()
        self._node_iid_by_name.clear()
        label = f"⌬  {network_name}" if network_name else "⌬  (no network configured)"
        self._network_iid = self._tree.insert(
            "", "end", text=label, open=True, tags=("network_root",)
        )

    def _format_node_row(self, name: str, ip: str, status: str,
                         telnet: Optional[bool]) -> str:
        """Render the tree row text for a node row.

        Layout: `<status-marker>  <name>   <ip>  <telnet-marker>`
            status-marker: ● online / ○ offline / ▸ unknown
            telnet-marker: 📡 (open) / · (closed) / blank (unknown)

        Telnet marker mirrors what Desigo CC's "Field Network" view
        shows per panel — at a glance, the operator can spot which
        panels accept telnet for nodeNametable / Fieldpanels cleanup
        without trying each in turn.
        """
        marker = {"online": "●", "offline": "○"}.get(status, "▸")
        if telnet is True:
            telnet_marker = "  📡 telnet"
        elif telnet is False:
            telnet_marker = "  · telnet closed"
        else:
            telnet_marker = ""
        return f"{marker}  {name}   {ip}{telnet_marker}"

    def add_node(self, name: str, ip: str,
                 telnet_open: Optional[bool] = None) -> str:
        if self._network_iid is None:
            self.set_network("")
        assert self._network_iid is not None
        # Initial status is "unknown" (gray ▸) — flips to online/offline
        # once any operation against the panel succeeds or fails. The
        # arrow marker `▸` is kept as the closed-folder hint; we prepend
        # a status dot when status becomes known.
        iid = self._tree.insert(
            self._network_iid,
            "end",
            text=self._format_node_row(name, ip, "unknown", telnet_open),
            open=False,
            tags=("node_unknown",),
        )
        self._data[iid] = (
            "node",
            {"name": name, "ip": ip, "status": "unknown",
             "telnet_open": telnet_open},
        )
        self._node_iid_by_name[name] = iid
        return iid

    def set_node_status(self, name: str, status: str) -> bool:
        """Update a node row's status indicator.

        status: 'online', 'offline', or 'unknown'.

        Online means the PXC accepted a TCP connection and completed a
        P2 handshake; offline means it refused, timed out, or rejected
        the handshake. This is independent of whether the node has any
        FLN devices — exactly the signal the device-level Verify can't
        provide for nodes that only host PPCL programs / global points.
        """
        iid = self._node_iid_by_name.get(name)
        if iid is None:
            return False
        entry = self._data.get(iid)
        if not (entry and entry[0] == "node"):
            return False
        ip = entry[1].get("ip", "")
        telnet_open = entry[1].get("telnet_open")
        tag = {
            "online": "node_online",
            "offline": "node_offline",
        }.get(status, "node_unknown")
        # Preserve the open/closed state — set_node_status can fire
        # mid-session and shouldn't snap a folder shut.
        was_open = bool(self._tree.item(iid, "open"))
        self._tree.item(
            iid,
            text=self._format_node_row(name, ip, status, telnet_open),
            tags=(tag,),
            open=was_open,
        )
        entry[1]["status"] = status
        return True

    def set_node_telnet(self, name: str, telnet_open: Optional[bool]) -> bool:
        """Update a node row's telnet-availability indicator.

        telnet_open: True (📡 visible), False (·), or None (unknown — clear).

        Independent of the online/offline P2-handshake status: a panel
        can be P2-online with telnet disabled (operator policy), or
        P2-offline with telnet still listening (TCP layer up but P2
        bouncer is rejecting). Both states are useful to surface.
        """
        iid = self._node_iid_by_name.get(name)
        if iid is None:
            return False
        entry = self._data.get(iid)
        if not (entry and entry[0] == "node"):
            return False
        ip = entry[1].get("ip", "")
        status = entry[1].get("status", "unknown")
        # Reuse the existing tag (online/offline/unknown) — telnet
        # display is appended to the row text but doesn't override
        # the foreground color tag.
        current_tags = self._tree.item(iid, "tags")
        tag = current_tags[0] if current_tags else "node_unknown"
        was_open = bool(self._tree.item(iid, "open"))
        self._tree.item(
            iid,
            text=self._format_node_row(name, ip, status, telnet_open),
            tags=(tag,),
            open=was_open,
        )
        entry[1]["telnet_open"] = telnet_open
        return True

    def clear_nodes(self) -> None:
        """Remove all nodes (and their devices), keep the network root."""
        if self._network_iid is None:
            return
        for child in list(self._tree.get_children(self._network_iid)):
            self._remove_subtree(child)

    def set_node_devices(self, node_name: str, devices: List[Dict]) -> None:
        node_iid = self._node_iid_by_name.get(node_name)
        if node_iid is None:
            return
        # Remove existing device children
        for child in list(self._tree.get_children(node_iid)):
            self._remove_subtree(child)

        payload_node = self._data[node_iid][1]

        for dev in devices:
            status = dev.get("status") or "unknown"
            comm = dev.get("comm_status")
            # Distinguish "FLN-faulted but APPLICATION-cached" (amber #COM)
            # from "totally unreachable" (red ○) and "live" (green ●).
            # Devices with comm_status='comm_fault' are always classified
            # offline by the scanner now, but we render them with the
            # amber tag and a #COM marker so the user can tell at a
            # glance which are wired-but-failing vs. genuinely missing.
            if comm == "comm_fault":
                marker = "◐"
                tag = "status_comm_fault"
            else:
                marker = {"online": "●", "offline": "○"}.get(status, "◌")
                tag = {
                    "online": "status_online",
                    "offline": "status_offline",
                }.get(status, "status_unknown")
            app = dev.get("application", 0) or 0
            app_cached = dev.get("application_cached", False)
            # Pull the v2 catalog description (`_meta.descr`) for the app so the
            # GUI tree shows "app 2020 — VAV Cooling Only" instead of just
            # "app 2020". Falls back to the bare form on v1 catalogs or
            # unknown apps. Import lazily to keep p2_gui_widgets importable
            # in environments without the scanner module on path.
            app_descr = ""
            if app:
                try:
                    import p2_scanner as _p2_for_descr  # type: ignore
                    _meta = _p2_for_descr.get_app_meta(app)
                    if _meta and isinstance(_meta.get("descr"), str) and _meta["descr"]:
                        app_descr = f" — {_meta['descr']}"
                except Exception:
                    pass

            if app and app_cached:
                app_str = f"app {app} (cached){app_descr}"
            elif app:
                app_str = f"app {app}{app_descr}"
            elif comm == "comm_fault":
                app_str = "#COM"
            else:
                app_str = ""
            dev_name = dev["device"]
            label = f"  {marker}  {dev_name:<18s} {app_str}"
            iid = self._tree.insert(node_iid, "end", text=label, tags=(tag,))
            self._data[iid] = (
                "device",
                {
                    "node": payload_node["name"],
                    "host": payload_node["ip"],
                    "device": dev_name,
                    "application": app,
                    "application_cached": app_cached,
                    "status": status,
                    "comm_status": comm,
                    "description": dev.get("description", ""),
                    "room_temp": dev.get("room_temp"),
                    "stale_temp": dev.get("stale_temp"),
                    "units": dev.get("units", ""),
                },
            )
        self._tree.item(node_iid, open=True)

    def update_device_status(
        self, node_name: str, device_name: str, updated: Dict
    ) -> bool:
        """Update a single device row in place — for live-verify progress
        where we want the row to flip color as each device is checked
        instead of waiting for the whole batch. Returns True if the row
        was found and updated, False otherwise."""
        node_iid = self._node_iid_by_name.get(node_name)
        if node_iid is None:
            return False
        for child in self._tree.get_children(node_iid):
            entry = self._data.get(child)
            if not (entry and entry[0] == "device"):
                continue
            if entry[1].get("device") != device_name:
                continue

            status = updated.get("status") or entry[1].get("status", "unknown")
            comm = updated.get("comm_status", entry[1].get("comm_status"))
            app = updated.get("application", entry[1].get("application", 0)) or 0
            app_cached = updated.get(
                "application_cached", entry[1].get("application_cached", False)
            )
            if comm == "comm_fault":
                marker = "◐"
                tag = "status_comm_fault"
            else:
                marker = {"online": "●", "offline": "○"}.get(status, "◌")
                tag = {
                    "online": "status_online",
                    "offline": "status_offline",
                }.get(status, "status_unknown")
            if app and app_cached:
                app_str = f"app {app} (cached)"
            elif app:
                app_str = f"app {app}"
            elif comm == "comm_fault":
                app_str = "#COM"
            else:
                app_str = ""
            label = f"  {marker}  {device_name:<18s} {app_str}"
            self._tree.item(child, text=label, tags=(tag,))

            # Merge the update into our stored payload so the detail panel
            # picks up fresh data on next selection.
            entry[1]["status"] = status
            entry[1]["application"] = app
            if comm is not None:
                entry[1]["comm_status"] = comm
            if app_cached:
                entry[1]["application_cached"] = app_cached
            if "room_temp" in updated:
                entry[1]["room_temp"] = updated["room_temp"]
            if "stale_temp" in updated:
                entry[1]["stale_temp"] = updated["stale_temp"]
            if "units" in updated:
                entry[1]["units"] = updated["units"]
            return True
        return False

    def selected(self) -> Optional[Tuple[str, Dict]]:
        sel = self._tree.selection()
        if not sel:
            return None
        return self._data.get(sel[0])

    def selected_node_payload(self) -> Optional[Dict]:
        """Return the node dict, whether a node OR one of its devices is selected."""
        sel = self._tree.selection()
        if not sel:
            return None
        iid = sel[0]
        entry = self._data.get(iid)
        if entry and entry[0] == "node":
            return entry[1]
        if entry and entry[0] == "device":
            parent = self._tree.parent(iid)
            parent_entry = self._data.get(parent)
            if parent_entry and parent_entry[0] == "node":
                return parent_entry[1]
        return None

    def node_payload(self, name: str) -> Optional[Dict]:
        """Return the stored payload for a node by name.

        Useful when the caller has a node name and wants the latest
        copy of its payload — including any status updates pushed via
        set_node_status — without going through the selection machinery.
        """
        iid = self._node_iid_by_name.get(name)
        if iid is None:
            return None
        entry = self._data.get(iid)
        if not (entry and entry[0] == "node"):
            return None
        return entry[1]

    def select_node(self, name: str) -> None:
        iid = self._node_iid_by_name.get(name)
        if iid:
            self._tree.selection_set(iid)
            self._tree.focus(iid)
            self._tree.see(iid)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _remove_subtree(self, iid: str) -> None:
        for child in list(self._tree.get_children(iid)):
            self._remove_subtree(child)
        self._data.pop(iid, None)
        # Also drop from node name index if this was a node
        for nm, niid in list(self._node_iid_by_name.items()):
            if niid == iid:
                del self._node_iid_by_name[nm]
                break
        self._tree.delete(iid)

    def _handle_select(self, _event=None) -> None:
        s = self.selected()
        if not s:
            return
        kind, payload = s
        if kind == "node" and self._on_select_node:
            self._on_select_node(payload)
        elif kind == "device" and self._on_select_device:
            self._on_select_device(payload)


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG / SINGLE-POINT DIALOGS
# ═══════════════════════════════════════════════════════════════════════════

class _NodeEditDialog(tk.Toplevel):
    """Small name+IP dialog used by ConfigDialog."""

    def __init__(self, parent: tk.Misc, title: str, name: str, ip: str) -> None:
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)

        body = ttk.Frame(self, padding=12)
        body.pack()

        ttk.Label(body, text="Node Name:").grid(row=0, column=0, sticky="w", pady=2)
        self._name_var = tk.StringVar(value=name)
        e1 = ttk.Entry(body, textvariable=self._name_var, width=22)
        e1.grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(body, text="IP Address:").grid(row=1, column=0, sticky="w", pady=2)
        self._ip_var = tk.StringVar(value=ip)
        ttk.Entry(body, textvariable=self._ip_var, width=22).grid(
            row=1, column=1, sticky="ew", pady=2
        )

        self.result: Optional[Tuple[str, str]] = None

        btns = ttk.Frame(body)
        btns.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(
            side="right", padx=2
        )
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right", padx=2)

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())

        e1.focus_set()
        _center_on_parent(self, parent)
        self.grab_set()

    def _ok(self) -> None:
        n = self._name_var.get().strip()
        i = self._ip_var.get().strip()
        if not n or not i:
            return
        self.result = (n, i)
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(
        cls, parent: tk.Misc, title: str, name: str = "", ip: str = ""
    ) -> Optional[Tuple[str, str]]:
        dlg = cls(parent, title, name, ip)
        dlg.wait_window()
        return dlg.result


class ConfigDialog(tk.Toplevel):
    """Modal editor for site.json content."""

    def __init__(self, parent: tk.Misc, config: Dict) -> None:
        super().__init__(parent)
        self.title("Site Configuration")
        self.transient(parent)
        self.resizable(False, True)

        self._cfg: Dict = {
            "p2_network": config.get("p2_network", ""),
            "p2_site": config.get("p2_site", ""),
            "scanner_name": config.get("scanner_name", "P2SCAN-LAP|5033"),
            "known_nodes": dict(config.get("known_nodes", {})),
        }
        # Preserve any unknown keys so save-round-trip doesn't drop them
        self._extras: Dict = {
            k: v
            for k, v in config.items()
            if k not in ("p2_network", "p2_site", "scanner_name", "known_nodes")
        }
        self.result: Optional[Dict] = None

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        # --- P2 identity fields ---
        ttk.Label(body, text="BLN Network Name:").grid(row=0, column=0, sticky="w", pady=2)
        self._net_var = tk.StringVar(value=self._cfg["p2_network"])
        ttk.Entry(body, textvariable=self._net_var, width=34).grid(
            row=0, column=1, sticky="ew", pady=2
        )

        ttk.Label(body, text="Site Name:").grid(row=1, column=0, sticky="w", pady=2)
        self._site_var = tk.StringVar(value=self._cfg["p2_site"])
        ttk.Entry(body, textvariable=self._site_var, width=34).grid(
            row=1, column=1, sticky="ew", pady=2
        )

        ttk.Label(body, text="Scanner Name:").grid(row=2, column=0, sticky="w", pady=2)
        self._scanner_var = tk.StringVar(value=self._cfg["scanner_name"])
        scanner_entry = ttk.Entry(body, textvariable=self._scanner_var, width=34)
        scanner_entry.grid(row=2, column=1, sticky="ew", pady=2)

        # Effective-on-wire label. The scanner library's
        # `effective_scanner_name()` silently substitutes the configured
        # value when it equals the generic default and Site Name is set:
        # the wire actually carries `<SITE>DCC-SVR|5033`, not the configured
        # default. Without this label the operator has no way to see what
        # name is actually being sent in slot 4 of handshakes. Updates live
        # as Site Name or Scanner Name change.
        self._effective_label = ttk.Label(
            body,
            text="",
            foreground="#0a6020",
            wraplength=460,
            justify="left",
        )
        self._effective_label.grid(row=3, column=0, columnspan=2,
                                   sticky="w", pady=(2, 2))

        def _update_effective(*_args):
            configured = self._scanner_var.get().strip()
            site = self._site_var.get().strip()
            generic_default = "P2SCAN-LAP|5033"
            if not configured:
                effective = ""
                note = "(empty — handshake will fail)"
            elif configured == generic_default and site:
                effective = f"{site.upper()}DCC-SVR|5033"
                note = "(auto-built from Site Name; configured value is the generic default)"
            else:
                effective = configured
                note = "(used as-is)"
            if effective:
                self._effective_label.configure(
                    text=f"→ Effective on wire: {effective}  {note}")
            else:
                self._effective_label.configure(
                    text=f"→ {note}")

        self._scanner_var.trace_add("write", _update_effective)
        self._site_var.trace_add("write", _update_effective)
        _update_effective()  # initial fill

        hint = ttk.Label(
            body,
            text=(
                "Scanner format tip: sites sometimes require <SITE>DCC-SVR|5033 "
                "(the Desigo CC server identity) instead of the generic default. "
                "The 'Effective on wire' line above shows what name will actually "
                "be sent in slot 4 of every handshake."
            ),
            foreground="#777",
            wraplength=460,
            justify="left",
        )
        hint.grid(row=4, column=0, columnspan=2, sticky="w", pady=(2, 8))

        # --- Known nodes ---
        ttk.Label(body, text="Known Nodes:", font=("", 10, "bold")).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(4, 4)
        )

        nodes_frame = ttk.Frame(body)
        nodes_frame.grid(row=6, column=0, columnspan=2, sticky="nsew")
        body.rowconfigure(6, weight=1)
        body.columnconfigure(1, weight=1)

        self._nodes_tree = ttk.Treeview(
            nodes_frame,
            columns=("name", "ip"),
            show="headings",
            height=9,
            selectmode="browse",
        )
        self._nodes_tree.heading("name", text="Node Name")
        self._nodes_tree.heading("ip", text="IP Address")
        self._nodes_tree.column("name", width=160)
        self._nodes_tree.column("ip", width=160)
        self._nodes_tree.grid(row=0, column=0, sticky="nsew")
        nsb = ttk.Scrollbar(nodes_frame, orient="vertical", command=self._nodes_tree.yview)
        self._nodes_tree.configure(yscrollcommand=nsb.set)
        nsb.grid(row=0, column=1, sticky="ns")
        nodes_frame.rowconfigure(0, weight=1)
        nodes_frame.columnconfigure(0, weight=1)
        self._nodes_tree.bind("<Double-1>", lambda _e: self._edit_node())

        self._refresh_nodes()

        node_btns = ttk.Frame(body)
        node_btns.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        ttk.Button(node_btns, text="Add…", command=self._add_node).pack(side="left", padx=2)
        ttk.Button(node_btns, text="Edit…", command=self._edit_node).pack(side="left", padx=2)
        ttk.Button(node_btns, text="Remove", command=self._remove_node).pack(
            side="left", padx=2
        )

        # --- OK / Cancel ---
        btns = ttk.Frame(body)
        btns.grid(row=7, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=4)
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right", padx=4)

        self.bind("<Escape>", lambda _e: self._cancel())
        _center_on_parent(self, parent)
        self.grab_set()

    # ------------------------------------------------------------------

    def _refresh_nodes(self) -> None:
        for iid in self._nodes_tree.get_children():
            self._nodes_tree.delete(iid)
        for name, ip in sorted(self._cfg["known_nodes"].items()):
            self._nodes_tree.insert("", "end", iid=name, values=(name, ip))

    def _add_node(self) -> None:
        r = _NodeEditDialog.ask(self, "Add Node")
        if r:
            name, ip = r
            self._cfg["known_nodes"][name] = ip
            self._refresh_nodes()

    def _edit_node(self) -> None:
        sel = self._nodes_tree.selection()
        if not sel:
            return
        old_name = sel[0]
        old_ip = self._cfg["known_nodes"].get(old_name, "")
        r = _NodeEditDialog.ask(self, "Edit Node", old_name, old_ip)
        if r:
            name, ip = r
            if name != old_name:
                self._cfg["known_nodes"].pop(old_name, None)
            self._cfg["known_nodes"][name] = ip
            self._refresh_nodes()

    def _remove_node(self) -> None:
        sel = self._nodes_tree.selection()
        if not sel:
            return
        self._cfg["known_nodes"].pop(sel[0], None)
        self._refresh_nodes()

    def _ok(self) -> None:
        self._cfg["p2_network"] = self._net_var.get().strip()
        self._cfg["p2_site"] = self._site_var.get().strip()
        self._cfg["scanner_name"] = (
            self._scanner_var.get().strip() or "P2SCAN-LAP|5033"
        )
        merged = dict(self._extras)
        merged.update(self._cfg)
        self.result = merged
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(cls, parent: tk.Misc, config: Dict) -> Optional[Dict]:
        dlg = cls(parent, config)
        dlg.wait_window()
        return dlg.result


class SinglePointDialog(tk.Toplevel):
    """Prompt for a point name OR slot number, plus the force-slot option."""

    def __init__(
        self,
        parent: tk.Misc,
        device_name: str,
        application: Optional[int] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"Read Point — {device_name}")
        self.transient(parent)
        self.resizable(False, False)

        body = ttk.Frame(self, padding=12)
        body.pack()

        ttk.Label(
            body, text="Point name or slot number:", font=("", 10)
        ).grid(row=0, column=0, sticky="w")
        self._entry = ttk.Entry(body, width=30)
        self._entry.grid(row=1, column=0, sticky="ew", pady=(2, 4))

        hint_text = 'Examples:  "ROOM TEMP"  ·  "HEAT.COOL"  ·  29'
        if application:
            hint_text = f"App {application}   |   " + hint_text
        ttk.Label(body, text=hint_text, foreground="#777").grid(
            row=2, column=0, sticky="w"
        )

        self._force_var = tk.BooleanVar()
        ttk.Checkbutton(
            body,
            text="Force read of undefined slot (troubleshooting)",
            variable=self._force_var,
        ).grid(row=3, column=0, sticky="w", pady=(8, 0))

        self.result: Optional[Tuple[str, bool]] = None

        btns = ttk.Frame(body)
        btns.grid(row=4, column=0, pady=(12, 0), sticky="e")
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(
            side="right", padx=2
        )
        ttk.Button(btns, text="Read", command=self._ok).pack(side="right", padx=2)

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())

        self._entry.focus_set()
        _center_on_parent(self, parent)
        self.grab_set()

    def _ok(self) -> None:
        val = self._entry.get().strip()
        if not val:
            return
        self.result = (val, self._force_var.get())
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(
        cls,
        parent: tk.Misc,
        device_name: str,
        application: Optional[int] = None,
    ) -> Optional[Tuple[str, bool]]:
        dlg = cls(parent, device_name, application)
        dlg.wait_window()
        return dlg.result


# ═══════════════════════════════════════════════════════════════════════════
# SWEEP DIALOG + RESULTS WINDOW
# ═══════════════════════════════════════════════════════════════════════════

# Common points catalog for the Sweep dialog's "Add common point" menu.
# Slots shown are the STANDARD VAV (2020-2027) slot assignments. For other
# application families (fume hoods, unit ventilators, etc.) the same point
# names may live at different slot numbers, which is why the dialog inserts
# names rather than slot numbers — names are universal, slots are not.
#
# Each entry: (category, slot, name, description)
# Category order is preserved as the menu group order.
COMMON_POINTS_CATALOG: List[Tuple[str, int, str, str]] = [
    # Temperature & sensors
    ("Temperature",  3,  "CTL TEMP",      "Control temperature"),
    ("Temperature",  4,  "ROOM TEMP",     "Room temperature sensor reading"),
    ("Temperature",  15, "AUX TEMP",      "Auxiliary temperature sensor (reheat apps)"),
    ("Temperature",  15, "SUPPLY TEMP",   "Supply air temperature (app 2021)"),
    # Setpoints — day/night, heating/cooling
    ("Setpoints",    6,  "DAY CLG STPT",  "Day cooling setpoint"),
    ("Setpoints",    7,  "DAY HTG STPT",  "Day heating setpoint"),
    ("Setpoints",    8,  "NGT CLG STPT",  "Night cooling setpoint"),
    ("Setpoints",    9,  "NGT HTG STPT",  "Night heating setpoint"),
    ("Setpoints",    11, "RM STPT MIN",   "Room setpoint dial minimum"),
    ("Setpoints",    12, "RM STPT MAX",   "Room setpoint dial maximum"),
    ("Setpoints",    13, "RM STPT DIAL",  "Room setpoint dial reading"),
    ("Setpoints",    35, "CTL STPT",      "Active control setpoint"),
    # Mode / occupancy
    ("Mode",         5,  "HEAT.COOL",     "Heating or cooling mode"),
    ("Mode",         29, "DAY.NGT",       "Day or night occupancy"),
    ("Mode",         21, "NGT OVRD",      "Night override active"),
    ("Mode",         20, "OVRD TIME",     "Override duration (hours)"),
    # Airflow & damper
    ("Airflow",      39, "FLOW",          "Actual airflow percentage"),
    ("Airflow",      40, "AIR VOLUME",    "Air volume (CFM)"),
    ("Airflow",      41, "DMPR POS",      "Damper position"),
    ("Airflow",      42, "DMPR COMD",     "Damper command"),
    ("Airflow",      38, "FLOW STPT",     "Flow setpoint"),
    # Hot water valves (reheat)
    ("Valves",       64, "VLV1 POS",      "Valve 1 position"),
    ("Valves",       65, "VLV1 COMD",     "Valve 1 command"),
    ("Valves",       66, "VLV2 POS",      "Valve 2 position"),
    ("Valves",       67, "VLV2 COMD",     "Valve 2 command"),
    # Controller outputs
    ("Outputs",      47, "CLG LOOPOUT",   "Cooling loop output"),
    ("Outputs",      56, "HTG LOOPOUT",   "Heating loop output"),
    # Status / inputs
    ("Status",       18, "WALL SWITCH",   "Wall switch monitoring enabled"),
    ("Status",       19, "DI OVRD SW",    "Override switch status"),
    ("Status",       91, "ERROR STATUS",  "Error status bitmap"),
    # Meta
    ("Meta",         2,  "APPLICATION",   "Application number"),
]


class SweepDialog(tk.Toplevel):
    """Configure a building-wide point sweep:

      * which points to read (names and/or slot numbers, one per line)
      * which scope of devices to include (all enumerated, or online only)
      * which nodes to include (checkbox list)

    On OK, `self.result` is a dict:
        {
            'points':  [str, ...],       # point names / numeric strings
            'scope':   'all' | 'online',
            'nodes':   {node_name, ...}, # set of included node names
        }
    or None if cancelled.
    """

    def __init__(
        self,
        parent: tk.Misc,
        available_nodes: List[Dict],
        device_counts: Dict[str, Tuple[int, int]],
    ) -> None:
        """
        available_nodes : [{'name': str, 'ip': str}, ...]
        device_counts   : node_name -> (total_devices, online_devices)
                          Used to show "NODE1 (12 devices, 10 online)" labels.
        """
        super().__init__(parent)
        self.title("Sweep Points Across Devices")
        self.transient(parent)
        self.resizable(False, True)

        self.result: Optional[Dict] = None

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        # --- Points entry ---
        ttk.Label(body, text="Points to read:", font=("", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(
            body,
            text="One per line — point name or slot number. Examples: "
            "ROOM TEMP, CTL STPT, HEAT.COOL, 4",
            foreground="#777",
            wraplength=500,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 2))

        # Menubutton + Clear, above the text area
        ctrl_row = ttk.Frame(body)
        ctrl_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        self._common_btn = ttk.Menubutton(
            ctrl_row, text="Add common point ▾", direction="below"
        )
        self._common_btn.pack(side="left")
        self._build_common_points_menu(self._common_btn)
        ttk.Button(
            ctrl_row, text="Clear",
            command=lambda: self._points_text.delete("1.0", "end"),
        ).pack(side="left", padx=(6, 0))
        ttk.Label(
            ctrl_row,
            text="  (slot numbers shown are standard-VAV defaults; names work across all apps)",
            foreground="#999",
        ).pack(side="left")

        text_frame = ttk.Frame(body)
        text_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self._points_text = tk.Text(
            text_frame, height=5, width=52, wrap="none", undo=True
        )
        self._points_text.insert("1.0", "ROOM TEMP")
        self._points_text.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(text_frame, orient="vertical", command=self._points_text.yview)
        self._points_text.configure(yscrollcommand=sb.set)
        sb.grid(row=0, column=1, sticky="ns")
        text_frame.columnconfigure(0, weight=1)

        # --- Scope radio ---
        ttk.Label(body, text="Devices to include:", font=("", 10, "bold")).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(4, 2)
        )
        self._scope_var = tk.StringVar(value="all")
        ttk.Radiobutton(
            body,
            text="All enumerated devices (including offline/unknown)",
            variable=self._scope_var,
            value="all",
        ).grid(row=5, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(
            body,
            text="Only devices verified online",
            variable=self._scope_var,
            value="online",
        ).grid(row=6, column=0, columnspan=2, sticky="w")

        # --- Nodes multi-select ---
        ttk.Label(body, text="Nodes to include:", font=("", 10, "bold")).grid(
            row=7, column=0, columnspan=2, sticky="w", pady=(8, 2)
        )

        nodes_container = ttk.Frame(body)
        nodes_container.grid(row=8, column=0, columnspan=2, sticky="nsew")
        body.rowconfigure(8, weight=1)

        # Use a Canvas + inner Frame for a scrollable checkbox list
        canvas = tk.Canvas(
            nodes_container, highlightthickness=0, height=140, background="#ffffff"
        )
        nsb = ttk.Scrollbar(nodes_container, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        canvas.configure(yscrollcommand=nsb.set)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind(
            "<Configure>",
            lambda _e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.grid(row=0, column=0, sticky="nsew")
        nsb.grid(row=0, column=1, sticky="ns")
        nodes_container.rowconfigure(0, weight=1)
        nodes_container.columnconfigure(0, weight=1)

        self._node_vars: Dict[str, tk.BooleanVar] = {}
        for n in available_nodes:
            name = n["name"]
            ip = n["ip"]
            total, online = device_counts.get(name, (0, 0))
            label = f"{name}   ({ip})"
            if total:
                label += f"   — {total} device{'s' if total != 1 else ''}"
                if online:
                    label += f", {online} online"
            var = tk.BooleanVar(value=(total > 0))  # default: only nodes we've enumerated
            self._node_vars[name] = var
            ttk.Checkbutton(
                inner,
                text=label,
                variable=var,
            ).pack(anchor="w", padx=8, pady=1)

        if not available_nodes:
            ttk.Label(
                inner,
                text="(no nodes — configure your site first)",
                foreground="#999",
            ).pack(anchor="w", padx=8, pady=4)

        # Quick "select/deselect all" row
        sel_row = ttk.Frame(body)
        sel_row.grid(row=9, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Button(
            sel_row, text="All", width=6, command=lambda: self._select_all(True)
        ).pack(side="left", padx=2)
        ttk.Button(
            sel_row, text="None", width=6, command=lambda: self._select_all(False)
        ).pack(side="left", padx=2)

        # --- OK / Cancel ---
        btns = ttk.Frame(body)
        btns.grid(row=10, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=4)
        ttk.Button(btns, text="Start Sweep", command=self._ok).pack(side="right", padx=4)

        self.bind("<Escape>", lambda _e: self._cancel())

        self._points_text.focus_set()
        _center_on_parent(self, parent)
        self.grab_set()

    def _select_all(self, state: bool) -> None:
        for v in self._node_vars.values():
            v.set(state)

    def _build_common_points_menu(self, parent_btn: ttk.Menubutton) -> None:
        """Construct the categorized 'Add common point' dropdown menu."""
        menu = tk.Menu(parent_btn, tearoff=0)
        # Group the catalog by category, preserving first-appearance order
        categories: List[str] = []
        by_cat: Dict[str, List[Tuple[int, str, str]]] = {}
        for cat, slot, name, desc in COMMON_POINTS_CATALOG:
            if cat not in by_cat:
                categories.append(cat)
                by_cat[cat] = []
            by_cat[cat].append((slot, name, desc))

        for cat in categories:
            sub = tk.Menu(menu, tearoff=0)
            for slot, name, desc in by_cat[cat]:
                # Label format: "(4) ROOM TEMP  — Room temperature sensor reading"
                label = f"({slot}) {name}   —   {desc}"
                sub.add_command(
                    label=label,
                    command=lambda n=name: self._append_point(n),
                )
            menu.add_cascade(label=cat, menu=sub)

        # Quick path: entire QUICK_SCAN_POINTS list as one click
        menu.add_separator()
        menu.add_command(
            label="Insert all 'quick' operational points",
            command=self._insert_quick_scan_set,
        )
        parent_btn["menu"] = menu

    def _append_point(self, name: str) -> None:
        """Append a point name to the textbox, one per line.
        Empty box → just the name; otherwise newline + name.
        Skips duplicates."""
        existing = [
            line.strip()
            for line in self._points_text.get("1.0", "end").splitlines()
            if line.strip()
        ]
        if name in existing:
            return  # already in the list; no-op
        if existing:
            self._points_text.insert("end-1c", "\n" + name)
        else:
            self._points_text.delete("1.0", "end")
            self._points_text.insert("1.0", name)
        # Ensure the cursor is visible at the end
        self._points_text.see("end")

    def _insert_quick_scan_set(self) -> None:
        """Replace textbox with the full QUICK_SCAN_POINTS list."""
        # We import lazily so widgets.py stays decoupled from p2_scanner
        try:
            import p2_scanner as _p2  # type: ignore
            quick = list(getattr(_p2, "QUICK_SCAN_POINTS", []))
        except Exception:
            quick = []
        if not quick:
            return
        self._points_text.delete("1.0", "end")
        self._points_text.insert("1.0", "\n".join(quick))

    def _ok(self) -> None:
        raw = self._points_text.get("1.0", "end").strip()
        # Split on newlines OR commas OR semicolons; allow extra whitespace
        lines = [
            line.strip()
            for raw_line in raw.splitlines()
            for line in raw_line.replace(";", ",").split(",")
        ]
        points = [p for p in lines if p]
        if not points:
            return  # Silently refuse - user hasn't entered anything

        selected_nodes = {
            name for name, var in self._node_vars.items() if var.get()
        }
        if not selected_nodes:
            return  # Must pick at least one node

        self.result = {
            "points": points,
            "scope": self._scope_var.get(),
            "nodes": selected_nodes,
        }
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(
        cls,
        parent: tk.Misc,
        available_nodes: List[Dict],
        device_counts: Dict[str, Tuple[int, int]],
    ) -> Optional[Dict]:
        dlg = cls(parent, available_nodes, device_counts)
        dlg.wait_window()
        return dlg.result


class SweepResultsWindow(tk.Toplevel):
    """Non-modal results window for a building-wide sweep.

    Results are a flat list of dicts; each row corresponds to one
    (node, device, point) tuple, or an error entry for a device that
    couldn't be read at all. Sortable, filterable, exportable.
    """

    COLUMNS = (
        # (key, label, width, anchor)
        ("node", "Node", 90, "w"),
        ("device", "Device", 120, "w"),
        ("description", "Description", 160, "w"),
        ("slot", "Slot", 55, "center"),
        ("point", "Point", 160, "w"),
        ("value", "Value", 120, "e"),
        ("units", "Units", 65, "center"),
        ("status", "Status", 75, "center"),
    )

    def __init__(
        self,
        parent: tk.Misc,
        points: List[str],
        results: List[Dict],
        on_jump_to_device: Optional[Callable] = None,
        on_resweep: Optional[Callable] = None,
        on_export_csv: Optional[Callable] = None,
        on_export_json: Optional[Callable] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"Sweep Results — {', '.join(points)}")
        # Size set via _center_on_parent so position+size land together
        self._parent = parent

        self._results = list(results)
        self._points = list(points)
        self._on_jump_to_device = on_jump_to_device

        # --- Header ---
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        n_results = len(results)
        n_devices = len({(r.get("_node") or r.get("node"),
                          r.get("_device") or r.get("device")) for r in results})
        n_errors = sum(1 for r in results if "error" in r)
        n_commfault = sum(
            1 for r in results if r.get("comm_status") == "comm_fault"
        )
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ttk.Label(
            header,
            text=f"Points: {', '.join(points)}",
            font=("", 11, "bold"),
        ).pack(anchor="w")
        summary = (
            f"{n_devices} device{'s' if n_devices != 1 else ''} swept  ·  "
            f"{n_results - n_errors} successful read{'s' if (n_results - n_errors) != 1 else ''}  ·  "
            f"{n_commfault} comm-fault  ·  "
            f"{n_errors} unreachable  ·  {ts}"
        )
        ttk.Label(header, text=summary, foreground="#555").pack(anchor="w", pady=(2, 0))

        # --- Toolbar ---
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        if on_resweep:
            ttk.Button(toolbar, text="Re-sweep", command=on_resweep).pack(side="left", padx=2)
        if on_export_csv:
            ttk.Button(
                toolbar, text="Export CSV…",
                command=lambda: on_export_csv(self._results, self._points),
            ).pack(side="left", padx=2)
        if on_export_json:
            ttk.Button(
                toolbar, text="Export JSON…",
                command=lambda: on_export_json(self._results, self._points),
            ).pack(side="left", padx=2)

        # Quick filter
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Label(toolbar, text="Filter:").pack(side="left", padx=(0, 4))
        # master=self so the StringVar (and its trace callback) get cleaned
        # up when the window is destroyed — without it, repeatedly opening
        # and closing this window leaks one trace + one closure-over-self
        # per session.
        self._filter_var = tk.StringVar(master=self)
        self._filter_var.trace_add("write", lambda *a: self._render())
        ttk.Entry(toolbar, textvariable=self._filter_var, width=24).pack(side="left")

        self._hide_errors_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar,
            text="Hide unreachable",
            variable=self._hide_errors_var,
            command=self._render,
        ).pack(side="left", padx=(12, 0))

        # --- Table ---
        table_frame = ttk.Frame(self, padding=(12, 0, 12, 10))
        table_frame.pack(fill="both", expand=True)

        keys = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(
            table_frame, columns=keys, show="headings", selectmode="browse"
        )
        for key, label, width, anchor in self.COLUMNS:
            self._tree.heading(
                key, text=label, command=lambda k=key: self._sort_by(k)
            )
            self._tree.column(
                key, width=width, anchor=anchor,
                stretch=(key in ("device", "description", "point")),
            )

        sby = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        sbx = ttk.Scrollbar(table_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        sbx.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self._tree.tag_configure(
            "comm_fault", background="#ffeee5", foreground="#8a2a00"
        )
        self._tree.tag_configure(
            "error", background="#f0f0f0", foreground="#888"
        )
        self._tree.tag_configure(
            "node_break", background="#fafafa"
        )

        # Double-click → jump to device in main tree
        self._tree.bind("<Double-1>", self._on_double_click)

        # iid -> original result dict, for lookups on double-click
        self._iid_to_result: Dict[str, Dict] = {}

        self._sort_key = "node"
        self._sort_reverse = False
        self._render()

        _center_on_parent(self, self._parent, width=1000, height=560)

    # ------------------------------------------------------------------

    def _sort_by(self, key: str) -> None:
        if key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False
        self._render()

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._iid_to_result.clear()

        filter_text = self._filter_var.get().strip().lower()
        hide_errors = self._hide_errors_var.get()

        def get_sortable(r: Dict, key: str):
            if key == "node":
                return (r.get("_node") or r.get("node") or "", )
            if key == "device":
                return (r.get("_device") or r.get("device") or "", )
            if key == "description":
                return (r.get("_description") or r.get("description") or "", )
            if key == "slot":
                s = r.get("point_slot")
                return (s if s is not None else 10_000, )
            if key == "point":
                return (r.get("point_name") or r.get("error") or "", )
            if key == "value":
                v = r.get("value")
                if v is None:
                    return (float("inf"), )
                try:
                    return (float(v), )
                except (TypeError, ValueError):
                    return (float("inf"), )
            if key == "units":
                return (r.get("units") or "", )
            if key == "status":
                return (r.get("comm_status") or ("error" if "error" in r else ""), )
            return ("", )

        rows = sorted(self._results, key=lambda r: get_sortable(r, self._sort_key),
                      reverse=self._sort_reverse)

        prev_node = None
        for r in rows:
            node = r.get("_node") or r.get("node") or ""
            dev = r.get("_device") or r.get("device") or ""
            desc = r.get("_description") or r.get("description") or ""
            slot = r.get("point_slot")
            slot_str = f"({slot})" if slot is not None else ""
            is_error = "error" in r

            if is_error:
                point_str = "—"
                value_str = f"({r['error']})"
                units_str = ""
                status_str = "— unreachable"
                tags = ["error"]
            else:
                point_str = r.get("point_name") or "?"
                val_text = r.get("value_text") or ""
                raw = r.get("value")
                if val_text:
                    try:
                        value_str = f"{val_text} ({int(raw)})" if raw is not None else val_text
                    except (TypeError, ValueError):
                        value_str = val_text
                elif raw is None:
                    value_str = "—"
                else:
                    try:
                        f = float(raw)
                        value_str = f"{f:.0f}" if abs(f - round(f)) < 0.01 else f"{f:.2f}"
                    except (TypeError, ValueError):
                        value_str = str(raw)
                units_str = r.get("units") or ""
                comm = r.get("comm_status") or ""
                if comm == "online":
                    status_str = "✓ OK"
                    tags = []
                elif comm == "comm_fault":
                    status_str = "✗ #COM"
                    tags = ["comm_fault"]
                else:
                    status_str = "—"
                    tags = []

            # Subtle alternating background between nodes (only useful in sort-by-node)
            if self._sort_key == "node" and prev_node is not None and node != prev_node:
                # (We could insert a blank row, but that clutters sortable tables.
                # Just tag for a subtle visual break instead.)
                pass
            prev_node = node

            # Simple text filter — match any column
            if filter_text:
                haystack = " ".join(str(x).lower() for x in (
                    node, dev, desc, slot_str, point_str, value_str, units_str, status_str
                ))
                if filter_text not in haystack:
                    continue
            if hide_errors and is_error:
                continue

            iid = self._tree.insert(
                "",
                "end",
                values=(node, dev, desc, slot_str, point_str, value_str, units_str, status_str),
                tags=tuple(tags),
            )
            self._iid_to_result[iid] = r

    def _on_double_click(self, _event) -> None:
        sel = self._tree.selection()
        if not sel or not self._on_jump_to_device:
            return
        r = self._iid_to_result.get(sel[0])
        if not r:
            return
        node = r.get("_node") or r.get("node")
        device = r.get("_device") or r.get("device")
        if node and device:
            self._on_jump_to_device(node, device)


# ═══════════════════════════════════════════════════════════════════════════
# HELP WINDOW
# ═══════════════════════════════════════════════════════════════════════════

# Help content is a list of (level, text) tuples. Level controls styling:
#   "h1"   — top-level heading
#   "h2"   — section heading
#   "p"    — body paragraph
#   "li"   — bullet item
#   "code" — inline monospace block (e.g. command example)
HELP_SECTIONS: List[Tuple[str, str]] = [
    ("h1", "P2 Scanner GUI — User Guide"),
    ("p", "A graphical front-end for the Siemens P2 protocol scanner. "
          "Wraps the p2_scanner library for interactive use against "
          "Siemens PXC/TEC controllers. Read-only — it never writes "
          "to a controller."),

    ("h2", "1. Getting started"),
    ("p", "Before the GUI can talk to anything, it needs to know three things "
          "about your site: the BLN (network) name, a scanner identity, and "
          "at least one PXC node with an IP. All three live in site.json."),
    ("li", "File → Edit Site Config… opens a dialog to edit everything at once."),
    ("li", "Discovery → Add Node Manually… opens a small name+IP dialog for "
           "adding a single node."),
    ("li", "Discovery → Port Scan Range… scans an IP range on TCP/5033 "
           "(the P2 port) for PXCs and offers to add any it finds."),
    ("p", "If site.json doesn't exist yet, the app starts with empty identity. "
          "The top toolbar always shows the current Network / Site / Scanner "
          "so you can tell at a glance what you're connected to."),

    ("h2", "2. Working with nodes"),
    ("p", "The left tree shows ⌬ BLN → node → device. Clicking a node "
          "selects it; the buttons below the tree act on the selected "
          "node. The primary row holds snappy operations; the secondary "
          "row (Walk All Points, PPCL Programs) holds slower panel-wide "
          "reads — see section 5."),
    ("li", "Enumerate FLN — asks the PXC to list every device on its FLN "
           "bus (opcode 0x0986). Populates the tree. Fast."),
    ("li", "Verify Online — reads ROOM TEMP on every enumerated device to "
           "see which ones are actually responding. Tree rows flip color "
           "(green online, red offline) live as each device is checked. "
           "Offline devices take ~6 seconds each on the wire; this is "
           "the PXC's own timeout and can't be shortened."),
    ("li", "Firmware — queries the PXC's model, firmware version, and build "
           "date. Covered in detail in section 5."),

    ("h2", "3. Reading points on a single device"),
    ("p", "Select a device in the tree, then use the detail panel on the right:"),
    ("li", "Scan All Points — reads every point defined in the device's "
           "application. Uses the point table from tecpoints.json."),
    ("li", "Quick Scan — reads a curated subset of operational points "
           "(ROOM TEMP, CTL STPT, HEAT.COOL, etc.) filtered to just those "
           "defined in this device's app, so small-app devices don't "
           "waste time on undefined names."),
    ("li", "Read Point… — reads one point you type. Accepts either a name "
           "('ROOM TEMP', 'HEAT.COOL') or a slot number (4, 29). Check "
           "'Force read of undefined slot' only if you're protocol-"
           "troubleshooting a slot that isn't in tecpoints.json."),
    ("p", "Results show up in the point table. Click column headers to sort. "
          "Point rows include: the slot number in parens, the point name, "
          "the value (digital points rendered as 'LABEL (raw)'), units, "
          "data type, and status (✓ OK or ✗ #COM)."),
    ("li", "Export CSV… / Export JSON… save the visible results to a file."),

    ("h2", "4. Sweeping points across many devices"),
    ("p", "Discovery → Sweep Points Across Devices… opens the sweep dialog. "
          "This is the 'how are all the room temps right now' workflow."),
    ("h2", "   4a. Picking points to read"),
    ("p", "The text area accepts one point per line. You can also paste a "
          "comma- or semicolon-separated list. Entries can be:"),
    ("li", "Point names — ROOM TEMP, HEAT.COOL, DAY CLG STPT, CTL STPT. "
           "Names work across all applications."),
    ("li", "Slot numbers — 4, 29, 35. Slots are app-specific: slot 4 is "
           "ROOM TEMP in the standard VAV family (2020-2027) but could "
           "mean something different in a fume hood or unit ventilator app. "
           "Use numbers if you really mean 'whatever lives at slot 4 in "
           "each device's app'; use names if you want the same concept "
           "regardless of app."),
    ("p", "The 'Add common point ▾' button above the text area offers "
          "categorized one-click insertion of the most frequently-swept "
          "points: Temperature, Setpoints, Mode, Airflow, Valves, Outputs, "
          "Status, and Meta. Slot numbers in the menu labels are the "
          "standard-VAV slot for reference; the button inserts the name, "
          "so it works across all apps."),
    ("p", "'Insert all quick operational points' at the bottom of the menu "
          "replaces the text area with the full QUICK_SCAN_POINTS list "
          "(18 points)."),

    ("h2", "   4b. Scope & nodes"),
    ("li", "All enumerated devices — reads every device regardless of "
           "status. Good for finding newly-offline devices."),
    ("li", "Only devices verified online — skips known-offline and "
           "never-verified devices. Fastest."),
    ("p", "The node checkbox list below shows how many devices each node "
          "has enumerated (and of those, how many are online). Nodes with "
          "no enumerated devices are unchecked by default; enumerate them "
          "first if you want them in the sweep."),

    ("h2", "   4c. Optimization: per-device point filter"),
    ("p", "Before calling the wire, the sweep filters each requested point "
          "through that device's application point table. If you sweep "
          "ROOM TEMP + HEAT.COOL across a mixed-app building and some "
          "devices run an app that doesn't define HEAT.COOL, those "
          "devices only get asked for ROOM TEMP. No wasted timeouts."),

    ("h2", "   4d. Results window"),
    ("p", "Opens in its own window so you can keep it visible while "
          "exploring other devices. Columns are Node, Device, Description, "
          "Slot, Point, Value, Units, Status. Click any column header to sort."),
    ("li", "Filter — live text filter across all columns. Type 'K4' to "
           "see only devices starting with K4; type '#COM' to see only "
           "comm-faulted reads."),
    ("li", "Hide unreachable — toggles showing devices that couldn't be "
           "read at all (no comm, bad handshake)."),
    ("li", "Re-sweep — re-opens the sweep dialog so you can tweak and "
           "run again."),
    ("li", "Export CSV… / Export JSON… save the full result set (not "
           "just what's filtered)."),
    ("li", "Double-click any row — selects that device in the main tree "
           "so you can drill in with Scan All / Read Point."),

    ("h2", "5. Panel-wide reads (Walk / Programs / Firmware)"),
    ("p", "The row of buttons below the tree — Walk All Points, PPCL "
          "Programs, Firmware — operate on a whole PXC panel rather than "
          "a single device. Walk and Programs can take 10–30 seconds on a "
          "busy panel, so each prompts for confirmation before running."),
    ("li", "Firmware — queries the PXC for its model, firmware version, "
           "and build date. The GUI first tries the newer 0x010C compact "
           "sysinfo opcode (richer output on PME1300-era panels, includes "
           "a build date) and transparently falls back to legacy 0x0100 "
           "on older firmware. The log line tells you which opcode worked."),
    ("li", "Walk All Points — enumerates every point the PXC knows about "
           "via opcode 0x0981. This is more complete than Enumerate FLN: "
           "it includes PPCL variables, schedule points, global analogs, "
           "and panel-level Title entries alongside the FLN device points. "
           "Results open in a window with a sortable Device / Subkey / "
           "Point / Value / Units / Description table, a filter box, and "
           "a 'Hide title entries' toggle. Export as CSV or JSON. Walks "
           "are also archived in session history, so you can diff two "
           "walks of the same panel across time to see what came and "
           "went."),
    ("p", "Subkeys: some PXC points use a compound identity — two name "
          "fields (e.g. BCCW / DAY.NGT) where a normal point has one. "
          "The Subkey column is the second field, empty for normal "
          "points. When diffing walks, entries are matched by (device, "
          "subkey, point) so compound entries don't collide."),
    ("li", "PPCL Programs — dumps the full PPCL source text of every "
           "program on the PXC via opcode 0x0985. Opens a master-detail "
           "view: program list on the left (name, module tag, line count), "
           "read-only monospace source on the right. A find bar "
           "highlights every match in the current program. Comment lines "
           "(lines tagged 'C' in PPCL convention) render in green. Export "
           "all programs as a JSON archive."),
    ("p", "Firmware-dialect note: the scanner auto-detects whether a PXC "
          "speaks the legacy (firmware build PME1252 and earlier) or "
          "modern (PME1300 and later) P2 wire dialect. If you used an "
          "earlier version and some panels seemed unreachable, they "
          "should now respond. The first connect to a modern panel is "
          "about 2 seconds slower while the dialect is probed; "
          "subsequent connects are fast. After the firmware build is "
          "known it's cached in site.json and the probe is skipped on "
          "every later connect. Nothing to configure."),

    ("h2", "6. Scan history (View → Scan History…)"),
    ("p", "Every scan and sweep you run this session is archived in memory "
          "with a timestamp. Open the history window to browse, reopen, "
          "or compare previous scans without redoing them."),
    ("li", "Open — loads the selected entry. Device scans restore into the "
           "main detail panel; sweep entries reopen their results window."),
    ("li", "Compare… — with exactly two entries selected (Ctrl-click or "
           "Shift-click), opens a side-by-side diff. Same-device device "
           "scans and same-points sweeps produce row-by-row matching "
           "with changed values highlighted. Use 'Show only changed "
           "values' to filter to deltas only."),
    ("li", "Delete — removes selected entries. Clear All — empties the "
           "whole history."),
    ("p", "History is in-memory only — it's cleared when the app closes. "
          "To save a scan permanently, use Export CSV / Export JSON from "
          "the point table or the sweep results window."),

    ("h2", "7. Cold-discovering a new site (CLI only)"),
    ("p", "When you're onboarding a site where nothing is configured — you "
          "don't know the BLN network name, which PXCs exist, or what "
          "node names they use — cold discovery handles it via a tiered "
          "dictionary attack against common Siemens naming conventions. "
          "That workflow lives in the CLI scanner, not the GUI, because "
          "it involves probe bursts that warrant their own delay flags "
          "and warnings."),
    ("p", "Run from a terminal in the scanner folder:"),
    ("code", "    python p2_scanner.py --cold-discover --range 192.0.2.0/24 --save site.json"),
    ("p", "Add --cold-delay 2 during production hours for a 2-second pause "
          "between probes. To watch live activity without sending probes, "
          "use --listen-push 60 (a passive TCP push listener for COV / "
          "virtual-write / routing events). See the main p2_scanner "
          "README for the full flag list and safety notes."),
    ("p", "Cold-discover now bootstraps via a 0x0050 Status Query (spec "
          "§22.6) — one round-trip per panel returns BLN name, node name, "
          "and supervisor identity from both legacy and modern firmware. "
          "Older builds of the scanner relied on legacy-dialect probes "
          "only and could fail on all-modern (PME1300+) greenfield sites; "
          "if you ever see that, point the scanner directly at one known "
          "panel IP with -n NODEx — that path always auto-detects the "
          "dialect."),
    ("p", "Once cold-discover has written a site.json, come back to the "
          "GUI and use File → Load Config… to pick it up."),

    ("h2", "8. Tips & troubleshooting"),
    ("li", "Handshake fails — the BLN name is wrong, or the scanner name "
           "format doesn't match what the site expects. Some sites require "
           "<SITE>DCC-SVR|5033 (the Desigo CC server identity) instead "
           "of the generic default."),
    ("li", "Verify takes forever — expected for sites with many offline "
           "devices. Each offline device eats ~6s of PXC timeout. "
           "A 65-device verify with all offline is ~6-7 minutes. "
           "The tree updates live so you can tell it's actually working."),
    ("li", "Device shows #COM — the PXC returned cached data but the "
           "FLN bus can't reach the device. Check wiring and the device's "
           "own power."),
    ("li", "Quick Scan returned nothing — the device's app doesn't have "
           "any QUICK_SCAN_POINTS defined. Try Scan All Points instead."),
    ("li", "'Busy' indicator stuck — only one scanner operation runs at "
           "a time by design (PXCs have a small peer-session budget). "
           "Wait for the current task to finish."),
    ("li", "Debug reads checkbox — top-right toggle. Turns on verbose "
           "hex logging for point reads that fail to parse. Useful for "
           "protocol troubleshooting; noisy for normal use."),

    ("h2", "9. Keyboard shortcuts"),
    ("li", "Enter in Read Point dialog — submit."),
    ("li", "Escape in any dialog — cancel."),
    ("li", "Double-click a device in any tree — selects it."),
    ("li", "Click column headers in any table — sort; click again to reverse."),

    ("h2", "10. Files it creates"),
    ("li", ".p2_gui_scanner_path — remembers where p2_scanner.py is, so "
           "you don't have to re-browse on every launch."),
    ("li", "site.json — only when you click Save Config. The GUI never "
           "writes to disk automatically."),
    ("li", "Exported CSV/JSON — only where and when you choose."),
]


class HelpWindow(tk.Toplevel):
    """Scrollable in-app user guide."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        self.title("P2 Scanner GUI — User Guide")
        self.minsize(560, 400)
        self._parent = parent

        # Header bar with close button
        header = ttk.Frame(self, padding=(12, 8))
        header.pack(fill="x")
        ttk.Label(
            header,
            text="User Guide",
            font=("", 12, "bold"),
        ).pack(side="left")
        ttk.Button(header, text="Close", command=self.destroy).pack(side="right")

        # Body: text widget with scrollbar
        body = ttk.Frame(self, padding=(0, 0, 0, 0))
        body.pack(fill="both", expand=True)

        try:
            import tkinter.font as tkfont
            default_family = tkfont.nametofont("TkDefaultFont").cget("family")
        except Exception:
            default_family = "Helvetica"

        text = tk.Text(
            body,
            wrap="word",
            padx=18,
            pady=12,
            bg="#ffffff",
            borderwidth=0,
            relief="flat",
            font=(default_family, 10),
        )
        sby = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sby.set)
        text.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        # Tag styles
        text.tag_configure(
            "h1", font=(default_family, 16, "bold"),
            foreground="#111", spacing1=4, spacing3=8,
        )
        text.tag_configure(
            "h2", font=(default_family, 12, "bold"),
            foreground="#222", spacing1=12, spacing3=4,
        )
        text.tag_configure(
            "p", spacing1=2, spacing3=6, lmargin1=0, lmargin2=0,
        )
        text.tag_configure(
            "li", spacing1=1, spacing3=2,
            lmargin1=20, lmargin2=36,
        )
        text.tag_configure(
            "code", font=("Courier", 9),
            background="#f0f0f0", foreground="#333",
        )

        # Render the help content
        for level, content in HELP_SECTIONS:
            if level == "h1":
                text.insert("end", content + "\n", "h1")
            elif level == "h2":
                text.insert("end", content + "\n", "h2")
            elif level == "p":
                text.insert("end", content + "\n", "p")
            elif level == "li":
                text.insert("end", "  •  " + content + "\n", "li")
            elif level == "code":
                text.insert("end", content + "\n", "code")

        text.configure(state="disabled")

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=780, height=640)


# ═══════════════════════════════════════════════════════════════════════════
# SCAN HISTORY — in-memory session store + browser + compare
# ═══════════════════════════════════════════════════════════════════════════

class ScanHistory:
    """Holds every scan/sweep done this session with a timestamp so the
    user can go back, reopen, and compare. In-memory only — cleared on
    application exit (disk persistence is a future feature)."""

    def __init__(self) -> None:
        self._entries: List[Dict] = []
        self._next_id = 1

    def add_device_scan(
        self,
        node: str,
        device: str,
        application: Optional[int],
        results: List[Dict],
        scan_type: str = "full",
    ) -> Dict:
        """Record a per-device scan (full / quick / single-point)."""
        import time
        entry = {
            "id": self._next_id,
            "kind": "device",
            "timestamp": time.time(),
            "node": node,
            "device": device,
            "application": application or 0,
            "scan_type": scan_type,  # 'full' | 'quick' | 'single'
            "results": [dict(r) for r in results],  # defensive copy
        }
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def add_sweep(
        self,
        points: List[str],
        target_count: int,
        results: List[Dict],
    ) -> Dict:
        """Record a building-wide sweep."""
        import time
        entry = {
            "id": self._next_id,
            "kind": "sweep",
            "timestamp": time.time(),
            "points": list(points),
            "target_count": target_count,
            "results": [dict(r) for r in results],
        }
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def add_walk(
        self,
        node: str,
        entries: List[Dict],
    ) -> Dict:
        """Record a Walk All Points run on a single PXC."""
        import time
        entry = {
            "id": self._next_id,
            "kind": "walk",
            "timestamp": time.time(),
            "node": node,
            "entries": [dict(e) for e in entries],  # defensive copy
        }
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def all(self) -> List[Dict]:
        return list(self._entries)

    def get(self, entry_id: int) -> Optional[Dict]:
        for e in self._entries:
            if e["id"] == entry_id:
                return e
        return None

    def for_device(self, node: str, device: str) -> List[Dict]:
        return [
            e for e in self._entries
            if e["kind"] == "device"
            and e["node"] == node
            and e["device"] == device
        ]

    def remove(self, entry_id: int) -> bool:
        for i, e in enumerate(self._entries):
            if e["id"] == entry_id:
                del self._entries[i]
                return True
        return False

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


def _format_timestamp(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _summarize_entry(entry: Dict) -> Tuple[str, str, str, str]:
    """Return (timestamp, kind_label, target_label, detail) tuple for display."""
    ts = _format_timestamp(entry["timestamp"])
    if entry["kind"] == "device":
        scan_type = entry.get("scan_type", "full")
        kind_label = {
            "full": "Full scan",
            "quick": "Quick scan",
            "single": "Single point",
        }.get(scan_type, "Scan")
        target_label = f"{entry['node']} / {entry['device']}"
        n = len(entry.get("results", []))
        app = entry.get("application", 0) or 0
        detail = f"{n} point{'s' if n != 1 else ''}"
        if app:
            detail += f"  ·  app {app}"
    elif entry["kind"] == "walk":
        kind_label = "Walk points"
        target_label = entry.get("node", "?")
        entries = entry.get("entries", [])
        n_total = len(entries)
        n_titles = sum(
            1 for e in entries
            if e.get("value") is None and e.get("description")
        )
        n_points = n_total - n_titles
        detail = f"{n_points} point{'s' if n_points != 1 else ''}"
        if n_titles:
            detail += f"  ·  {n_titles} title{'s' if n_titles != 1 else ''}"
    else:  # sweep
        kind_label = "Sweep"
        target_label = ", ".join(entry.get("points", []))
        n = len(entry.get("results", []))
        t = entry.get("target_count", 0)
        detail = f"{t} device{'s' if t != 1 else ''}  ·  {n} rows"
    return ts, kind_label, target_label, detail


class HistoryWindow(tk.Toplevel):
    """Browser for ScanHistory. Click-to-open, shift-click for compare."""

    def __init__(
        self,
        parent: tk.Misc,
        history: ScanHistory,
        on_open_entry,
        on_compare_entries,
    ) -> None:
        super().__init__(parent)
        self.title("Scan History")
        self.minsize(600, 320)
        self._parent = parent

        self._history = history
        self._on_open = on_open_entry
        self._on_compare = on_compare_entries

        # Header
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(
            header,
            text="Session scan history",
            font=("", 12, "bold"),
        ).pack(side="left")
        ttk.Label(
            header,
            text="  (in-memory; cleared when the app closes)",
            foreground="#888",
        ).pack(side="left")
        ttk.Button(header, text="Close", command=self.destroy).pack(side="right")

        # Toolbar
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Open", command=self._open_selected).pack(
            side="left", padx=2
        )
        ttk.Button(
            toolbar, text="Compare…", command=self._compare_selected
        ).pack(side="left", padx=2)
        ttk.Button(
            toolbar, text="Delete", command=self._delete_selected
        ).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=8
        )
        ttk.Button(toolbar, text="Clear All", command=self._clear_all).pack(
            side="left", padx=2
        )
        ttk.Label(
            toolbar,
            text="  (Ctrl-click to select two entries for compare)",
            foreground="#888",
        ).pack(side="left", padx=(12, 0))

        # Table
        body = ttk.Frame(self, padding=(12, 0, 12, 10))
        body.pack(fill="both", expand=True)

        cols = ("time", "kind", "target", "detail")
        self._tree = ttk.Treeview(
            body, columns=cols, show="headings", selectmode="extended"
        )
        self._tree.heading("time", text="When")
        self._tree.heading("kind", text="Type")
        self._tree.heading("target", text="Target")
        self._tree.heading("detail", text="Detail")
        self._tree.column("time", width=160, anchor="w")
        self._tree.column("kind", width=110, anchor="w")
        self._tree.column("target", width=260, anchor="w", stretch=True)
        self._tree.column("detail", width=180, anchor="w")

        sby = ttk.Scrollbar(body, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self._iid_to_id: Dict[str, int] = {}
        self._tree.bind("<Double-1>", lambda _e: self._open_selected())

        self.bind("<Escape>", lambda _e: self.destroy())
        self.refresh()

        _center_on_parent(self, self._parent, width=880, height=480)

    def refresh(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._iid_to_id.clear()
        # Most-recent first
        entries = sorted(
            self._history.all(),
            key=lambda e: e["timestamp"],
            reverse=True,
        )
        for e in entries:
            ts, kind, target, detail = _summarize_entry(e)
            iid = self._tree.insert("", "end", values=(ts, kind, target, detail))
            self._iid_to_id[iid] = e["id"]

    def _selected_ids(self) -> List[int]:
        return [self._iid_to_id[iid] for iid in self._tree.selection()]

    def _open_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        entry = self._history.get(ids[0])
        if entry and self._on_open:
            self._on_open(entry)

    def _compare_selected(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 2:
            from tkinter import messagebox
            messagebox.showinfo(
                "Pick two entries",
                "Compare needs exactly two scans selected. Ctrl-click "
                "(or Shift-click) to select two rows.",
                parent=self,
            )
            return
        e1 = self._history.get(ids[0])
        e2 = self._history.get(ids[1])
        if e1 and e2 and self._on_compare:
            # Pass them in chronological order (older first) so the compare
            # view can label them "Before" / "After"
            if e1["timestamp"] > e2["timestamp"]:
                e1, e2 = e2, e1
            self._on_compare(e1, e2)

    def _delete_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        for eid in ids:
            self._history.remove(eid)
        self.refresh()

    def _clear_all(self) -> None:
        from tkinter import messagebox
        if not messagebox.askyesno(
            "Clear history?",
            f"Remove all {len(self._history)} history entries? This cannot be undone.",
            parent=self,
        ):
            return
        self._history.clear()
        self.refresh()


class CompareWindow(tk.Toplevel):
    """Side-by-side comparison of two ScanHistory entries."""

    def __init__(
        self,
        parent: tk.Misc,
        entry_before: Dict,
        entry_after: Dict,
    ) -> None:
        super().__init__(parent)
        self.title("Compare Scans")
        self.minsize(720, 400)
        self._parent = parent

        # Header with the two entries' summaries
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")

        compatible, reason = self._compatibility(entry_before, entry_after)
        if compatible:
            title = "Compare scans"
        else:
            title = f"Compare scans  —  {reason}"
        ttk.Label(header, text=title, font=("", 12, "bold")).pack(anchor="w")

        cols_frame = ttk.Frame(header)
        cols_frame.pack(fill="x", pady=(6, 0))
        for col, entry, label in (
            (0, entry_before, "Before"),
            (1, entry_after, "After"),
        ):
            box = ttk.Frame(cols_frame)
            box.grid(row=0, column=col, sticky="ew", padx=(0, 12))
            cols_frame.columnconfigure(col, weight=1)
            ts, kind, target, detail = _summarize_entry(entry)
            ttk.Label(box, text=f"{label}:", foreground="#666").pack(anchor="w")
            ttk.Label(box, text=f"{kind}  ·  {target}", font=("", 10, "bold")).pack(anchor="w")
            ttk.Label(box, text=f"{ts}  ·  {detail}", foreground="#666").pack(anchor="w")

        # Toolbar: filter changed-only
        tools = ttk.Frame(self, padding=(12, 0, 12, 6))
        tools.pack(fill="x")
        self._changed_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tools,
            text="Show only changed values",
            variable=self._changed_only_var,
            command=self._render,
        ).pack(side="left")

        # Table: depends on whether entries are compatible
        body = ttk.Frame(self, padding=(12, 0, 12, 10))
        body.pack(fill="both", expand=True)

        self._body = body
        self._entry_before = entry_before
        self._entry_after = entry_after
        self._compatible = compatible
        self._reason = reason

        self._build_table()
        self._render()

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=1040, height=600)

    @staticmethod
    def _compatibility(e1: Dict, e2: Dict) -> Tuple[bool, str]:
        if e1["kind"] != e2["kind"]:
            return False, "different scan types — row matching disabled"
        if e1["kind"] == "device":
            if e1["node"] != e2["node"] or e1["device"] != e2["device"]:
                return False, "different devices — row matching disabled"
        elif e1["kind"] == "sweep":
            if set(e1.get("points", [])) != set(e2.get("points", [])):
                return False, "different point sets — row matching disabled"
        elif e1["kind"] == "walk":
            if e1.get("node") != e2.get("node"):
                return False, "different nodes — row matching disabled"
        return True, "same target"

    def _build_table(self) -> None:
        # Clear any existing children
        for w in self._body.winfo_children():
            w.destroy()

        if self._entry_before["kind"] == "device":
            cols = ("slot", "name", "before", "after", "delta", "change")
            labels = ("Slot", "Point Name", "Before", "After", "Δ", "Change")
            widths = (60, 180, 140, 140, 80, 80)
        elif self._entry_before["kind"] == "walk":
            cols = ("device", "subkey", "point", "before", "after", "delta", "change")
            labels = ("Device", "Subkey", "Point", "Before", "After", "Δ", "Change")
            widths = (140, 80, 180, 130, 130, 80, 80)
        else:  # sweep
            cols = ("node", "device", "point", "before", "after", "delta", "change")
            labels = ("Node", "Device", "Point", "Before", "After", "Δ", "Change")
            widths = (90, 120, 160, 130, 130, 80, 80)

        self._tree = ttk.Treeview(
            self._body, columns=cols, show="headings"
        )
        for c, lbl, w in zip(cols, labels, widths):
            self._tree.heading(c, text=lbl)
            anchor = "e" if c in ("before", "after", "delta") else "w"
            self._tree.column(c, width=w, anchor=anchor)

        sby = ttk.Scrollbar(self._body, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        self._body.rowconfigure(0, weight=1)
        self._body.columnconfigure(0, weight=1)

        # Row tags
        self._tree.tag_configure(
            "changed", background="#fff4e0"
        )
        self._tree.tag_configure(
            "only_before", background="#f0f4ff", foreground="#444"
        )
        self._tree.tag_configure(
            "only_after", background="#f0fff4", foreground="#444"
        )

    def _format_value(self, r: Optional[Dict]) -> str:
        if r is None:
            return "—"
        if "error" in r:
            return f"({r['error']})"
        val = r.get("value")
        val_text = r.get("value_text") or ""
        if val_text:
            try:
                return f"{val_text} ({int(val)})" if val is not None else val_text
            except (TypeError, ValueError):
                return val_text
        if val is None:
            return "—"
        try:
            f = float(val)
            return f"{f:.0f}" if abs(f - round(f)) < 0.01 else f"{f:.2f}"
        except (TypeError, ValueError):
            return str(val)

    def _numeric(self, r: Optional[Dict]) -> Optional[float]:
        if r is None or "error" in r:
            return None
        v = r.get("value")
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    def _delta(self, b: Optional[Dict], a: Optional[Dict]) -> str:
        bn, an = self._numeric(b), self._numeric(a)
        if bn is None or an is None:
            return ""
        d = an - bn
        if abs(d) < 0.005:
            return ""
        return f"{d:+.2f}" if abs(d) < 100 else f"{d:+.0f}"

    def _changed(self, b: Optional[Dict], a: Optional[Dict]) -> bool:
        # Different error state → changed
        b_err = b is None or "error" in (b or {})
        a_err = a is None or "error" in (a or {})
        if b_err != a_err:
            return True
        if b_err and a_err:
            return False
        # Compare rendered value strings
        return self._format_value(b) != self._format_value(a)

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)

        changed_only = self._changed_only_var.get()

        if self._entry_before["kind"] == "device":
            self._render_device(changed_only)
        elif self._entry_before["kind"] == "walk":
            self._render_walk(changed_only)
        else:
            self._render_sweep(changed_only)

    def _render_walk(self, changed_only: bool) -> None:
        """Diff two Walk All Points runs on the same node. Entries are keyed
        by (device, subkey, point) — the subkey disambiguates compound-name
        entries where the same device has multiple records (e.g. BCCW has
        one entry per PPCL variable attached to it)."""

        def key(e: Dict) -> Tuple[str, str, str]:
            return (
                e.get("device", "") or "",
                e.get("subkey", "") or "",
                e.get("point", "") or "",
            )

        def as_result(e: Dict) -> Dict:
            # Walk entries use 'value'/'units' keys like scan results,
            # so they feed _format_value and _delta directly.
            return e

        before = {key(e): as_result(e) for e in self._entry_before.get("entries", [])}
        after = {key(e): as_result(e) for e in self._entry_after.get("entries", [])}
        all_keys = sorted(set(before) | set(after))

        for k in all_keys:
            device, subkey, point = k
            b = before.get(k)
            a = after.get(k)
            bv = self._format_value(b)
            av = self._format_value(a)
            delta = self._delta(b, a)
            changed = self._changed(b, a)
            change_str = "⬤" if changed else ""
            tags = []
            if b and not a:
                tags.append("only_before")
                change_str = "removed"
            elif a and not b:
                tags.append("only_after")
                change_str = "new"
            elif changed:
                tags.append("changed")
            if changed_only and not changed and b and a:
                continue
            self._tree.insert(
                "", "end",
                values=(device, subkey, point, bv, av, delta, change_str),
                tags=tuple(tags),
            )

    def _render_device(self, changed_only: bool) -> None:
        before = {r.get("point_name"): r for r in self._entry_before["results"]}
        after = {r.get("point_name"): r for r in self._entry_after["results"]}
        all_names = sorted(set(before) | set(after),
                           key=lambda n: ((before.get(n) or after.get(n) or {}).get("point_slot") or 10_000, n))

        for name in all_names:
            b = before.get(name)
            a = after.get(name)
            slot = ((b or a) or {}).get("point_slot")
            slot_str = f"({slot})" if slot is not None else ""
            bv = self._format_value(b)
            av = self._format_value(a)
            delta = self._delta(b, a)
            changed = self._changed(b, a)
            change_str = "⬤" if changed else ""
            tags = []
            if b and not a:
                tags.append("only_before")
                change_str = "removed"
            elif a and not b:
                tags.append("only_after")
                change_str = "new"
            elif changed:
                tags.append("changed")
            if changed_only and not changed and b and a:
                continue
            self._tree.insert(
                "", "end",
                values=(slot_str, name, bv, av, delta, change_str),
                tags=tuple(tags),
            )

    def _render_sweep(self, changed_only: bool) -> None:
        # Key rows by (node, device, point_name)
        def key(r: Dict) -> Tuple[str, str, str]:
            node = r.get("_node") or r.get("node") or ""
            dev = r.get("_device") or r.get("device") or ""
            pt = r.get("point_name") or ""
            return (node, dev, pt)

        before = {key(r): r for r in self._entry_before["results"]}
        after = {key(r): r for r in self._entry_after["results"]}
        all_keys = sorted(set(before) | set(after))

        for k in all_keys:
            node, dev, pt = k
            b = before.get(k)
            a = after.get(k)
            bv = self._format_value(b)
            av = self._format_value(a)
            delta = self._delta(b, a)
            changed = self._changed(b, a)
            change_str = "⬤" if changed else ""
            tags = []
            if b and not a:
                tags.append("only_before")
                change_str = "removed"
            elif a and not b:
                tags.append("only_after")
                change_str = "new"
            elif changed:
                tags.append("changed")
            if changed_only and not changed and b and a:
                continue
            self._tree.insert(
                "", "end",
                values=(node, dev, pt, bv, av, delta, change_str),
                tags=tuple(tags),
            )


# ═══════════════════════════════════════════════════════════════════════════
# WALK ALL POINTS WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class WalkPointsWindow(tk.Toplevel):
    """Results viewer for conn.enumerate_all_points() — the full panel walk
    via 0x0981 which includes FLN devices plus panel-internal PPCL
    variables, scheduled points, global analogs, and Title entries.

    Two row shapes come back in the same list:
      * Regular:  {device, point, value, units, description=''}
      * Title:    {device==point, value=None, units='', description='label'}
    """

    COLUMNS = (
        ("device", "Device", 180, "w"),
        ("subkey", "Subkey", 85,  "w"),
        ("point",  "Point", 200, "w"),
        ("value",  "Value", 110, "e"),
        ("units",  "Units", 70,  "center"),
        ("desc",   "Description / Title", 260, "w"),
    )

    def __init__(
        self,
        parent: tk.Misc,
        node_name: str,
        entries: List[Dict],
        on_export_csv: Optional[Callable] = None,
        on_export_json: Optional[Callable] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"All Points — {node_name}")
        self.minsize(760, 440)
        self._parent = parent

        self._entries = list(entries)
        self._node_name = node_name

        # Header
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(
            header,
            text=f"Panel-wide point walk: {node_name}",
            font=("", 11, "bold"),
        ).pack(anchor="w")

        n_total = len(entries)
        n_titles = sum(
            1 for e in entries
            if e.get("value") is None and e.get("description")
        )
        n_points = n_total - n_titles
        summary_parts = [f"{n_total} entr{'ies' if n_total != 1 else 'y'}"]
        if n_points:
            summary_parts.append(
                f"{n_points} point read{'s' if n_points != 1 else ''}"
            )
        if n_titles:
            summary_parts.append(
                f"{n_titles} title entr{'ies' if n_titles != 1 else 'y'}"
            )
        ttk.Label(
            header, text="  ·  ".join(summary_parts), foreground="#555"
        ).pack(anchor="w", pady=(2, 0))

        # Toolbar
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        if on_export_csv:
            ttk.Button(
                toolbar, text="Export CSV…",
                command=lambda: on_export_csv(self._entries, self._node_name),
            ).pack(side="left", padx=2)
        if on_export_json:
            ttk.Button(
                toolbar, text="Export JSON…",
                command=lambda: on_export_json(self._entries, self._node_name),
            ).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=10
        )
        ttk.Label(toolbar, text="Filter:").pack(side="left", padx=(0, 4))
        # master=self anchors the trace lifetime to this window
        self._filter_var = tk.StringVar(master=self)
        self._filter_var.trace_add("write", lambda *a: self._render())
        ttk.Entry(toolbar, textvariable=self._filter_var, width=24).pack(side="left")

        self._hide_titles_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar,
            text="Hide title entries",
            variable=self._hide_titles_var,
            command=self._render,
        ).pack(side="left", padx=(12, 0))

        ttk.Button(toolbar, text="Close", command=self.destroy).pack(side="right", padx=2)

        # Table
        body = ttk.Frame(self, padding=(12, 0, 12, 10))
        body.pack(fill="both", expand=True)
        keys = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(body, columns=keys, show="headings")
        for key, label, width, anchor in self.COLUMNS:
            self._tree.heading(
                key, text=label, command=lambda k=key: self._sort_by(k)
            )
            self._tree.column(
                key, width=width, anchor=anchor,
                stretch=(key in ("point", "desc")),
            )
        sby = ttk.Scrollbar(body, orient="vertical", command=self._tree.yview)
        sbx = ttk.Scrollbar(body, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        sbx.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        # Title entries get a faint background so they read as labels
        # rather than values
        self._tree.tag_configure(
            "title", background="#f5f0e8", foreground="#6a5020"
        )

        self._sort_key = "device"
        self._sort_reverse = False
        self._render()

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=980, height=560)

    def _sort_by(self, key: str) -> None:
        if key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False
        self._render()

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)

        filter_text = self._filter_var.get().strip().lower()
        hide_titles = self._hide_titles_var.get()

        def is_title(e: Dict) -> bool:
            return (
                e.get("value") is None
                and bool(e.get("description"))
            )

        def sort_key(e: Dict):
            k = self._sort_key
            if k == "device":
                return (e.get("device", ""),)
            if k == "subkey":
                return (e.get("subkey", "") or "",)
            if k == "point":
                return (e.get("point", ""),)
            if k == "value":
                v = e.get("value")
                if v is None:
                    return (float("inf"),)
                try:
                    return (float(v),)
                except (TypeError, ValueError):
                    return (float("inf"),)
            if k == "units":
                return (e.get("units", ""),)
            if k == "desc":
                return (e.get("description", ""),)
            return ("",)

        rows = sorted(
            self._entries, key=sort_key, reverse=self._sort_reverse
        )

        for e in rows:
            title = is_title(e)
            if hide_titles and title:
                continue

            device = e.get("device", "") or ""
            subkey = e.get("subkey", "") or ""
            point = e.get("point", "") or ""
            raw = e.get("value")
            units = e.get("units", "") or ""
            desc = e.get("description", "") or ""

            if raw is None:
                value_str = "—"
            else:
                try:
                    f = float(raw)
                    value_str = f"{f:.0f}" if abs(f - round(f)) < 0.01 else f"{f:.2f}"
                except (TypeError, ValueError):
                    value_str = str(raw)

            if filter_text:
                haystack = " ".join(
                    str(x).lower() for x in (device, subkey, point, value_str, units, desc)
                )
                if filter_text not in haystack:
                    continue

            tags = ("title",) if title else ()
            self._tree.insert(
                "", "end",
                values=(device, subkey, point, value_str, units, desc),
                tags=tags,
            )


# ═══════════════════════════════════════════════════════════════════════════
# PPCL PROGRAMS WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class ProgramsWindow(tk.Toplevel):
    """Master-detail viewer for conn.read_programs() — PPCL source dumps.

    Left: program list (name + module tag). Right: read-only monospace
    source. Includes an in-source find bar for searching the currently-
    selected program.
    """

    def __init__(
        self,
        parent: tk.Misc,
        node_name: str,
        programs: List[Dict],
        on_export: Optional[Callable] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"PPCL Programs — {node_name}")
        self.minsize(700, 420)
        self._parent = parent

        self._programs = list(programs)
        self._node_name = node_name

        # Header
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(
            header,
            text=f"PPCL source: {node_name}",
            font=("", 11, "bold"),
        ).pack(anchor="w")
        total_lines = sum(p.get("code", "").count("\n") for p in programs)
        ttk.Label(
            header,
            text=f"{len(programs)} program{'s' if len(programs) != 1 else ''}"
                 f"  ·  {total_lines} total lines",
            foreground="#555",
        ).pack(anchor="w", pady=(2, 0))

        # Toolbar
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        if on_export:
            ttk.Button(
                toolbar, text="Export All…",
                command=lambda: on_export(self._programs, self._node_name),
            ).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=10
        )
        ttk.Label(toolbar, text="Find in source:").pack(side="left", padx=(0, 4))
        # master=self anchors the trace lifetime to this window
        self._find_var = tk.StringVar(master=self)
        self._find_var.trace_add("write", lambda *a: self._find_in_source())
        find_entry = ttk.Entry(toolbar, textvariable=self._find_var, width=24)
        find_entry.pack(side="left")
        ttk.Button(toolbar, text="Next", command=self._find_next).pack(
            side="left", padx=(4, 0)
        )
        ttk.Button(toolbar, text="Close", command=self.destroy).pack(
            side="right", padx=2
        )

        # Split body: list | source
        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        # Left: program list
        left = ttk.Frame(body)
        body.add(left, weight=1)
        cols = ("name", "module", "lines")
        self._prog_tree = ttk.Treeview(
            left, columns=cols, show="headings", selectmode="browse"
        )
        self._prog_tree.heading("name", text="Program")
        self._prog_tree.heading("module", text="Module")
        self._prog_tree.heading("lines", text="Lines")
        self._prog_tree.column("name", width=160, anchor="w")
        self._prog_tree.column("module", width=60, anchor="center")
        self._prog_tree.column("lines", width=55, anchor="e")
        psb = ttk.Scrollbar(left, orient="vertical", command=self._prog_tree.yview)
        self._prog_tree.configure(yscrollcommand=psb.set)
        self._prog_tree.grid(row=0, column=0, sticky="nsew")
        psb.grid(row=0, column=1, sticky="ns")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self._prog_tree.bind(
            "<<TreeviewSelect>>", lambda _e: self._on_select_program()
        )

        # Right: source text
        right = ttk.Frame(body)
        body.add(right, weight=3)

        try:
            import tkinter.font as tkfont
            mono_family = "Consolas" if "Consolas" in tkfont.families() else "Courier"
        except Exception:
            mono_family = "Courier"

        self._source = tk.Text(
            right,
            wrap="none",
            font=(mono_family, 10),
            bg="#fcfcf8",
            fg="#222",
            padx=10,
            pady=8,
            borderwidth=0,
        )
        ssy = ttk.Scrollbar(right, orient="vertical", command=self._source.yview)
        ssx = ttk.Scrollbar(right, orient="horizontal", command=self._source.xview)
        self._source.configure(yscrollcommand=ssy.set, xscrollcommand=ssx.set)
        self._source.grid(row=0, column=0, sticky="nsew")
        ssy.grid(row=0, column=1, sticky="ns")
        ssx.grid(row=1, column=0, sticky="ew")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        self._source.tag_configure(
            "search_hit", background="#ffe58a", foreground="#222"
        )
        self._source.tag_configure(
            "comment", foreground="#0b7"
        )

        # Populate program list
        self._iid_to_idx: Dict[str, int] = {}
        for i, prog in enumerate(self._programs):
            name = prog.get("name", "?")
            mod = prog.get("module", "") or ""
            code = prog.get("code", "") or ""
            lines = code.count("\n") + (0 if code.endswith("\n") or not code else 1)
            iid = self._prog_tree.insert(
                "", "end", values=(name, mod, lines)
            )
            self._iid_to_idx[iid] = i

        self._source.configure(state="disabled")

        # Auto-select first program
        first = self._prog_tree.get_children()
        if first:
            self._prog_tree.selection_set(first[0])
            self._prog_tree.focus(first[0])
            # Call the handler directly — the <<TreeviewSelect>> event from
            # selection_set() fires asynchronously, so if the caller opens
            # the window and immediately queries the source text it'd be
            # empty. Populate it synchronously here.
            self._on_select_program()

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=940, height=600)

    def _on_select_program(self) -> None:
        sel = self._prog_tree.selection()
        if not sel:
            return
        idx = self._iid_to_idx.get(sel[0])
        if idx is None:
            return
        prog = self._programs[idx]
        self._source.configure(state="normal")
        self._source.delete("1.0", "end")
        code = prog.get("code", "") or "(empty program)"
        self._source.insert("1.0", code)

        # Faint coloring for PPCL comment lines (start with 'C ' after the
        # line number, or are the bare 'C' filler)
        self._source.tag_remove("comment", "1.0", "end")
        line_count = int(self._source.index("end-1c").split(".")[0])
        for ln in range(1, line_count + 1):
            line = self._source.get(f"{ln}.0", f"{ln}.end")
            stripped = line.strip()
            # PPCL convention: "NNNN    C <comment>" or "NNNN    C"
            parts = stripped.split(None, 2)
            if len(parts) >= 2 and parts[1].upper() == "C":
                self._source.tag_add("comment", f"{ln}.0", f"{ln}.end")

        self._source.configure(state="disabled")
        self._source.yview_moveto(0)
        # Re-apply any active find
        self._find_in_source()

    def _find_in_source(self) -> None:
        """Highlight all occurrences of the find-text in the current source."""
        self._source.configure(state="normal")
        try:
            self._source.tag_remove("search_hit", "1.0", "end")
            needle = self._find_var.get()
            if not needle:
                return
            start = "1.0"
            while True:
                pos = self._source.search(needle, start, "end", nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(needle)}c"
                self._source.tag_add("search_hit", pos, end)
                start = end
        finally:
            self._source.configure(state="disabled")

    def _find_next(self) -> None:
        """Scroll to the next search hit past the current view."""
        needle = self._find_var.get()
        if not needle:
            return
        current_top = self._source.index("@0,0")
        # Search from after current_top; wrap to start if nothing found
        pos = self._source.search(
            needle, f"{current_top}+1c", "end", nocase=True
        )
        if not pos:
            pos = self._source.search(needle, "1.0", "end", nocase=True)
        if pos:
            self._source.see(pos)


DEFAULT_CONFIG_PATH = os.path.join(_HERE, "site.json")
POLL_INTERVAL_MS = 80


# ═══════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class MainWindow:
    def __init__(self, root: tk.Tk, config_path: str) -> None:
        self.root = root
        self.config_path = config_path

        self.log_queue: "queue.Queue[Tuple[str, str]]" = queue.Queue()
        self.result_queue: "queue.Queue[tuple]" = queue.Queue()
        # Used for mid-task progress updates (e.g. live-verify per-device
        # status flips) separate from final results. Workers push tuples
        # here; the UI thread drains them in _poll().
        self.progress_queue: "queue.Queue[tuple]" = queue.Queue()
        self.runner = TaskRunner(self.log_queue, self.result_queue)

        # (node_name, device_name) -> list of result dicts (latest scan only)
        # Used for the detail-panel "restore when I click back" behavior.
        # Full scan history with timestamps lives separately in scan_history.
        self._device_cache: Dict[Tuple[str, str], List[Dict]] = {}
        # Session-wide scan history: every scan and sweep done since launch,
        # with timestamps so the user can go back and compare.
        self.scan_history = ScanHistory()
        # node_name -> firmware info dict
        self._firmware_cache: Dict[str, Dict] = {}
        # node_name -> list of device dicts from enumerate
        self._node_devices: Dict[str, List[Dict]] = {}
        # node_name -> telnet-open bool (populated by cold-discover or
        # by Refresh Telnet Status; persisted to site.json's node_telnet)
        self._node_telnet: Dict[str, bool] = {}

        self._current_device: Optional[Dict] = None
        self._current_node: Optional[Dict] = None

        self._build_ui()
        self._refresh_identity_labels()
        self._rebuild_tree_from_config()

        self._load_config_if_present()
        self._start_polling()

        # Note on first-connect latency for users new to this build. The
        # scanner auto-detects legacy vs modern PXC wire dialect. With the
        # firmware-build registry (firmware_registry.py) cached in
        # site.json, known panels skip the probe entirely; only the
        # first-ever connect to an unknown panel pays ~2s.
        self.log.log(
            "Scanner supports both legacy (PME1252) and modern "
            "(PME1300) PXC firmware.",
            level="info",
        )
        self.log.log(
            "First connect to an unknown panel may take ~2s extra while "
            "the dialect is probed; the build tag is then cached in "
            "site.json so every later connect skips the probe.",
            level="info",
        )

        root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.root.title("P2 Scanner — GUI")
        # Size + center on screen (nothing worse than an app opening
        # scrunched in the top-left corner on a multi-monitor setup).
        w, h = 1240, 820
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(960, 600)

        try:
            style = ttk.Style()
            # 'clam' is the most consistent cross-platform ttk theme
            if "clam" in style.theme_names():
                style.theme_use("clam")
            style.configure("Treeview", rowheight=22)
        except tk.TclError:
            pass

        # ── Menu ─────────────────────────────────────────────────────
        menubar = tk.Menu(self.root)

        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Load Config…", command=self._menu_load)
        filemenu.add_command(label="Save Config", command=self._menu_save)
        filemenu.add_command(label="Save Config As…", command=self._menu_save_as)
        filemenu.add_separator()
        filemenu.add_command(label="Edit Site Config…", command=self._menu_edit_config)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=filemenu)

        discmenu = tk.Menu(menubar, tearoff=0)
        discmenu.add_command(
            label="Cold Discover (Auto)…",
            command=self._menu_cold_discover_auto,
        )
        discmenu.add_command(
            label="Port Scan Range…", command=self._menu_port_scan
        )
        discmenu.add_command(
            label="Add Node Manually…", command=self._menu_add_node
        )
        discmenu.add_separator()
        discmenu.add_command(
            label="Refresh Telnet Status",
            command=self._menu_refresh_telnet,
        )
        discmenu.add_separator()
        discmenu.add_command(
            label="Sweep Points Across Devices…", command=self._menu_sweep
        )
        menubar.add_cascade(label="Discovery", menu=discmenu)

        viewmenu = tk.Menu(menubar, tearoff=0)
        viewmenu.add_command(
            label="Scan History…", command=self._menu_scan_history
        )
        menubar.add_cascade(label="View", menu=viewmenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="User Guide", command=self._menu_user_guide)
        helpmenu.add_separator()
        helpmenu.add_command(label="About", command=self._menu_about)
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.root.config(menu=menubar)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = ttk.Frame(self.root, padding=(10, 6))
        toolbar.pack(side="top", fill="x")

        self.net_label = ttk.Label(
            toolbar, text="Network: —", font=("", 10, "bold")
        )
        self.net_label.pack(side="left", padx=(0, 14))
        self.site_label = ttk.Label(toolbar, text="Site: —", foreground="#666")
        self.site_label.pack(side="left", padx=(0, 14))
        self.scanner_label = ttk.Label(
            toolbar, text="Scanner: —", foreground="#666"
        )
        self.scanner_label.pack(side="left", padx=(0, 14))

        ttk.Button(
            toolbar, text="Edit Config…", command=self._menu_edit_config
        ).pack(side="right", padx=2)

        self.debug_var = tk.BooleanVar()
        ttk.Checkbutton(
            toolbar,
            text="Debug reads",
            variable=self.debug_var,
            command=self._toggle_debug,
        ).pack(side="right", padx=12)

        # ── Main body (vertical paned: work area | log) ──────────────
        vpane = ttk.PanedWindow(self.root, orient="vertical")
        vpane.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        hpane = ttk.PanedWindow(vpane, orient="horizontal")
        vpane.add(hpane, weight=3)

        # Left: tree + node-level buttons
        left = ttk.Frame(hpane)
        hpane.add(left, weight=1)

        self.tree = NodeTree(
            left,
            on_select_node=self._on_select_node,
            on_select_device=self._on_select_device,
        )
        self.tree.pack(side="top", fill="both", expand=True)

        tree_btns = ttk.Frame(left)
        tree_btns.pack(side="top", fill="x", pady=(6, 0))
        self._enum_btn = ttk.Button(
            tree_btns, text="Enumerate FLN", command=self._enumerate_node
        )
        self._enum_btn.pack(side="left", padx=2, fill="x", expand=True)
        self._verify_btn = ttk.Button(
            tree_btns, text="Verify Online", command=self._verify_node
        )
        self._verify_btn.pack(side="left", padx=2, fill="x", expand=True)
        self._firmware_btn = ttk.Button(
            tree_btns, text="Firmware", command=self._query_firmware
        )
        self._firmware_btn.pack(side="left", padx=2, fill="x", expand=True)

        # Secondary node operations: panel-wide walks that are potentially
        # slow (10-30s on a busy panel), so given their own row so they're
        # distinct from the snappy primary ops.
        tree_btns2 = ttk.Frame(left)
        tree_btns2.pack(side="top", fill="x", pady=(3, 0))
        self._walk_btn = ttk.Button(
            tree_btns2, text="Walk All Points", command=self._walk_all_points
        )
        self._walk_btn.pack(side="left", padx=2, fill="x", expand=True)
        self._programs_btn = ttk.Button(
            tree_btns2, text="PPCL Programs", command=self._dump_programs
        )
        self._programs_btn.pack(side="left", padx=2, fill="x", expand=True)

        # Right: device detail
        right = ttk.Frame(hpane, padding=(8, 0, 0, 0))
        hpane.add(right, weight=3)

        self.detail_header = ttk.Label(
            right, text="Select a node or device", font=("", 12, "bold")
        )
        self.detail_header.pack(anchor="w")
        self.detail_subhead = ttk.Label(
            right, text="", foreground="#555"
        )
        self.detail_subhead.pack(anchor="w", pady=(0, 8))

        detail_btns = ttk.Frame(right)
        detail_btns.pack(fill="x", pady=(0, 8))
        self._scan_all_btn = ttk.Button(
            detail_btns,
            text="Scan All Points",
            command=self._scan_all,
            state="disabled",
        )
        self._scan_all_btn.pack(side="left", padx=2)
        self._quick_btn = ttk.Button(
            detail_btns,
            text="Quick Scan",
            command=self._scan_quick,
            state="disabled",
        )
        self._quick_btn.pack(side="left", padx=2)
        self._single_btn = ttk.Button(
            detail_btns,
            text="Read Point…",
            command=self._read_single,
            state="disabled",
        )
        self._single_btn.pack(side="left", padx=2)

        ttk.Separator(detail_btns, orient="vertical").pack(
            side="left", fill="y", padx=10
        )
        self._csv_btn = ttk.Button(
            detail_btns,
            text="Export CSV…",
            command=self._export_csv,
            state="disabled",
        )
        self._csv_btn.pack(side="left", padx=2)
        self._json_btn = ttk.Button(
            detail_btns,
            text="Export JSON…",
            command=self._export_json,
            state="disabled",
        )
        self._json_btn.pack(side="left", padx=2)

        self.point_table = PointTable(right)
        self.point_table.pack(fill="both", expand=True)

        # ── Log pane ────────────────────────────────────────────────
        logframe = ttk.LabelFrame(vpane, text=" Log ", padding=4)
        vpane.add(logframe, weight=1)
        self.log = LogPane(logframe, self.log_queue)
        self.log.pack(fill="both", expand=True)

        # ── Status bar ──────────────────────────────────────────────
        status = ttk.Frame(self.root, padding=(10, 3))
        status.pack(side="bottom", fill="x")
        self.status_label = ttk.Label(status, text="Ready", foreground="#555")
        self.status_label.pack(side="left")
        # Cancel button — visible only when a task is in flight. Signals
        # cooperative cancel; the worker checks runner.stop_event at its
        # next checkpoint and bails out cleanly. Hard backstop is the
        # daemon-thread + os._exit() in _on_close.
        self.cancel_btn = ttk.Button(
            status, text="Cancel", command=self._cancel_current
        )
        self.busy_label = ttk.Label(status, text="", foreground="#c48a00")
        self.busy_label.pack(side="right")
        # Don't pack cancel_btn yet — _set_busy will pack it; _clear_busy
        # will hide it again.

    # ------------------------------------------------------------------
    # Config handling
    # ------------------------------------------------------------------

    def _load_config_if_present(self) -> None:
        if not os.path.exists(self.config_path):
            self.log.log(
                f"No config at {self.config_path} — use File → Edit Site Config to get started.",
                level="warn",
            )
            return
        try:
            # Use the scanner's own loader so globals are set correctly
            ok = p2.load_config(self.config_path)
            # Pull node_telnet separately — the scanner's load_config
            # doesn't know about it (it's a GUI-side display map).
            try:
                with open(self.config_path) as f:
                    raw = json.load(f)
                self._node_telnet = {
                    k: bool(v)
                    for k, v in (raw.get("node_telnet") or {}).items()
                }
            except (json.JSONDecodeError, OSError):
                self._node_telnet = {}
            if ok:
                self.log.log(
                    f"Loaded config: network={p2.P2_NETWORK or '—'}, "
                    f"site={p2.P2_SITE or '—'}, "
                    f"{len(p2.KNOWN_NODES)} nodes",
                    level="ok",
                )
                self._refresh_identity_labels()
                self._rebuild_tree_from_config()
                # Warn on obvious placeholder values
                if p2.P2_NETWORK == "MYBLN" or p2.P2_SITE == "SITE":
                    self.log.log(
                        "Config still has placeholder values (MYBLN / SITE). "
                        "Edit via File → Edit Site Config before running scans.",
                        level="warn",
                    )
        except Exception as e:
            self.log.log(f"Config load failed: {e}", level="error")

    def _current_config_dict(self) -> Dict:
        """Snapshot the scanner's current globals into a config dict."""
        return {
            "p2_network": p2.P2_NETWORK,
            "p2_site": p2.P2_SITE,
            "scanner_name": p2.SCANNER_NAME,
            "known_nodes": dict(p2.KNOWN_NODES),
            # node_telnet is a separate map (node_name -> bool) populated
            # by polished_cold_discover and "Refresh Telnet Status." Not
            # stored as a scanner-module global — kept here on the GUI
            # since it's a display-layer concern.
            "node_telnet": dict(getattr(self, "_node_telnet", {})),
        }

    def _apply_config_dict(self, cfg: Dict) -> None:
        """Apply config dict into scanner globals."""
        p2._set_network(cfg.get("p2_network", ""))
        p2._set_scanner_name(cfg.get("scanner_name", "P2SCAN-LAP|5033"))
        # P2_SITE doesn't have a setter — write to the module directly
        p2.P2_SITE = cfg.get("p2_site", "")
        # KNOWN_NODES is a dict the scanner mutates; replace contents
        p2.KNOWN_NODES.clear()
        p2.KNOWN_NODES.update(cfg.get("known_nodes", {}))
        # Telnet status is GUI-side state. Init from the loaded config
        # if present; otherwise leave empty (rendered as "unknown" per
        # node — no false signal).
        self._node_telnet: Dict[str, bool] = dict(cfg.get("node_telnet", {}))

    def _save_config_to(self, path: str) -> bool:
        try:
            # save_config reads from module globals; write it ourselves so
            # we can preserve arbitrary extra keys too (e.g. _comment)
            existing: Dict = {}
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        existing = json.load(f)
                except Exception:
                    existing = {}
            existing["p2_network"] = p2.P2_NETWORK
            existing["p2_site"] = p2.P2_SITE
            existing["scanner_name"] = p2.SCANNER_NAME
            existing["known_nodes"] = dict(p2.KNOWN_NODES)
            # Persist telnet-status map alongside the rest. Renamed-out
            # nodes are dropped; unprobed nodes keep no entry (rendered
            # as "unknown" on next load, not "closed").
            telnet = {
                name: bool(open_)
                for name, open_ in getattr(self, "_node_telnet", {}).items()
                if name in p2.KNOWN_NODES
            }
            if telnet:
                existing["node_telnet"] = telnet
            elif "node_telnet" in existing:
                # All probes cleared — drop the key rather than keep a
                # stale dict around.
                existing.pop("node_telnet", None)
            with open(path, "w") as f:
                json.dump(existing, f, indent=2)
            return True
        except OSError as e:
            messagebox.showerror("Save failed", str(e), parent=self.root)
            return False

    def _effective_scanner_identity(self) -> str:
        """Return the scanner identity that will actually appear in slot 4
        of outgoing handshakes. This calls `p2.effective_scanner_name()`
        which silently substitutes `<SITE>DCC-SVR|5033` when the configured
        SCANNER_NAME equals the generic default and P2_SITE is set.
        Use this in scan-start log messages so the operator sees the
        actual on-wire identity rather than just the configured one.
        """
        if not p2:
            return ""
        try:
            return p2.effective_scanner_name()
        except Exception:
            return p2.SCANNER_NAME

    def _refresh_identity_labels(self) -> None:
        net = p2.P2_NETWORK if p2 else ""
        site = p2.P2_SITE if p2 else ""
        # Show the EFFECTIVE on-wire scanner name, not the configured one.
        # `effective_scanner_name()` silently substitutes the configured
        # value when it equals the generic default — the substituted
        # value (`<SITE>DCC-SVR|5033`) is what actually goes in slot 4 of
        # every handshake. Showing the configured value here would
        # mislead the operator about what name is being used on the wire.
        try:
            scanner = p2.effective_scanner_name() if p2 else ""
        except Exception:
            scanner = p2.SCANNER_NAME if p2 else ""
        # If the effective name differs from the configured name (silent
        # substitution active), annotate so the user understands what's
        # actually happening.
        configured = p2.SCANNER_NAME if p2 else ""
        if scanner and configured and scanner != configured:
            scanner_display = f"{scanner}  (auto-built from site; configured: {configured})"
        else:
            scanner_display = scanner or "—"
        self.net_label.configure(text=f"Network: {net or '—'}")
        self.site_label.configure(text=f"Site: {site or '—'}")
        self.scanner_label.configure(text=f"Scanner: {scanner_display}")

    def _rebuild_tree_from_config(self) -> None:
        """Rebuild the tree to reflect current p2.KNOWN_NODES."""
        self.tree.set_network(p2.P2_NETWORK)
        telnet_map = getattr(self, "_node_telnet", {}) or {}
        for name, ip in sorted(p2.KNOWN_NODES.items()):
            self.tree.add_node(name, ip,
                               telnet_open=telnet_map.get(name))

    # ------------------------------------------------------------------
    # Menu handlers
    # ------------------------------------------------------------------

    def _menu_load(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Load site config",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            initialdir=_HERE,
        )
        if not path:
            return
        self.config_path = path
        self._load_config_if_present()

    def _menu_save(self) -> None:
        if self._save_config_to(self.config_path):
            self.log.log(f"Saved config to {self.config_path}", level="ok")

    def _menu_save_as(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save site config",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialdir=_HERE,
        )
        if not path:
            return
        if self._save_config_to(path):
            self.config_path = path
            self.log.log(f"Saved config to {path}", level="ok")

    def _menu_edit_config(self) -> None:
        new_cfg = ConfigDialog.ask(self.root, self._current_config_dict())
        if new_cfg is None:
            return
        self._apply_config_dict(new_cfg)
        self._refresh_identity_labels()
        self._rebuild_tree_from_config()
        # Clear caches — they were keyed on the previous identity
        self._device_cache.clear()
        self._firmware_cache.clear()
        self._node_devices.clear()
        self._clear_detail_panel()
        self.log.log("Config updated (not yet saved to disk).", level="info")

    def _menu_add_node(self) -> None:
        # Import the small name+IP dialog directly from widgets; avoids
        # reopening the full ConfigDialog (which Edit Config already does).
        pass  # (merged) widgets are defined in this file

        r = _NodeEditDialog.ask(self.root, "Add Node")
        if not r:
            return
        name, ip = r
        if name in p2.KNOWN_NODES and not messagebox.askyesno(
            "Replace existing?",
            f"Node '{name}' already maps to {p2.KNOWN_NODES[name]}.\n"
            f"Replace with {ip}?",
            parent=self.root,
        ):
            return
        p2.KNOWN_NODES[name] = ip
        self._rebuild_tree_from_config()
        self.log.log(f"Added node {name} → {ip}", level="ok")

    def _menu_port_scan(self) -> None:
        if self.runner.busy:
            messagebox.showinfo(
                "Busy", "Finish the current operation first.", parent=self.root
            )
            return
        range_str = simpledialog.askstring(
            "Port Scan",
            "IP range to scan for PXC (TCP/5033):\n\n"
            "Formats:  192.0.2.50  |  192.0.2.80-200  |  192.0.2.0/24  |  192.0.2",
            parent=self.root,
        )
        if not range_str:
            return
        range_str = range_str.strip()
        self.log.log(f"Port-scanning {range_str} for PXC on TCP/5033…")
        self._set_busy(f"Port scanning {range_str}…")
        self.runner.submit(
            ("port_scan", range_str),
            self._do_port_scan,
            range_str,
        )

    # ------------------------------------------------------------------
    # Cold-discover (auto): one-shot polished discovery
    # ------------------------------------------------------------------
    #
    # Auto-detects the local /24, port-scans for PXCs on TCP/5033, bootstraps
    # BLN + supervisor + per-panel names via the 0x0050 StatusQuery primitive,
    # then atomically writes everything to the currently-loaded site.json and
    # reloads the in-memory config + UI tree. The whole flow is the polished
    # version of what would otherwise be: open a terminal, run
    # `p2_scanner --auto-discover --save site.json`, then File → Load Config.

    def _menu_cold_discover_auto(self) -> None:
        if not self._check_busy():
            return
        # Auto-detect to pre-fill the range field — user can override.
        subnets = p2.auto_detect_local_subnets() if p2 else []
        default_range = subnets[0] if subnets else ""

        # Step 1: ask for subnet to scan
        subnet_prompt = (
            f"Cold-discover via the validated 2-packet primitive.\n"
            f"Auto-detected subnet: {default_range or '(none)'}\n\n"
            f"Subnet (CIDR, e.g. 192.0.2.0/24):"
        )
        network = simpledialog.askstring(
            "Cold Discover — step 1/3: subnet",
            subnet_prompt,
            initialvalue=default_range,
            parent=self.root,
        )
        if not network:
            return
        network = network.strip()
        try:
            from ipaddress import ip_network
            ip_network(network, strict=False)
        except ValueError:
            messagebox.showerror(
                "Cold Discover",
                f"Not a valid CIDR or IP: {network!r}\n\n"
                "Use formats like 192.168.1.0/24 or 192.0.2.0/24.",
                parent=self.root,
            )
            return

        # Step 2: BLN — leave blank to auto-discover via active probe.
        # The worker iterates BLN candidates against the first port-scanned
        # PXC with the 15-char placeholder in slot 4. Wrong-BLN guesses
        # get TCP-RST without writing anything; only the correct BLN
        # gets accepted/silent-dropped (writes 1 placeholder entry).
        # Total NODE NAME TABLE footprint for the whole discovery: ONE
        # entry BLN-wide under RANDOM15CHARSXY.
        current_bln = (p2.P2_NETWORK
                       if p2 and p2.P2_NETWORK and p2.P2_NETWORK != 'MYBLN'
                       else '')
        bln_prompt = (
            "BLN (Building-Level Network) name — leave blank to auto-discover.\n\n"
            "Siemens also calls this the ALN (Automation Level Network).\n"
            "Both terms refer to the same network; firmware prompts and\n"
            "Desigo CC's APOGEE Configuration use BLN.\n\n"
            "If blank: active probe tries a list of common BLN patterns\n"
            "against the first PXC found. Wrong guesses TCP-RST without\n"
            "any NODE NAME TABLE write; only the correct BLN gets accepted.\n"
            "Add a site hint in step 3 to narrow the candidate list (e.g.\n"
            "site_hint='ACME' → tries ACMEEBLN, ACMEBLN, ACME_BLN, ...).\n\n"
            "If filled: skip auto-discovery, use the value as-is.\n\n"
            "Find it (if you want to fill it in manually):\n"
            "  • Desigo CC → System Browser → Project → Field Networks\n"
            "  • Desigo CC → APOGEE Configuration → BLN system name\n"
            "  • Field panel HMI: S → H → S → F → C → H → M → BLN Name\n"
            "  • Existing site.json (p2_network key)\n\n"
            "Note: BLN names are case-sensitive ASCII per Siemens documentation.\n\n"
            "BLN name (blank = auto-discover):"
        )
        bln = simpledialog.askstring(
            "Cold Discover — step 2/3: BLN name (optional)",
            bln_prompt,
            initialvalue=current_bln,
            parent=self.root,
        )
        if bln is None:
            return  # user clicked Cancel
        bln = bln.strip()
        if bln in ('MYBLN', 'SITE'):
            messagebox.showerror(
                "Cold Discover",
                f"BLN {bln!r} is a placeholder, not a real BLN name.\n\n"
                "Either look it up in Desigo CC, or leave the field blank "
                "to auto-discover.",
                parent=self.root,
            )
            return
        # Empty bln is OK — worker will auto-discover

        # Step 3: site hint (optional, only relevant if BLN is blank).
        # If user provides 'ACME', the candidate list becomes ACME-prefixed
        # patterns (ACMEEBLN, ACMEBLN, ACME_BLN, ACME-BLN, ACME_EBLN, ACME-EBLN,
        # ACME, ACMENET). If user leaves blank, the worker does 15 s passive
        # BACnet/IP recon (UDP/47808) and infers the site prefix from
        # supervisor and other BACnet device names — pure passive, no
        # writes, works on switched networks because BACnet broadcasts
        # are visible to every host on the subnet.
        site_hint = ''
        if not bln:
            current_site = (p2.P2_SITE
                            if p2 and p2.P2_SITE and p2.P2_SITE != 'SITE'
                            else '')
            site_hint_prompt = (
                "Site hint (optional, ONLY if BLN auto-discovery struggles).\n\n"
                "If blank (recommended for first run at a new site):\n"
                "  Worker does 15 s passive BACnet/IP recon (UDP/47808)\n"
                "  and infers the site prefix from Desigo CC's device\n"
                "  name and other BACnet controllers on the network.\n"
                "  Then generates BLN candidates from that prefix and\n"
                "  active-probes them against the first PXC found.\n"
                "  Pure passive recon = zero NODE NAME TABLE writes\n"
                "  during prefix discovery.\n\n"
                "If you know the site prefix and want to skip BACnet recon:\n"
                "  Examples:\n"
                "    • ACME → tries ACMEEBLN, ACMEBLN, ACME_BLN, ACME-BLN, ...\n"
                "    • MAIN → tries MAINEBLN, MAINBLN, MAIN_BLN, ...\n\n"
                "Site prefix (blank = BACnet recon auto-detect):"
            )
            site_hint = simpledialog.askstring(
                "Cold Discover — step 3/3: site hint (optional)",
                site_hint_prompt,
                initialvalue=current_site,
                parent=self.root,
            )
            if site_hint is None:
                return  # user clicked Cancel
            site_hint = site_hint.strip()

        # Placeholder name that lands in NODE NAME TABLE
        placeholder = getattr(p2, 'V1A_WILDCARD_15CHAR', None) or getattr(
            p2, 'WILDCARD_15CHAR_PLACEHOLDER', 'RANDOM15CHARSXY')

        # Final confirmation — explicit about the footprint and cleanup.
        if bln:
            bln_display = bln
            time_estimate = "~1–3 min"
        elif site_hint:
            bln_display = (f"(active auto-discover, "
                           f"site_hint={site_hint!r})")
            time_estimate = "~1.5–3.5 min (includes BLN auto-discover)"
        else:
            bln_display = ("(BACnet recon + active auto-discover, "
                           "no site hint)")
            time_estimate = ("~2–4 min (includes 15 s BACnet recon + "
                             "BLN auto-discover)")

        # Build the numbered step list dynamically based on which auto-
        # phases will run, so the user sees exactly what's about to happen.
        steps = []
        steps.append(f"Port-scan {network} for TCP/5033")
        if not bln and not site_hint:
            steps.append("15 s passive BACnet/IP recon (UDP/47808) "
                         "to infer site prefix")
        if not bln:
            steps.append(f"Active BLN auto-discover against first PXC\n"
                         f"     (wrong-BLN guesses TCP-RST — NO writes)")
        steps.append(f"Per PXC: Identify handshake (BLN, "
                     f"scanner={placeholder})\n"
                     f"     trying node1..node20 in slot 2 until one accepts")
        steps.append("Per accepted PXC: 0x0050 chain for supervisor name")
        steps.append("Telnet probe per resolved panel")
        steps.append(f"Save site.json → {self.config_path}")
        steps_text = "\n".join(f"  {i+1}. {s}"
                               for i, s in enumerate(steps))

        if not messagebox.askyesno(
            "Cold Discover — confirm",
            f"Run cold discovery on {network} with BLN={bln_display}?\n\n"
            f"What this does:\n{steps_text}\n\n"
            f"NODE NAME TABLE footprint:\n"
            f"  ONE entry BLN-wide under '{placeholder}' → your IP.\n"
            f"  (Wrong-BLN probes don't write — TCP RST happens before\n"
            f"   any application-layer processing. BACnet recon is\n"
            f"   pure passive UDP listen — zero packets sent.)\n"
            f"  Cleanup afterward via telnet on any 📡 panel:\n"
            f"      Fieldpanels dElete {placeholder}\n"
            f"      nodeNametable Remove {placeholder}\n"
            f"  (delete from Fieldpanels FIRST — reverse order strands\n"
            f"   the field-panel entry)\n\n"
            f"Cancel button is in the status bar (bottom-right) while\n"
            f"discovery runs.\n\n"
            f"Time: {time_estimate} depending on subnet + panel count.",
            parent=self.root,
        ):
            return

        self.log.log(f"Cold-discover on {network} (BLN={bln_display}) → "
                     f"will save to {self.config_path}")
        self._set_busy(f"Cold-discover on {network}…")
        self.runner.submit(
            ("cold_auto", network),
            self._do_cold_discover_auto,
            network,
            bln,
            site_hint,
            self.config_path,
            self.runner.stop_event,
        )

    @staticmethod
    def _do_cold_discover_auto(network: str, bln: str,
                               site_hint: str,
                               save_path: str,
                               stop_event) -> Optional[Dict]:
        """Worker: run polished_cold_discover (2-packet primitive +
        active BLN auto-discover when bln is empty) and let it write
        site.json.

        Returns the discovered site_config dict (or None) for the result
        handler to apply to in-memory globals and refresh the UI. Polls
        stop_event between phases / per-host iterations so the Cancel
        button can abort cleanly.
        """
        return p2.polished_cold_discover(
            network=network,
            bln=bln or None,         # convert '' to None for auto-discover
            site_hint=site_hint or None,
            save_to=save_path,
            probe_delay=0.5,
            stop_event=stop_event,
            verbose=True,
        )

    def _on_cold_discover_auto_done(
        self, task_id: tuple, result: Optional[Dict]
    ) -> None:
        if not result:
            self.log.log(
                "Cold discover: nothing found. The subnet may have no PXCs, "
                "or none responded to either the bootstrap or the wildcard "
                "handshake. Check connectivity and try again.",
                level="warn",
            )
            messagebox.showinfo(
                "Cold Discover",
                "No PXCs were discovered on the scanned subnet.\n\n"
                "Things to check:\n"
                "  • Is this machine on the BAS VLAN?\n"
                "  • Is anything responding on TCP/5033?\n"
                "  • Try Port Scan Range… first to confirm IP-level "
                "reachability.",
                parent=self.root,
            )
            return

        # The library already wrote site.json atomically; refresh the
        # in-memory config so the UI matches what's now on disk.
        self._apply_config_dict(result)
        self._refresh_identity_labels()
        self._rebuild_tree_from_config()
        self._device_cache.clear()
        self._firmware_cache.clear()
        self._node_devices.clear()
        self._clear_detail_panel()

        node_count = len(result.get("known_nodes", {}))
        bln = result.get("p2_network", "")
        site = result.get("p2_site", "")
        scanner = result.get("scanner_name", "")
        telnet_map = result.get("node_telnet", {}) or {}
        telnet_open = sum(1 for v in telnet_map.values() if v)
        self.log.log(
            f"Cold discover complete: BLN={bln!r} site={site!r} "
            f"scanner={scanner!r}, {node_count} node(s), "
            f"telnet open on {telnet_open}/{len(telnet_map) or node_count}. "
            f"Saved to {self.config_path}.",
            level="ok",
        )
        # Surface the result in a dialog too — a one-shot operation that
        # silently mutates the entire site config deserves visible feedback.
        messagebox.showinfo(
            "Cold Discover — complete",
            f"Discovered and saved to {self.config_path}:\n\n"
            f"  Network (BLN):  {bln or '—'}\n"
            f"  Site:           {site or '—'}\n"
            f"  Scanner name:   {scanner or '—'}\n"
            f"  Panels:         {node_count}\n"
            f"  Telnet open:    {telnet_open}/{len(telnet_map) or node_count}"
            f"  (📡 = open in tree)\n\n"
            f"The tree on the left has been refreshed. Use Enumerate FLN "
            f"on each node to populate devices, or open telnet to any 📡 "
            f"panel for nodeNametable cleanup.",
            parent=self.root,
        )

    # ------------------------------------------------------------------
    # Refresh telnet status — re-probe every known node's TCP/23
    # ------------------------------------------------------------------
    #
    # The cold-discover flow does this once at end-of-discovery, but
    # telnet policy can change over time (operator disables it on a
    # panel after cleanup, a freshly-flashed panel comes online with
    # defaults), so a manual refresh is the cheapest way to get an
    # accurate per-panel indicator without re-running cold-discover.

    def _menu_refresh_telnet(self) -> None:
        if not self._check_busy():
            return
        if not p2.KNOWN_NODES:
            messagebox.showinfo(
                "Refresh Telnet Status",
                "No known nodes to probe. Run Cold Discover (Auto) first, "
                "or add nodes via File → Edit Site Config.",
                parent=self.root,
            )
            return
        n = len(p2.KNOWN_NODES)
        self.log.log(
            f"Probing TCP/23 (telnet) on {n} known node(s)…"
        )
        self._set_busy(f"Probing telnet on {n} nodes…")
        # Snapshot the name->ip map so the worker doesn't read mutable
        # GUI state from another thread.
        nodes_snapshot = dict(p2.KNOWN_NODES)
        self.runner.submit(
            ("refresh_telnet", n),
            self._do_refresh_telnet,
            nodes_snapshot,
        )

    @staticmethod
    def _do_refresh_telnet(nodes: Dict[str, str]) -> Dict[str, bool]:
        """Worker: probe each node's TCP/23. Returns {node_name: open_bool}."""
        out: Dict[str, bool] = {}
        for i, (name, ip) in enumerate(sorted(nodes.items()), start=1):
            print(f"  [{i}/{len(nodes)}] {name:<14} {ip:<16}",
                  end=" ", flush=True)
            r = p2.probe_telnet_status(ip, timeout=1.0, read_banner=False)
            out[name] = bool(r['open'])
            print("OPEN" if r['open']
                  else f"closed ({r['error']})")
        open_count = sum(1 for v in out.values() if v)
        print(f"  Telnet open on {open_count}/{len(out)} node(s)")
        return out

    def _on_refresh_telnet_done(self, task_id: tuple,
                                result: Dict[str, bool]) -> None:
        if not result:
            self.log.log("Telnet refresh: no results.", level="warn")
            return
        self._node_telnet = dict(result)
        # Push each row's indicator into the tree without touching the
        # online/offline P2 status. set_node_telnet preserves it.
        for name, open_ in self._node_telnet.items():
            self.tree.set_node_telnet(name, open_)
        # Persist alongside the rest of site config so the next launch
        # shows the same indicators without re-probing.
        if self._save_config_to(self.config_path):
            open_count = sum(1 for v in result.values() if v)
            self.log.log(
                f"Telnet refresh: {open_count}/{len(result)} open. "
                f"Saved to {self.config_path}.",
                level="ok",
            )
        else:
            open_count = sum(1 for v in result.values() if v)
            self.log.log(
                f"Telnet refresh: {open_count}/{len(result)} open "
                f"(not saved — File → Save Config when ready).",
                level="warn",
            )

    # ------------------------------------------------------------------
    # Sweep — read specified points across many devices at once
    # ------------------------------------------------------------------

    def _menu_sweep(self) -> None:
        if not self._check_busy():
            return
        if not p2.P2_NETWORK:
            messagebox.showwarning(
                "No network name",
                "Set the BLN network name first (File → Edit Site Config).",
                parent=self.root,
            )
            return

        # Build the "available nodes" list from config, plus per-node device
        # counts (total / online) from whatever we've already enumerated.
        available_nodes = [
            {"name": name, "ip": ip}
            for name, ip in sorted(p2.KNOWN_NODES.items())
        ]
        device_counts: Dict[str, Tuple[int, int]] = {}
        for name, ip in p2.KNOWN_NODES.items():
            devs = self._node_devices.get(name, [])
            total = len(devs)
            online = sum(1 for d in devs if d.get("status") == "online")
            device_counts[name] = (total, online)

        if not any(tot for tot, _ in device_counts.values()):
            if not messagebox.askyesno(
                "No enumerated devices",
                "No devices have been enumerated yet. A sweep with nothing "
                "to read will produce nothing.\n\n"
                "Enumerate FLN on at least one node first, or open the "
                "dialog anyway to review options?",
                parent=self.root,
            ):
                return

        spec = SweepDialog.ask(self.root, available_nodes, device_counts)
        if not spec:
            return

        targets = self._build_sweep_targets(spec)
        if not targets:
            messagebox.showinfo(
                "Nothing to sweep",
                "No devices matched the selected scope. Try enumerating "
                "more nodes or loosening the scope (e.g. 'All enumerated' "
                "instead of 'Only online').",
                parent=self.root,
            )
            return

        self._last_sweep_spec = spec  # for re-sweep
        self.log.log(
            f"Sweeping {len(spec['points'])} point(s) "
            f"across {len(targets)} device(s)…"
        )
        self._set_busy(f"Sweeping {len(targets)} devices…")
        self.runner.submit(
            ("sweep", tuple(spec["points"])),
            self._do_sweep_points,
            targets,
            list(spec["points"]),
        )

    def _build_sweep_targets(self, spec: Dict) -> List[Dict]:
        """Turn a SweepDialog spec into a concrete list of target dicts.

        Each target: {'node', 'host', 'device', 'description', 'application'}
        """
        selected_nodes = spec["nodes"]
        scope = spec["scope"]  # 'all' | 'online'

        targets: List[Dict] = []
        for node_name in sorted(selected_nodes):
            host = p2.KNOWN_NODES.get(node_name)
            if not host:
                continue
            devs = self._node_devices.get(node_name, [])
            for d in devs:
                if scope == "online" and d.get("status") != "online":
                    continue
                targets.append(
                    {
                        "node": node_name,
                        "host": host,
                        "device": d["device"],
                        "description": d.get("description", ""),
                        "application": d.get("application", 0) or 0,
                    }
                )
        return targets

    @staticmethod
    def _do_sweep_points(
        targets: List[Dict], points: List[str]
    ) -> List[Dict]:
        """Worker: iterate devices, read `points` on each, collect results.

        Runs in the background worker thread. Prints progress via the
        redirected stdout so the UI log shows live status.
        """
        sweep_results: List[Dict] = []
        total = len(targets)

        for i, t in enumerate(targets, start=1):
            node = t["node"]
            host = t["host"]
            dev = t["device"]
            desc = t["description"]
            app = t["application"]

            # Per-device optimization: if we know the app, filter out points
            # that aren't defined in its point table. Saves timeouts for
            # points like "HEAT.COOL" when sweeping across a mixed-app
            # building where not every app has that point. Numeric slot
            # references are kept regardless since they resolve per-app.
            scan_points: List[str] = []
            skipped: List[str] = []
            if app:
                try:
                    table = p2.get_point_table(app)
                except Exception:
                    table = None
                if table:
                    defined = {entry[0] for entry in table.values()}
                    for pt in points:
                        if str(pt).strip().isdigit() or pt in defined:
                            scan_points.append(pt)
                        else:
                            skipped.append(pt)
                else:
                    scan_points = list(points)
            else:
                scan_points = list(points)

            print(f"  Sweep {i}/{total} — {node}/{dev}", flush=True)

            if not scan_points:
                # All requested points are undefined for this app; log and
                # record a synthetic miss so the user sees why.
                sweep_results.append(
                    {
                        "_node": node,
                        "_device": dev,
                        "_description": desc,
                        "error": "no requested points defined in app "
                        f"{app}",
                    }
                )
                continue

            try:
                dev_results = p2.scan_device(
                    host,
                    dev,
                    scan_points,
                    False,  # quick
                    "none",  # suppress per-device banners; use our log
                    False,  # force_slot
                )
            except p2.ScannerInputError:
                # Bad input (invalid slot etc.) — propagate so the UI can
                # show a friendly error and stop the whole sweep.
                raise
            except Exception as e:
                sweep_results.append(
                    {
                        "_node": node,
                        "_device": dev,
                        "_description": desc,
                        "error": str(e),
                    }
                )
                continue

            if dev_results:
                for r in dev_results:
                    # Skip the APPLICATION read that scan_device always does —
                    # the user didn't ask for it in a sweep context.
                    if r.get("point_name") == "APPLICATION" and "APPLICATION" not in points:
                        continue
                    r["_node"] = node
                    r["_device"] = dev
                    r["_description"] = desc
                    sweep_results.append(r)
            else:
                sweep_results.append(
                    {
                        "_node": node,
                        "_device": dev,
                        "_description": desc,
                        "error": "no data",
                    }
                )

        print(f"  Sweep complete: {total} device(s) visited, "
              f"{len(sweep_results)} result row(s)", flush=True)
        return sweep_results

    def _on_sweep_done(self, task_id: tuple, results: List[Dict]) -> None:
        if not results:
            self.log.log("Sweep returned no rows.", level="warn")
            return

        points = list(task_id[1])

        # Archive the sweep first. Figure out how many distinct devices
        # were touched by counting (node, device) pairs in the results.
        unique_devices = {
            (r.get("_node") or r.get("node"), r.get("_device") or r.get("device"))
            for r in results
        }
        self.scan_history.add_sweep(
            points=points,
            target_count=len(unique_devices),
            results=results,
        )

        SweepResultsWindow(
            self.root,
            points=points,
            results=results,
            on_jump_to_device=self._jump_to_device,
            on_resweep=self._menu_sweep,
            on_export_csv=self._export_sweep_csv,
            on_export_json=self._export_sweep_json,
        )

    def _jump_to_device(self, node_name: str, device_name: str) -> None:
        """Select a device in the main NodeTree (called when user double-
        clicks a sweep result row)."""
        # Bring main window to front
        self.root.lift()
        self.root.focus_force()

        # Use the tree's internal lookup — walk children of the node iid
        node_iid = self.tree._node_iid_by_name.get(node_name)  # noqa: SLF001
        if not node_iid:
            self.log.log(f"Node {node_name} not in tree", level="warn")
            return
        for child in self.tree._tree.get_children(node_iid):  # noqa: SLF001
            entry = self.tree._data.get(child)  # noqa: SLF001
            if entry and entry[0] == "device" and entry[1]["device"] == device_name:
                self.tree._tree.selection_set(child)  # noqa: SLF001
                self.tree._tree.focus(child)  # noqa: SLF001
                self.tree._tree.see(child)  # noqa: SLF001
                return
        self.log.log(
            f"Device {device_name} not in tree under {node_name}",
            level="warn",
        )

    def _export_sweep_csv(
        self, results: List[Dict], points: List[str]
    ) -> None:
        from tkinter import filedialog  # local to keep toolbar callbacks light
        import csv as _csv_mod
        default = f"sweep_{'_'.join(p.replace(' ', '') for p in points)[:40]}.csv"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export sweep results (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=default,
        )
        if not path:
            return
        cols = [
            "node", "device", "description", "point_slot", "point_name",
            "value", "value_text", "units", "point_type", "comm_status",
            "error",
        ]
        try:
            with open(path, "w", newline="") as f:
                w = _csv_mod.writer(f)
                w.writerow(cols)
                for r in results:
                    w.writerow(
                        [
                            r.get("_node", r.get("node", "")),
                            r.get("_device", r.get("device", "")),
                            r.get("_description", r.get("description", "")),
                            r.get("point_slot", "") if r.get("point_slot") is not None else "",
                            r.get("point_name", ""),
                            r.get("value", "") if r.get("value") is not None else "",
                            r.get("value_text", "") or "",
                            r.get("units", "") or "",
                            r.get("point_type", "") or "",
                            r.get("comm_status", "") or "",
                            r.get("error", "") or "",
                        ]
                    )
            self.log.log(f"Exported {len(results)} sweep rows → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    def _export_sweep_json(
        self, results: List[Dict], points: List[str]
    ) -> None:
        from tkinter import filedialog
        default = f"sweep_{'_'.join(p.replace(' ', '') for p in points)[:40]}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export sweep results (JSON)",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(
                    {"points": points, "results": results},
                    f,
                    indent=2,
                    default=str,
                )
            self.log.log(f"Exported {len(results)} sweep rows → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    def _menu_user_guide(self) -> None:
        # Track an instance so repeated clicks raise the existing window
        # instead of stacking duplicates.
        existing = getattr(self, "_help_window", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.lift()
                    existing.focus_set()
                    return
            except tk.TclError:
                pass
        self._help_window = HelpWindow(self.root)

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    def _menu_scan_history(self) -> None:
        """Open (or raise) the session scan-history browser."""
        existing = getattr(self, "_history_window", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.refresh()
                    existing.lift()
                    existing.focus_set()
                    return
            except tk.TclError:
                pass
        self._history_window = HistoryWindow(
            self.root,
            history=self.scan_history,
            on_open_entry=self._open_history_entry,
            on_compare_entries=self._compare_history_entries,
        )

    def _open_history_entry(self, entry: Dict) -> None:
        """User double-clicked or hit Open on a history entry."""
        if entry["kind"] == "device":
            # Restore into the detail panel: find the device in the tree,
            # select it, and inject the historical results into the table.
            self._jump_to_device(entry["node"], entry["device"])
            # _jump_to_device sets _current_device via the selection event;
            # once that's done, load the historical results instead of the
            # latest cached. We schedule via after(0) so selection events
            # fire first.
            def restore() -> None:
                self.point_table.load(entry["results"])
                self._csv_btn.configure(state="normal")
                self._json_btn.configure(state="normal")
                self.log.log(
                    f"Loaded historical {entry.get('scan_type', 'scan')} "
                    f"of {entry['device']} from "
                    f"{self._format_ts(entry['timestamp'])}",
                    level="info",
                )
            self.root.after(50, restore)
        elif entry["kind"] == "sweep":
            # Reopen the sweep results window with the historical results
            SweepResultsWindow(
                self.root,
                points=list(entry["points"]),
                results=list(entry["results"]),
                on_jump_to_device=self._jump_to_device,
                on_resweep=self._menu_sweep,
                on_export_csv=self._export_sweep_csv,
                on_export_json=self._export_sweep_json,
            )
            self.log.log(
                f"Reopened sweep from {self._format_ts(entry['timestamp'])}: "
                f"{', '.join(entry['points'])}",
                level="info",
            )
        elif entry["kind"] == "walk":
            # Reopen a historical walk in a fresh WalkPointsWindow
            WalkPointsWindow(
                self.root,
                node_name=entry["node"],
                entries=list(entry["entries"]),
                on_export_csv=self._export_walk_csv,
                on_export_json=self._export_walk_json,
            )
            self.log.log(
                f"Reopened walk of {entry['node']} from "
                f"{self._format_ts(entry['timestamp'])}",
                level="info",
            )

    def _compare_history_entries(
        self, before: Dict, after: Dict
    ) -> None:
        """User selected two entries and clicked Compare."""
        CompareWindow(self.root, before, after)
        self.log.log(
            f"Comparing {self._format_ts(before['timestamp'])} → "
            f"{self._format_ts(after['timestamp'])}",
            level="info",
        )

    @staticmethod
    def _format_ts(ts: float) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")

    def _menu_about(self) -> None:
        messagebox.showinfo(
            "About",
            "P2 Scanner GUI\n\n"
            "Desktop front-end for the Siemens P2 protocol scanner.\n"
            "Wraps the p2_scanner library for interactive use against\n"
            "Siemens PXC controllers.\n\n"
            "Read-only — never writes to controllers.",
            parent=self.root,
        )

    def _toggle_debug(self) -> None:
        p2.DEBUG_READS = bool(self.debug_var.get())
        self.log.log(
            f"Debug reads {'ON' if p2.DEBUG_READS else 'OFF'}",
            level="info",
        )

    # ------------------------------------------------------------------
    # Tree selection callbacks
    # ------------------------------------------------------------------

    def _on_select_node(self, payload: Dict) -> None:
        self._current_node = payload
        self._current_device = None
        # Surface the panel's reachability state in the header. payload
        # may not include status if the node was just added — default
        # to unknown/gray. The status flips to online/offline whenever a
        # node-level operation completes (or fails), via
        # NodeTree.set_node_status, but the payload dict the tree
        # selection callback hands us reflects whatever was there at
        # selection time. Pull the latest from the tree directly.
        latest = self.tree.node_payload(payload["name"]) or payload
        node_status = latest.get("status", "unknown")
        status_color = {
            "online": "#0a7a0a",
            "offline": "#a82020",
        }.get(node_status, "")
        if node_status == "online":
            header = f"Node: {payload['name']}   (online)"
        elif node_status == "offline":
            header = f"Node: {payload['name']}   (offline)"
        else:
            header = f"Node: {payload['name']}"
        self.detail_header.configure(text=header, foreground=status_color)
        self.detail_subhead.configure(text=f"{payload['ip']}   ·   TCP/5033")

        fw = self._firmware_cache.get(payload["name"])
        if fw:
            sub = (
                f"{payload['ip']}   ·   "
                f"model={fw.get('model', '?')}   "
                f"firmware={fw.get('firmware', '?')}"
            )
            if fw.get("extra"):
                sub += f"   ·   {fw['extra']}"
            self.detail_subhead.configure(text=sub)

        self._scan_all_btn.configure(state="disabled")
        self._quick_btn.configure(state="disabled")
        self._single_btn.configure(state="disabled")
        self._csv_btn.configure(state="disabled")
        self._json_btn.configure(state="disabled")
        self.point_table.clear()

    def _on_select_device(self, payload: Dict) -> None:
        self._current_device = payload
        self._current_node = None

        app_str = f"app {payload.get('application')}" if payload.get("application") else "app unknown"
        if payload.get("application_cached"):
            # APPLICATION came from the panel cache for a comm-faulted
            # device — flag it so the user knows it's not live.
            app_str += " (cached)"
        status = payload.get("status", "unknown")
        comm = payload.get("comm_status")
        extras = []
        if payload.get("room_temp") is not None:
            extras.append(
                f"ROOM TEMP {payload['room_temp']:.1f}{payload.get('units', '') or ''}"
            )
        elif comm == "comm_fault" and payload.get("stale_temp") is not None:
            # FLN-faulted: surface the cached value the panel is still
            # serving, but mark it as stale so it isn't mistaken for live.
            extras.append(
                f"ROOM TEMP {payload['stale_temp']:.1f}"
                f"{payload.get('units', '') or ''} (cached, #COM)"
            )
        if payload.get("description"):
            extras.append(payload["description"])
        extra_str = "   ·   ".join(extras)
        # Color: green for online, red for offline. For online-but-#COM
        # (which shouldn't happen with the corrected scanner, but might
        # arise from race conditions), fall back to amber.
        if status == "online":
            status_color = "#a06010" if comm == "comm_fault" else "#0a7a0a"
        elif status == "offline":
            status_color = "#a82020"
        else:
            status_color = "#666666"
        # Header label: append #COM tag for comm-faulted devices
        if comm == "comm_fault":
            header_label = f"Device: {payload['device']}   ({status} · #COM)"
        else:
            header_label = f"Device: {payload['device']}   ({status})"
        self.detail_header.configure(
            text=header_label,
            foreground=status_color,
        )
        self.detail_subhead.configure(
            text=(
                f"node={payload['node']}   ·   {payload['host']}   ·   "
                f"{app_str}" + (f"   ·   {extra_str}" if extra_str else "")
            )
        )

        self._scan_all_btn.configure(state="normal")
        self._quick_btn.configure(state="normal")
        self._single_btn.configure(state="normal")

        # Show cached results if any
        cache_key = (payload["node"], payload["device"])
        cached = self._device_cache.get(cache_key)
        if cached:
            self.point_table.load(cached)
            self._csv_btn.configure(state="normal")
            self._json_btn.configure(state="normal")
        else:
            self.point_table.clear()
            self._csv_btn.configure(state="disabled")
            self._json_btn.configure(state="disabled")

    def _clear_detail_panel(self) -> None:
        self._current_device = None
        self._current_node = None
        self.detail_header.configure(text="Select a node or device", foreground="")
        self.detail_subhead.configure(text="")
        self.point_table.clear()
        for btn in (
            self._scan_all_btn,
            self._quick_btn,
            self._single_btn,
            self._csv_btn,
            self._json_btn,
        ):
            btn.configure(state="disabled")

    # ------------------------------------------------------------------
    # Node-level operations
    # ------------------------------------------------------------------

    def _require_node(self) -> Optional[Dict]:
        node = self.tree.selected_node_payload()
        if not node:
            messagebox.showinfo(
                "No node selected", "Select a node first.", parent=self.root
            )
            return None
        if not p2.P2_NETWORK:
            messagebox.showwarning(
                "No network name",
                "Set the BLN network name first (File → Edit Site Config).",
                parent=self.root,
            )
            return None
        return node

    def _enumerate_node(self) -> None:
        node = self._require_node()
        if not node or not self._check_busy():
            return
        self.log.log(f"Enumerating FLN devices on {node['name']} ({node['ip']}) "
                     f"as scanner={self._effective_scanner_identity()!r}…")
        self._set_busy(f"Enumerating {node['name']}…")
        self.runner.submit(
            ("enumerate", node["name"]),
            p2.enumerate_fln_devices,
            node["ip"],
            node["name"],
        )

    def _verify_node(self) -> None:
        node = self._require_node()
        if not node or not self._check_busy():
            return
        devices = self._node_devices.get(node["name"])
        if not devices:
            # No FLN devices to verify — but the user still wants to
            # know whether the PXC itself is reachable. Run a firmware
            # query as the lightest available "is this panel up?" probe;
            # the result handler flips the node row to online or
            # offline. This is especially useful for nodes that only
            # host PPCL programs / global points and never had devices,
            # where the device-level Verify would simply do nothing.
            self.log.log(
                f"No enumerated devices for {node['name']} — "
                f"probing PXC reachability instead…"
            )
            self._set_busy(f"Probing {node['name']}…")
            self.runner.submit(
                ("firmware", node["name"]),
                self._do_firmware_query,
                node["ip"],
                node["name"],
            )
            return
        self.log.log(
            f"Verifying {len(devices)} devices on {node['name']} "
            f"as scanner={self._effective_scanner_identity()!r}…"
        )
        self._set_busy(f"Verifying {node['name']}…")
        # Live verify: our own worker opens one PXC connection and pushes a
        # progress update to progress_queue after each device so the tree
        # can flip green/red in real time. Without this the user stares at
        # a frozen UI for multiple minutes on sites with offline devices.
        self.runner.submit(
            ("verify", node["name"]),
            self._do_verify_live,
            node["ip"],
            node["name"],
            devices,
            self.progress_queue,
        )

    @staticmethod
    def _do_verify_live(
        host: str,
        node_name: str,
        devices: List[Dict],
        progress_queue: "queue.Queue[tuple]",
    ) -> List[Dict]:
        """Worker: verify online/offline status device-by-device, pushing a
        per-device progress update to progress_queue as we go.

        Mirrors the logic of p2.verify_devices but with live progress.
        Mutates `devices` in place and also returns it."""
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        node_lower = node_name.lower()

        if not conn.connect(node_lower):
            print(f"  [ERROR] Could not connect to {host} as {node_name}")
            return devices

        total = len(devices)
        online = 0
        offline = 0

        try:
            for i, dev in enumerate(devices, start=1):
                dev_name = dev["device"]
                # Read ROOM TEMP first. The comm_status flag on the
                # response is the authoritative live/dead signal — it
                # matches Desigo's own #COM indicator on the same point.
                #   comm_status=='online'     → live FLN read → ONLINE
                #   comm_status=='comm_fault' → PXC returned stale cache
                #                               because the device is
                #                               FLN-faulted → OFFLINE
                #   None (no ROOM TEMP point) → fall through to APPLICATION
                #                               as a last-resort probe
                #
                # NOTE: an earlier version of this loop fell back to
                # APPLICATION whenever ROOM TEMP came back stale.
                # APPLICATION is panel-cached metadata (configured app
                # number), not live FLN data — it returns successfully
                # even for #COM-faulted devices, so falling back to it
                # converts true offlines into false onlines. The scanner
                # was fixed; this mirror has been brought into line.
                result = conn.read_point(dev_name, "ROOM TEMP", node_lower)

                # Default: offline until proven otherwise
                dev["status"] = "offline"
                room_temp_comm = result.get("comm_status") if result else None
                if room_temp_comm:
                    dev["comm_status"] = room_temp_comm

                if result and result.get("comm_status") == "online":
                    # Live ROOM TEMP read.
                    dev["status"] = "online"
                    dev["room_temp"] = result.get("value")
                    dev["units"] = result.get("units", "")
                    if dev.get("application", 0) == 0:
                        app_result = conn.read_point(
                            dev_name, "APPLICATION", node_lower
                        )
                        if app_result and app_result.get("value") is not None:
                            dev["application"] = int(app_result["value"])
                    online += 1
                elif result and result.get("comm_status") == "comm_fault":
                    # PXC explicitly reports the device as FLN-faulted.
                    # Record the stale value (useful for diagnostics) but
                    # do NOT mark online. APPLICATION would lie here.
                    dev["stale_temp"] = result.get("value")
                    if "units" not in dev:
                        dev["units"] = result.get("units", "")
                    # Best-effort: still surface APPLICATION from the
                    # panel cache so the GUI can show "app 2090" beside
                    # the offline indicator (matching what Desigo does).
                    if dev.get("application", 0) == 0:
                        app_result = conn.read_point(
                            dev_name, "APPLICATION", node_lower
                        )
                        if app_result and app_result.get("value") is not None:
                            dev["application"] = int(app_result["value"])
                            dev["application_cached"] = True
                    offline += 1
                else:
                    # No ROOM TEMP response at all (point doesn't exist on
                    # this device, parse failed, or panel returned an
                    # error). Fall back to APPLICATION — for devices
                    # without a ROOM TEMP point this is the only way to
                    # confirm they exist. Trust comm_status here too:
                    # if APPLICATION itself comes back stale, the device
                    # is offline.
                    app_result = conn.read_point(
                        dev_name, "APPLICATION", node_lower
                    )
                    if app_result and app_result.get("value") is not None:
                        if app_result.get("comm_status") == "comm_fault":
                            dev["comm_status"] = "comm_fault"
                            if dev.get("application", 0) == 0:
                                dev["application"] = int(app_result["value"])
                                dev["application_cached"] = True
                            offline += 1
                        else:
                            dev["status"] = "online"
                            if dev.get("application", 0) == 0:
                                dev["application"] = int(app_result["value"])
                            online += 1
                    else:
                        offline += 1

                # Push progress so the UI thread can update the tree row.
                # We copy the dev dict so subsequent in-place changes by this
                # loop can't race the UI's reading of the update.
                try:
                    progress_queue.put_nowait(
                        ("verify_progress", node_name, i, total, dict(dev))
                    )
                except Exception:
                    pass  # best-effort; a full queue shouldn't kill the verify

                # Also log progress to stdout (captured in the log pane)
                print(
                    f"  Verify {i}/{total} — {dev_name:<18s} → "
                    f"{dev['status']}",
                    flush=True,
                )
        finally:
            conn.close()

        print(
            f"  Verify complete: {online} online, {offline} offline, {total} total"
        )
        return devices

    def _query_firmware(self) -> None:
        node = self._require_node()
        if not node or not self._check_busy():
            return
        self.log.log(f"Querying firmware on {node['name']} "
                     f"as scanner={self._effective_scanner_identity()!r}…")
        self._set_busy(f"Firmware query: {node['name']}…")
        # Try the newer 0x010C compact sysinfo first — returns more fields
        # on PME1300-era firmware — and silently fall back to legacy 0x0100
        # on older panels.
        self.runner.submit(
            ("firmware", node["name"]),
            self._do_firmware_query,
            node["ip"],
            node["name"],
        )

    @staticmethod
    def _do_firmware_query(host: str, node_name: str) -> Optional[Dict]:
        """Worker: try 0x010C first, fall back to 0x0100. Returns a dict
        shaped for _on_firmware_done regardless of which opcode worked."""
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        try:
            if not conn.connect(node_name.lower()):
                print(f"  Could not connect to {host} as {node_name}")
                return None

            # Newer panels: compact (0x010C) — returns model + firmware
            # string + build_date + raw_strings list. More informative on
            # PME1300-era firmware than legacy 0x0100.
            compact = conn.read_system_info_compact(node_name.lower())
            if compact:
                result = {
                    "model": compact.get("model", ""),
                    "firmware": compact.get("firmware", ""),
                    "build": compact.get("build_date", ""),
                    "extra": "",
                    "_source": "compact (0x010C)",
                }
                # Stick the full raw string list into 'extra' so the user
                # sees everything the panel sent back, formatted compactly
                rs = compact.get("raw_strings") or []
                if rs and len(rs) > 3:
                    result["extra"] = " | ".join(rs[3:7])[:80]
                print(
                    f"  Compact sysinfo: model={result['model']}  "
                    f"firmware={result['firmware']}  "
                    f"build={result['build']}"
                )
                return result
            # Older panels: legacy sysinfo (0x0100)
            print("  Compact sysinfo not supported; falling back to legacy 0x0100…")
        finally:
            conn.close()

        # Legacy path: use the existing helper (opens its own connection)
        legacy = p2.get_node_info(host, node_name)
        if legacy:
            legacy = dict(legacy)  # defensive copy
            legacy["_source"] = "legacy (0x0100)"
        return legacy

    def _walk_all_points(self) -> None:
        """Walk every point on the panel via 0x0981 cursor pagination.
        Can take 10-30 seconds on a busy panel."""
        node = self._require_node()
        if not node or not self._check_busy():
            return
        if not messagebox.askyesno(
            "Walk all points?",
            f"This enumerates every point on {node['name']} — including "
            "PPCL variables, schedule points, and global analogs.\n\n"
            "It can take 10–30 seconds on a busy panel. Continue?",
            parent=self.root,
        ):
            return
        self.log.log(f"Walking all points on {node['name']} "
                     f"as scanner={self._effective_scanner_identity()!r}…")
        self._set_busy(f"Walk points: {node['name']}…")
        self.runner.submit(
            ("walk_points", node["name"]),
            self._do_walk_points,
            node["ip"],
            node["name"],
        )

    @staticmethod
    def _do_walk_points(host: str, node_name: str) -> List[Dict]:
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        try:
            if not conn.connect(node_name.lower()):
                print(f"  Could not connect to {host} as {node_name}")
                return []
            print(f"  Enumerating all points on {node_name}…")
            entries = conn.enumerate_all_points(node_name.lower())
            print(f"  Walk complete: {len(entries)} entr{'ies' if len(entries) != 1 else 'y'} found")
            return entries
        finally:
            conn.close()

    def _dump_programs(self) -> None:
        """Dump PPCL source code for every program on the panel."""
        node = self._require_node()
        if not node or not self._check_busy():
            return
        if not messagebox.askyesno(
            "Dump PPCL programs?",
            f"This reads every PPCL program's source from {node['name']}.\n\n"
            "It can take 10–30 seconds on a busy panel. Continue?",
            parent=self.root,
        ):
            return
        self.log.log(f"Dumping PPCL programs on {node['name']} "
                     f"as scanner={self._effective_scanner_identity()!r}…")
        self._set_busy(f"Dump programs: {node['name']}…")
        self.runner.submit(
            ("dump_programs", node["name"]),
            self._do_dump_programs,
            node["ip"],
            node["name"],
        )

    @staticmethod
    def _do_dump_programs(host: str, node_name: str) -> List[Dict]:
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        try:
            if not conn.connect(node_name.lower()):
                print(f"  Could not connect to {host} as {node_name}")
                return []
            print(f"  Reading PPCL programs on {node_name}…")
            programs = conn.read_programs(node_name.lower())
            total_lines = sum(p.get("code", "").count("\n") for p in programs)
            print(
                f"  Dump complete: {len(programs)} program{'s' if len(programs) != 1 else ''}, "
                f"{total_lines} total lines"
            )
            return programs
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Device-level operations
    # ------------------------------------------------------------------

    def _require_device(self) -> Optional[Dict]:
        if not self._current_device:
            messagebox.showinfo(
                "No device selected",
                "Select a device in the tree first.",
                parent=self.root,
            )
            return None
        if not p2.P2_NETWORK:
            messagebox.showwarning(
                "No network name",
                "Set the BLN network name first (File → Edit Site Config).",
                parent=self.root,
            )
            return None
        return self._current_device

    def _scan_all(self) -> None:
        dev = self._require_device()
        if not dev or not self._check_busy():
            return
        self.log.log(
            f"Scanning all points on {dev['device']} via {dev['node']} "
            f"({dev['host']})…"
        )
        self._set_busy(f"Scanning {dev['device']}…")
        self.runner.submit(
            ("scan_all", dev["node"], dev["device"]),
            p2.scan_device,
            dev["host"],
            dev["device"],
            None,  # points
            False,  # quick
            "none",  # suppress scan_device's own table/json/csv print
            False,  # force_slot
        )

    def _scan_quick(self) -> None:
        dev = self._require_device()
        if not dev or not self._check_busy():
            return

        # Filter QUICK_SCAN_POINTS down to just what's actually defined in
        # this device's application. The scanner's built-in quick=True mode
        # tries all 18 names blindly — any that don't exist in the app time
        # out on the wire, so on a small app the "quick" scan ends up slower
        # than a full scan. Filtering makes it actually quick.
        app = dev.get("application") or 0
        quick_points = list(getattr(p2, "QUICK_SCAN_POINTS", []))
        if app and quick_points:
            try:
                table = p2.get_point_table(app)
                if table:
                    defined = {entry[0] for entry in table.values()}
                    filtered = [p for p in quick_points if p in defined]
                    if filtered:
                        quick_points = filtered
            except Exception:
                pass  # non-fatal — fall through with the unfiltered list

        self.log.log(
            f"Quick scan on {dev['device']} ({len(quick_points)} points)…"
        )
        self._set_busy(f"Quick-scanning {dev['device']}…")
        self.runner.submit(
            ("scan_quick", dev["node"], dev["device"]),
            p2.scan_device,
            dev["host"],
            dev["device"],
            quick_points,  # explicit list — bypass quick=True
            False,         # quick
            "none",
            False,
        )

    def _read_single(self) -> None:
        dev = self._require_device()
        if not dev or not self._check_busy():
            return
        r = SinglePointDialog.ask(
            self.root,
            device_name=dev["device"],
            application=dev.get("application") or None,
        )
        if not r:
            return
        point, force_slot = r
        self.log.log(
            f"Reading {point!r} on {dev['device']} "
            f"(force_slot={force_slot})…"
        )
        self._set_busy(f"Reading {point}…")
        self.runner.submit(
            ("scan_single", dev["node"], dev["device"]),
            p2.scan_device,
            dev["host"],
            dev["device"],
            [point],
            False,
            "none",
            force_slot,
        )

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------

    def _export_csv(self) -> None:
        results = self.point_table.results()
        if not results:
            return
        dev = self._current_device or {}
        default_name = f"{dev.get('node', 'node')}_{dev.get('device', 'device')}.csv"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=default_name,
        )
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                cols = [
                    "point_slot",
                    "point_name",
                    "value",
                    "value_text",
                    "units",
                    "point_type",
                    "data_type",
                    "comm_status",
                ]
                w = _csv.writer(f)
                w.writerow(cols)
                for r in results:
                    w.writerow([r.get(c, "") if r.get(c) is not None else "" for c in cols])
            self.log.log(f"Exported {len(results)} points → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    def _export_json(self) -> None:
        results = self.point_table.results()
        if not results:
            return
        dev = self._current_device or {}
        default_name = f"{dev.get('node', 'node')}_{dev.get('device', 'device')}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=default_name,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            self.log.log(f"Exported {len(results)} points → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    # ------------------------------------------------------------------
    # Async task plumbing
    # ------------------------------------------------------------------

    def _check_busy(self) -> bool:
        if self.runner.busy:
            messagebox.showinfo(
                "Busy",
                "Another operation is in progress. Wait for it to finish.",
                parent=self.root,
            )
            return False
        return True

    def _set_busy(self, message: str) -> None:
        self.busy_label.configure(text=f"⏳ {message}")
        # Show the Cancel button next to the busy label
        self.cancel_btn.configure(state="normal", text="Cancel")
        self.cancel_btn.pack(side="right", padx=(0, 6))
        for btn in (
            self._scan_all_btn,
            self._quick_btn,
            self._single_btn,
            self._enum_btn,
            self._verify_btn,
            self._firmware_btn,
            self._walk_btn,
            self._programs_btn,
        ):
            btn.configure(state="disabled")

    def _clear_busy(self) -> None:
        self.busy_label.configure(text="")
        self.cancel_btn.pack_forget()
        # Re-enable per current selection
        if self._current_device:
            self._scan_all_btn.configure(state="normal")
            self._quick_btn.configure(state="normal")
            self._single_btn.configure(state="normal")
            results = self.point_table.results()
            self._csv_btn.configure(state="normal" if results else "disabled")
            self._json_btn.configure(state="normal" if results else "disabled")
        for btn in (
            self._enum_btn, self._verify_btn, self._firmware_btn,
            self._walk_btn, self._programs_btn,
        ):
            btn.configure(state="normal")

    def _cancel_current(self) -> None:
        """Signal the running worker to cancel at its next checkpoint.
        Cooperative — the scanner function must poll runner.stop_event
        for this to have any effect. If the worker doesn't cooperate,
        closing the window still kills it (daemon thread + os._exit).
        """
        if not self.runner.busy:
            return
        self.runner.cancel()
        self.cancel_btn.configure(state="disabled", text="Cancelling…")
        self.busy_label.configure(text="⏳ Cancelling…")
        self.log.log(
            "Cancel requested — worker will stop at next checkpoint.",
            level="warn",
        )

    def _start_polling(self) -> None:
        self._poll()

    def _poll(self) -> None:
        """Tk event-loop tick. Drain log + progress + result queues."""
        self.log.poll()
        # Drain progress updates first — they're frequent and cheap, and
        # doing them before final results means a final "verify complete"
        # arrives after all its per-device updates have been rendered.
        while True:
            try:
                upd = self.progress_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._handle_progress(upd)
            except Exception as e:  # noqa: BLE001
                self.log.log(f"Progress handler error: {e}", level="error")
        while True:
            try:
                item = self.result_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._handle_result(item)
            except Exception as e:  # noqa: BLE001
                self.log.log(f"Result handler error: {e}", level="error")
        self.root.after(POLL_INTERVAL_MS, self._poll)

    def _handle_progress(self, upd: tuple) -> None:
        """Handle a mid-task progress update from a worker.

        Current update kinds:
            ('verify_progress', node_name, i, total, updated_device_dict)
        """
        if not upd:
            return
        kind = upd[0]
        if kind == "verify_progress":
            _, node_name, i, total, dev = upd
            # Update the tree row in place so the user sees the color flip
            self.tree.update_device_status(node_name, dev["device"], dev)
            # Also keep the busy label informative
            status_tag = dev.get("status") or "…"
            self.busy_label.configure(
                text=f"⏳ Verifying {node_name}: {i}/{total} "
                f"({dev['device']} → {status_tag})"
            )

    def _handle_result(self, item: tuple) -> None:
        task_id, status, payload, elapsed = item

        if status == "cancelled":
            self.log.log(
                f"Task {task_id!r} cancelled after {elapsed:.1f}s.",
                level="warn",
            )
            self._clear_busy()
            return

        if status == "error":
            exc, tb = payload
            # If a node-level operation failed (firmware, enumerate,
            # walk, programs, verify), the panel itself is likely not
            # reachable. Flip the node row to offline so the user can
            # see at a glance which PXC is dead. We restrict this to
            # node-scoped task kinds — a per-device scan failure
            # shouldn't repaint the whole node.
            if (
                isinstance(task_id, tuple)
                and len(task_id) >= 2
                and task_id[0] in (
                    "firmware",
                    "enumerate",
                    "verify",
                    "walk_points",
                    "dump_programs",
                )
            ):
                self.tree.set_node_status(task_id[1], "offline")
            # Surface ScannerInputError as a friendly message instead of a stack trace
            if p2 is not None and isinstance(exc, getattr(p2, "ScannerInputError", ())):
                messagebox.showwarning(
                    "Invalid input", str(exc), parent=self.root
                )
                self.log.log(f"Input rejected: {exc}", level="warn")
            else:
                self.log.log(
                    f"Task {task_id!r} failed after {elapsed:.1f}s: {exc}",
                    level="error",
                )
                # Dump traceback lines at 'error' level; keep them indented
                for line in tb.rstrip().splitlines()[-6:]:
                    self.log.log("    " + line, level="error")
            self._clear_busy()
            return

        # status == 'ok'
        kind = task_id[0] if isinstance(task_id, tuple) else task_id
        self.log.log(f"Completed in {elapsed:.1f}s", level="ok")

        try:
            if kind == "enumerate":
                self._on_enumerate_done(task_id, payload)
            elif kind == "verify":
                self._on_verify_done(task_id, payload)
            elif kind == "firmware":
                self._on_firmware_done(task_id, payload)
            elif kind in ("scan_all", "scan_quick", "scan_single"):
                self._on_scan_done(task_id, payload)
            elif kind == "port_scan":
                self._on_port_scan_done(task_id, payload)
            elif kind == "cold_auto":
                self._on_cold_discover_auto_done(task_id, payload)
            elif kind == "refresh_telnet":
                self._on_refresh_telnet_done(task_id, payload)
            elif kind == "sweep":
                self._on_sweep_done(task_id, payload)
            elif kind == "walk_points":
                self._on_walk_points_done(task_id, payload)
            elif kind == "dump_programs":
                self._on_dump_programs_done(task_id, payload)
        finally:
            self._clear_busy()

    # ------------------------------------------------------------------
    # Result handlers
    # ------------------------------------------------------------------

    def _on_enumerate_done(self, task_id: tuple, devices: List[Dict]) -> None:
        node_name = task_id[1]
        self._node_devices[node_name] = devices
        self.tree.set_node_devices(node_name, devices)
        # An enumerate that returns successfully means the panel
        # accepted our handshake and answered the 0x0986 request — the
        # node is reachable. An empty list (0 devices) is still a
        # success, just means the panel hosts no FLN devices.
        self.tree.set_node_status(node_name, "online")
        self.log.log(
            f"Found {len(devices)} device(s) on {node_name}", level="ok"
        )

    def _on_verify_done(self, task_id: tuple, devices: List[Dict]) -> None:
        node_name = task_id[1]
        self._node_devices[node_name] = devices
        self.tree.set_node_devices(node_name, devices)
        # Verify reached the panel — it's online regardless of how its
        # downstream FLN devices look.
        self.tree.set_node_status(node_name, "online")
        online = sum(1 for d in devices if d.get("status") == "online")
        offline = sum(1 for d in devices if d.get("status") == "offline")
        # #COM-faulted devices are a subset of offline. Surface the count
        # separately because it's the most common reason a row turns red:
        # the device is wired up and the panel still has cached data, but
        # FLN comms with the controller are currently broken.
        comm_fault = sum(
            1 for d in devices if d.get("comm_status") == "comm_fault"
        )
        if comm_fault:
            self.log.log(
                f"Verify done: {online} online, {offline} offline "
                f"({comm_fault} #COM), {len(devices)} total",
                level="ok",
            )
        else:
            self.log.log(
                f"Verify done: {online} online, {offline} offline, "
                f"{len(devices)} total",
                level="ok",
            )

    def _on_firmware_done(self, task_id: tuple, info: Optional[Dict]) -> None:
        node_name = task_id[1]
        if not info:
            # Firmware query is the lightest probe we have — if it
            # failed, the panel isn't reachable. Mark offline.
            self.tree.set_node_status(node_name, "offline")
            self.log.log(
                f"No firmware info returned for {node_name} "
                "(connect failed or handshake rejected — node likely offline)",
                level="warn",
            )
            return
        self._firmware_cache[node_name] = info
        # Successful firmware read → panel is up.
        self.tree.set_node_status(node_name, "online")
        # Build a clean summary line. Compact sysinfo gives us a build date;
        # legacy doesn't.
        parts = [f"model={info.get('model', '?')}"]
        if info.get("firmware"):
            parts.append(f"firmware={info['firmware']}")
        if info.get("build"):
            parts.append(f"build={info['build']}")
        if info.get("extra"):
            parts.append(f"extra={info['extra']}")
        source = info.get("_source", "")
        suffix = f"   [{source}]" if source else ""
        self.log.log(
            f"{node_name}: " + "   ".join(parts) + suffix,
            level="ok",
        )
        # If this is the currently selected node, update the subheader
        if self._current_node and self._current_node["name"] == node_name:
            self._on_select_node(self._current_node)

    def _on_walk_points_done(
        self, task_id: tuple, entries: List[Dict]
    ) -> None:
        node_name = task_id[1]
        if not entries:
            self.log.log(
                f"Walk points on {node_name} returned no entries "
                "— check handshake and PXC access",
                level="warn",
            )
            return
        # Reaching this point means the panel responded to 0x0981 and
        # streamed at least one entry — definitively online.
        self.tree.set_node_status(node_name, "online")
        self.log.log(
            f"{node_name}: {len(entries)} entr{'ies' if len(entries) != 1 else 'y'} walked",
            level="ok",
        )
        # Archive so the user can diff walks across time (useful for
        # tracking panel changes: "what came and went between yesterday
        # and today"). Symmetric with how regular scans are archived.
        self.scan_history.add_walk(node=node_name, entries=entries)
        WalkPointsWindow(
            self.root,
            node_name=node_name,
            entries=entries,
            on_export_csv=self._export_walk_csv,
            on_export_json=self._export_walk_json,
        )

    def _on_dump_programs_done(
        self, task_id: tuple, programs: List[Dict]
    ) -> None:
        node_name = task_id[1]
        if not programs:
            self.log.log(
                f"No PPCL programs returned for {node_name} "
                "(panel may not have any, or firmware doesn't support 0x0985)",
                level="warn",
            )
            return
        # Successful PPCL dump → panel responded to opcode 0x0985.
        self.tree.set_node_status(node_name, "online")
        total_lines = sum(p.get("code", "").count("\n") for p in programs)
        self.log.log(
            f"{node_name}: {len(programs)} program(s), {total_lines} lines",
            level="ok",
        )
        ProgramsWindow(
            self.root,
            node_name=node_name,
            programs=programs,
            on_export=self._export_programs,
        )

    # ------------------------------------------------------------------
    # Walk / programs exports
    # ------------------------------------------------------------------

    def _export_walk_csv(
        self, entries: List[Dict], node_name: str
    ) -> None:
        import csv as _csv_mod
        from tkinter import filedialog
        default = f"walk_{node_name}.csv"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export walk results (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                w = _csv_mod.writer(f)
                w.writerow(["device", "subkey", "point", "value", "units", "description"])
                for e in entries:
                    w.writerow([
                        e.get("device", ""),
                        e.get("subkey", "") or "",
                        e.get("point", ""),
                        "" if e.get("value") is None else e.get("value"),
                        e.get("units", "") or "",
                        e.get("description", "") or "",
                    ])
            self.log.log(f"Exported {len(entries)} entries → {path}", level="ok")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)

    def _export_walk_json(
        self, entries: List[Dict], node_name: str
    ) -> None:
        from tkinter import filedialog
        default = f"walk_{node_name}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export walk results (JSON)",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(
                    {"node": node_name, "entries": entries},
                    f, indent=2, default=str,
                )
            self.log.log(f"Exported {len(entries)} entries → {path}", level="ok")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)

    def _export_programs(
        self, programs: List[Dict], node_name: str
    ) -> None:
        """Writes either a single .json archive or a folder of .ppcl files,
        depending on what the user picks."""
        from tkinter import filedialog
        default = f"ppcl_{node_name}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export PPCL programs (JSON)",
            defaultextension=".json",
            filetypes=[("JSON archive", "*.json"), ("All files", "*.*")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(
                    {"node": node_name, "programs": programs},
                    f, indent=2, default=str,
                )
            self.log.log(
                f"Exported {len(programs)} program(s) → {path}", level="ok"
            )
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)

    def _on_scan_done(self, task_id: tuple, results: List[Dict]) -> None:
        _, node_name, device_name = task_id
        if not results:
            self.log.log(
                f"No points returned for {device_name} — "
                "check handshake, network name, or comm status",
                level="warn",
            )
            # Keep an empty result set in the table for clarity
            self.point_table.clear()
            self._device_cache.pop((node_name, device_name), None)
            self._csv_btn.configure(state="disabled")
            self._json_btn.configure(state="disabled")
            return

        kind = task_id[0]
        if kind == "scan_single":
            # Merge into any existing cached results so single-point reads
            # refresh a row in the table instead of blowing it away.
            existing = self._device_cache.get((node_name, device_name), [])
            by_name = {r.get("point_name"): r for r in existing}
            for r in results:
                by_name[r.get("point_name")] = r
            merged = list(by_name.values())
            self._device_cache[(node_name, device_name)] = merged
            self.point_table.load(merged)
        else:
            self._device_cache[(node_name, device_name)] = results
            self.point_table.load(results)

        self._csv_btn.configure(state="normal")
        self._json_btn.configure(state="normal")
        self.log.log(
            f"{device_name}: {len(results)} point(s) read", level="ok"
        )

        # Archive this scan in session history. For single-point reads we
        # record just the new results (not the merged cache) so the diff in
        # a later compare is meaningful. Application comes from the first
        # result that carries point_info (scan_device attaches app context
        # to every result via get_point_info under the hood).
        scan_type = {
            "scan_all": "full",
            "scan_quick": "quick",
            "scan_single": "single",
        }.get(kind, "full")
        # Pull application from device tree if we know it
        dev_payload = None
        for _, payload in self.tree._data.values():  # noqa: SLF001
            if isinstance(payload, dict) and payload.get("device") == device_name \
                    and payload.get("node") == node_name:
                dev_payload = payload
                break
        application = (dev_payload or {}).get("application", 0) if dev_payload else 0
        self.scan_history.add_device_scan(
            node=node_name,
            device=device_name,
            application=application,
            results=results,
            scan_type=scan_type,
        )

    def _on_port_scan_done(
        self, task_id: tuple, hosts: List[str]
    ) -> None:
        if not hosts:
            self.log.log("Port scan: no PXCs found.", level="warn")
            return
        self.log.log(f"Port scan: {len(hosts)} PXC(s) found.", level="ok")
        # Let user add discovered IPs to known_nodes
        self._offer_to_add_hosts(hosts)

    def _offer_to_add_hosts(self, hosts: List[str]) -> None:
        # Suggest sequential node names starting after the highest existing
        existing_ips = set(p2.KNOWN_NODES.values())
        new_hosts = [h for h in hosts if h not in existing_ips]
        if not new_hosts:
            messagebox.showinfo(
                "Port Scan",
                f"All {len(hosts)} discovered IPs are already in known_nodes.",
                parent=self.root,
            )
            return
        if not messagebox.askyesno(
            "Port Scan",
            f"Found {len(new_hosts)} new PXC IP(s):\n  "
            + "\n  ".join(new_hosts)
            + "\n\nAdd them to known_nodes? You'll be prompted for a name for each.",
            parent=self.root,
        ):
            return
        next_n = 1
        while any(f"NODE{next_n}" == k for k in p2.KNOWN_NODES):
            next_n += 1
        for ip in new_hosts:
            default = f"NODE{next_n}"
            name = simpledialog.askstring(
                "Add Node",
                f"Name for PXC at {ip}:",
                initialvalue=default,
                parent=self.root,
            )
            if not name:
                continue
            name = name.strip()
            p2.KNOWN_NODES[name] = ip
            self.log.log(f"Added node {name} → {ip}", level="ok")
            next_n += 1
        self._rebuild_tree_from_config()

    # ------------------------------------------------------------------
    # Port-scan helper (runs in worker thread)
    # ------------------------------------------------------------------

    @staticmethod
    def _do_port_scan(range_str: str) -> List[str]:
        ip_list = p2.parse_ip_range(range_str)
        print(f"  Port scanning {len(ip_list)} IP(s) on TCP/{p2.P2_PORT}…")
        hosts = p2.port_scan_p2(ip_list)
        print(f"  Result: {len(hosts)} PXC(s) responding.")
        for h in hosts:
            print(f"    {h}")
        return hosts

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _on_close(self) -> None:
        # 1. Signal cooperative cancel so any well-behaved scanner function
        #    can flush state / close sockets cleanly
        try:
            self.runner.shutdown(wait=False)
        except Exception:
            pass
        # 2. Destroy the Tk root (closes the window)
        try:
            self.root.destroy()
        except Exception:
            pass
        # 3. Hard-exit the process. The worker is a daemon thread so it
        #    should die when the main thread exits, but in practice some
        #    blocking syscalls (recv, port-scan connect_ex with long
        #    timeouts) can keep the process alive briefly after destroy().
        #    os._exit bypasses the Python shutdown sequence and kills
        #    everything immediately. This is what makes "close the window"
        #    actually terminate cold discoveries / sniffs mid-flight.
        os._exit(0)


def _import_from(dirpath: str):
    """Try to import p2_scanner from `dirpath`. Returns the module on success,
    None on failure. Adds (and on failure removes) the dir from sys.path."""
    scanner_file = os.path.join(dirpath, "p2_scanner.py")
    if not os.path.isfile(scanner_file):
        return None
    # Clean any stale entry so we really import from the target dir
    sys.modules.pop("p2_scanner", None)
    if dirpath in sys.path:
        sys.path.remove(dirpath)
    sys.path.insert(0, dirpath)
    try:
        import p2_scanner as _p2  # type: ignore
        return _p2
    except Exception:
        try:
            sys.path.remove(dirpath)
        except ValueError:
            pass
        return None


def _candidate_scanner_dirs() -> List[str]:
    """Directories to auto-probe for p2_scanner.py, most likely first."""
    candidates: List[str] = []

    # 1. Same directory as p2_gui.py
    candidates.append(_HERE)

    # 2. Persisted location from previous run
    try:
        if os.path.isfile(_SCANNER_PATH_CACHE):
            with open(_SCANNER_PATH_CACHE) as f:
                remembered = f.read().strip()
            if remembered:
                candidates.append(remembered)
    except OSError:
        pass

    # 3. Common sibling folder names (scanner zips tend to unpack into these)
    parent = os.path.dirname(_HERE)
    for name in (
        "p2_scanner_cli_latest_version",
        "p2_scanner_cli",
        "p2_scanner",
        "scanner",
    ):
        candidates.append(os.path.join(parent, name))

    # 4. One-level-deep children of the GUI folder (in case the zip was
    #    extracted as a subfolder inside the GUI folder)
    try:
        for entry in os.listdir(_HERE):
            full = os.path.join(_HERE, entry)
            if os.path.isdir(full):
                candidates.append(full)
    except OSError:
        pass

    # Dedupe while preserving order
    seen = set()
    unique = []
    for c in candidates:
        norm = os.path.normcase(os.path.abspath(c))
        if norm not in seen:
            seen.add(norm)
            unique.append(c)
    return unique


def _save_scanner_path(dirpath: str) -> None:
    try:
        with open(_SCANNER_PATH_CACHE, "w") as f:
            f.write(dirpath)
    except OSError:
        pass  # cache is best-effort; not a fatal problem


def _locate_and_import_p2_scanner(root: tk.Tk) -> Optional[Any]:
    """Find p2_scanner.py, import it, return the module.

    Tries automatic candidates first, then falls back to a file picker.
    Returns None if the user cancels.
    """
    first_error: Optional[str] = None

    # Automatic probe
    for d in _candidate_scanner_dirs():
        mod = _import_from(d)
        if mod is not None:
            _save_scanner_path(d)
            return mod

    # If p2_scanner.py existed in _HERE but failed to import, try to capture
    # the error for the dialog (most likely a stdlib issue, not missing file)
    scanner_here = os.path.join(_HERE, "p2_scanner.py")
    if os.path.isfile(scanner_here):
        try:
            # Fresh import attempt to get the real exception
            sys.modules.pop("p2_scanner", None)
            import p2_scanner  # noqa: F401 - just for the exception
        except Exception as e:
            first_error = f"{type(e).__name__}: {e}"

    # Interactive fallback
    while True:
        msg = (
            "Could not locate p2_scanner.py automatically."
            if first_error is None
            else (
                "p2_scanner.py was found but failed to import:\n"
                f"  {first_error}\n\n"
                "If that looks like a code error, fix it and retry. "
                "Otherwise, browse to a different copy."
            )
        )
        msg += (
            "\n\nBrowse to the folder containing p2_scanner.py?\n\n"
            "Yes = pick the folder\n"
            "No  = pick the p2_scanner.py file itself\n"
            "Cancel = quit"
        )
        choice = messagebox.askyesnocancel("Locate p2_scanner.py", msg, parent=root)
        if choice is None:
            return None

        if choice:
            picked = filedialog.askdirectory(
                title="Folder containing p2_scanner.py",
                parent=root,
                mustexist=True,
            )
            if not picked:
                continue
            scan_dir = picked
        else:
            picked = filedialog.askopenfilename(
                title="Locate p2_scanner.py",
                parent=root,
                filetypes=[("p2_scanner.py", "p2_scanner.py"), ("Python files", "*.py")],
            )
            if not picked:
                continue
            scan_dir = os.path.dirname(os.path.abspath(picked))

        mod = _import_from(scan_dir)
        if mod is not None:
            _save_scanner_path(scan_dir)
            return mod

        # Import failed. Give a useful message.
        scanner_there = os.path.join(scan_dir, "p2_scanner.py")
        if not os.path.isfile(scanner_there):
            messagebox.showerror(
                "Not found",
                f"p2_scanner.py was not found in:\n{scan_dir}",
                parent=root,
            )
        else:
            try:
                sys.modules.pop("p2_scanner", None)
                sys.path.insert(0, scan_dir)
                import p2_scanner  # noqa: F401
            except Exception as e:
                messagebox.showerror(
                    "Import failed",
                    f"Found p2_scanner.py in:\n  {scan_dir}\n\n"
                    f"but import raised:\n  {type(e).__name__}: {e}\n\n"
                    "Make sure tecpoints.json is in that folder too.",
                    parent=root,
                )
                try:
                    sys.path.remove(scan_dir)
                except ValueError:
                    pass


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Graphical front-end for the P2 Scanner"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to site config JSON (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--scanner-dir",
        default=None,
        help="Explicit path to the directory containing p2_scanner.py "
        "(overrides auto-detection)",
    )
    args = parser.parse_args()

    _enable_high_dpi()

    root = tk.Tk()
    # Hide the empty root while we locate the scanner / show any dialogs.
    # Without this an empty "tk" window briefly appears next to the picker.
    root.withdraw()

    # If the user gave --scanner-dir, try it first
    if args.scanner_dir:
        mod = _import_from(args.scanner_dir)
        if mod is None:
            messagebox.showerror(
                "Cannot start",
                f"--scanner-dir pointed to:\n  {args.scanner_dir}\n\n"
                "but p2_scanner.py could not be imported from there.",
                parent=root,
            )
            root.destroy()
            return 2
        _save_scanner_path(args.scanner_dir)
    else:
        mod = _locate_and_import_p2_scanner(root)
        if mod is None:
            root.destroy()
            return 2

    # Publish the located module at module-global scope so the rest of
    # p2_gui (MainWindow and helpers) can reach it through `p2.*`.
    global p2
    p2 = mod

    root.deiconify()
    MainWindow(root, args.config)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
