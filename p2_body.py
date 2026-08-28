"""Turn a P2 body into named fields, using the catalog in `p2_asdu.py`.

`p2_data.py` names an operation and decodes an enum. This walks the operation's
declared structure over the bytes and reports every field it contains, with its
offset, width and value. It is the piece that lets a reader do what PROTOCOL.md
10.9 says is possible for 444 of 455 operations.

    from p2_body import decode
    result = decode(0x0981, "rsp", body)
    for f in result.fields:
        print(f.path, f.type, f.offset, f.width, f.value)

Nothing here is generated: `p2_asdu.py` is the data and this is the reading of
it. The two are kept apart so regenerating the catalog cannot overwrite the
walker.

**The rules this implements, and where they come from.** Each is a place where
the obvious reading is wrong, which is why the walker is more than a loop over
field widths:

  * **A string is a TLV**, `tag | u16 BE length | bytes`, and the tag is 0 or 1
    (8.1). The length is two bytes -- one byte would refuse every string of 256
    or more, the band that carries message text and PPCL lines (8.4.3).
  * **A CHOICE selects an arm by tag, and the tag is not always the arm's
    position** (10.4.1, 10.4.3). Where the tag map is known it is used; where it
    is not, the positional reading is applied and the field is marked so the
    caller can see the difference.
  * **One type name can mean different layouts under different parents**
    (10.4.2). `real_addr_` is five different widths depending on which
    `Physical_address_*` encloses it, and 65 other names are parent-qualified.
    Resolution therefore needs the parent, and happens where the parent is known.
  * **An array's length is a preceding field**, named `nrOf...`, and there is no
    marker in the bytes -- read the count, then that many elements.
  * **A body may legitimately end early.** Running out of bytes exactly at a
    field boundary is truncation, not corruption, and is reported as such rather
    than raised.

`decode` never raises on bad input: it returns whatever it read plus an `error`,
because a partial decode of an unexpected body is more useful to a reader than
an exception, and because a malformed body is a normal thing to meet on a wire.
"""
import struct
from collections import namedtuple

try:
    import p2_asdu as A
except ImportError:                                       # pragma: no cover
    A = None

Field = namedtuple("Field", "path type offset width value note")
Result = namedtuple("Result", "struct fields consumed length error truncated")

_MAXDEPTH = 24


class _Fail(Exception):
    pass


def _resolve(t):
    """The declared type a name refers to (mirrors the catalog's own order)."""
    if t in A.ALIAS:
        return A.ALIAS[t]
    if t in A.STRUCTS or t in A.WIDTHS or t in A.TEXTLIKE:
        return t
    if t.endswith("_"):
        for cand in (t[:-1].upper() + "_type", t[:-1].capitalize()):
            if cand in A.STRUCTS:
                return cand
    return t


def _is_choice(name):
    f = A.STRUCTS.get(name)
    return bool(f) and f[0][0] == "tag_"


def _scalar(b, i, w, typ):
    raw = b[i:i + w]
    if typ == "FLOAT_" and w == 4:
        return struct.unpack(">f", raw)[0]
    if w in (1, 2, 4, 8):
        v = int.from_bytes(raw, "big")
        if typ in A.SIGNED and v >> (w * 8 - 1):
            v -= 1 << (w * 8)
        return v
    return raw


class _Walker(object):
    def __init__(self, body):
        self.b = body
        self.out = []
        self.truncated = False

    def add(self, path, typ, off, width, value, note=""):
        self.out.append(Field(path, typ, off, width, value, note))

    def read(self, i, typ, path, depth=0, parent=None):
        if depth > _MAXDEPTH:
            raise _Fail("nesting deeper than %d at %s" % (_MAXDEPTH, path))
        b = self.b
        typ = _resolve(typ)

        if typ in A.TEXTLIKE:
            if i + 3 > len(b) or b[i] > 1:
                raise _Fail("expected a string TLV at %d (%s)" % (i, path))
            n = int.from_bytes(b[i + 1:i + 3], "big")
            if i + 3 + n > len(b):
                raise _Fail("string TLV at %d runs %d past the body" %
                            (i, i + 3 + n - len(b)))
            self.add(path, typ, i, 3 + n,
                     b[i + 3:i + 3 + n].decode("latin-1", "replace"))
            return i + 3 + n

        if typ == "Point_extension2":
            # `nrOftypes` is an ENTRY COUNT, not a byte length, and each entry
            # is self-describing: tag_ 1 | size_of_extension u16 | payload.
            # An earlier version read the u16 as a byte length -- a fitted
            # guess that also forced a compensating two-byte trailer on the
            # `lao` point arm. Both are gone; see PROTOCOL.md 10.4.1.
            if i + 2 > len(b):
                raise _Fail("truncated extension count at %d (%s)" % (i, path))
            n = int.from_bytes(b[i:i + 2], "big")
            start, j = i, i + 2
            for k in range(n):
                if j + 3 > len(b):
                    raise _Fail("extension entry %d at %d is truncated" % (k, j))
                size = int.from_bytes(b[j + 1:j + 3], "big")
                if j + 3 + size > len(b):
                    raise _Fail("extension entry %d at %d runs past the body" % (k, j))
                self.add("%s.types[%d]" % (path, k), "Point_extension2_type",
                         j, 3 + size, (b[j], bytes(b[j + 3:j + 3 + size])))
                j += 3 + size
            self.add(path + ".nrOftypes", "UNSIGNED16", start, 2, n)
            return j

        if typ == "real_addr_":
            w = A.REALW.get(parent)
            if w is None:
                raise _Fail("real_addr_ needs a known parent, got %r (%s)"
                            % (parent, path))
            if i + w > len(b):
                raise _Fail("truncated real_addr_ at %d (%s)" % (i, path))
            self.add(path, "real_addr_(%s)" % parent, i, w, bytes(b[i:i + w]))
            return i + w

        w = A.WIDTHS.get(typ)
        if w is not None:
            if i + w > len(b):
                raise _Fail("truncated %s at %d (%s)" % (typ, i, path))
            if w:
                self.add(path, typ, i, w, _scalar(b, i, w, typ))
            return i + w

        if typ.endswith("[]"):
            raise _Fail("array %s with no count in scope (%s)" % (typ, path))

        if typ == "All_points":
            if i >= len(b):
                raise _Fail("truncated point tag at %d (%s)" % (i, path))
            tag = b[i]
            arm = A.POINT_TAGS.get(tag)
            i = self.read(i, "Point_base", path + ".base", depth + 1)
            arms = dict(A.STRUCTS["All_points"][1:])
            if arm is None or arm not in arms:
                raise _Fail("point type %d is not a declared arm (%s)" % (tag, path))
            i = self.read(i, arms[arm], "%s.%s" % (path, arm), depth + 1)
            if i > len(b):
                raise _Fail("point arm %s runs past the body" % arm)
            return i

        if typ == "Alarm_object":
            if i >= len(b):
                raise _Fail("truncated alarm tag at %d (%s)" % (i, path))
            w = A.ALARM.get(b[i])
            if w is None:
                raise _Fail("alarm arm %d is not declared (%s)" % (b[i], path))
            if i + 1 + w > len(b):
                raise _Fail("truncated alarm arm at %d (%s)" % (i, path))
            self.add(path, "Alarm_object[tag=%d]" % b[i], i, 1 + w,
                     bytes(b[i + 1:i + 1 + w]))
            return i + 1 + w

        if typ in A.STRUCTS:
            fields = A.STRUCTS[typ]
            if not fields:
                return i
            if _is_choice(typ):
                return self._choice(i, typ, fields, path, depth)
            return self._fields(i, typ, fields, path, depth)

        if parent:
            alt = A.NESTED.get(parent + "::" + typ)
            if alt is not None:
                return self._fields(i, typ, alt, path, depth + 1)

        raise _Fail("no definition for type %s (%s)" % (typ, path))

    def _choice(self, i, typ, fields, path, depth):
        b = self.b
        if i >= len(b):
            raise _Fail("truncated CHOICE tag at %d (%s)" % (i, path))
        tag = b[i]
        arms = fields[1:]
        known = A.CHOICE_TAGS.get(typ)
        note = ""
        if known and tag in known["map"]:
            arm = known["map"][tag]
            armtype = dict(arms).get(arm)
            if armtype is None:
                raise _Fail("tag %d names arm %s, which %s does not declare"
                            % (tag, arm, typ))
        elif known and known["complete"]:
            raise _Fail("tag %d is not an arm of %s" % (tag, typ))
        else:
            # No recovered map, or a partial one that does not cover this tag.
            # Fall back to the positional reading and SAY SO -- 10.4.1 shows it
            # is wrong for four CHOICEs, so a caller must be able to tell a
            # known selection from a guessed one.
            if tag >= len(arms):
                raise _Fail("tag %d is beyond %s's %d arms" % (tag, typ, len(arms)))
            arm, armtype = arms[tag]
            note = "arm selected positionally; tag map not recovered"
        self.add(path + ".tag_", "UNSIGNED_8", i, 1, tag, note or arm)
        return self.read(i + 1, armtype, "%s.%s" % (path, arm), depth + 1, typ)

    def _fields(self, i, typ, fields, path, depth):
        b = self.b
        count = None
        for fname, ftype in fields:
            if i == len(b):
                # the body ended exactly at a field boundary: truncation, which
                # is a normal way for a short response to end, not corruption
                self.truncated = True
                return i
            sub = "%s.%s" % (path, fname) if path else fname
            if ftype.endswith("[]"):
                if count is None:
                    raise _Fail("array %s has no preceding count (%s)" % (ftype, sub))
                for k in range(count):
                    if i >= len(b):
                        raise _Fail("array %s ended after %d of %d (%s)"
                                    % (ftype, k, count, sub))
                    i = self.read(i, ftype[:-2], "%s[%d]" % (sub, k), depth + 1, typ)
                count = None
                continue
            before = i
            i = self.read(i, ftype, sub, depth + 1, typ)
            if ftype in ("UNSIGNED_16", "UNSIGNED16") and fname.lower().startswith("nrof"):
                count = int.from_bytes(b[before:before + 2], "big")
        return i


def structure_for(opcode, direction):
    """The declared structure name for an operation, or None."""
    if A is None:
        return None
    ent = A.OPS.get(opcode)
    if not ent:
        return None
    return ent[0] if direction == "req" else ent[1]


def decode(opcode, direction, body, struct_name=None):
    """Walk `body` as the structure declared for (opcode, direction).

    `direction` is "req" for a request or push and "rsp" for a response.
    `struct_name` overrides the lookup, for a body whose operation is unknown.

    Returns a Result. `error` is None on a clean walk; `consumed` is how far the
    walk got either way, so a partial decode is still usable. `truncated` says
    the body ended at a field boundary, which is normal for a short response.
    """
    if A is None:
        return Result(None, [], 0, len(body), "p2_asdu.py is not importable", False)
    name = struct_name or structure_for(opcode, direction)
    if not name:
        return Result(None, [], 0, len(body),
                      "no structure is declared for %#06x %s" % (opcode, direction), False)
    w = _Walker(bytes(body))
    try:
        n = w.read(0, name, "", 0, None)
        # Fields the structure library does not declare that this one operation
        # nevertheless carries -- see p2_asdu.OP_TAILS and PROTOCOL.md 10.1.
        # Nine operations, 342 bodies, every one of which stops one or two bytes
        # short without them. They are appended after the declared structure and
        # named so a reader can see they are observed rather than declared.
        for fname, ftype in getattr(A, "OP_TAILS", {}).get(
                "%s:%#06x" % (direction, opcode), []):
            if n >= len(body):
                break
            n = w.read(n, ftype, fname, 0, name)
    except _Fail as e:
        n = w.out[-1].offset + w.out[-1].width if w.out else 0
        return Result(name, w.out, n, len(body), str(e), w.truncated)
    err = None
    if n < len(body):
        err = "%d trailing bytes the structure does not account for" % (len(body) - n)
    return Result(name, w.out, n, len(body), err, w.truncated)
