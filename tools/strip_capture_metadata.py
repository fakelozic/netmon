"""Remove machine details (CPU model, kernel version) from pcapng headers. Packets are untouched."""
import struct, sys

SHB, IDB = 0x0A0D0D0A, 1
DROP = {SHB: {2, 3}, IDB: {12, 15}}   # shb_hardware, shb_os; if_os, if_hardware
FIXED = {SHB: 16, IDB: 8}             # bytes of the block body before its options

def keep_options(data, drop):
    out, i = b"", 0
    while i + 4 <= len(data):
        code, length = struct.unpack_from("<HH", data, i)
        size = 4 + length + (4 - length % 4) % 4
        if code not in drop:
            out += data[i:i + size]
        i += size
        if code == 0:
            break
    return out

for path in sys.argv[1:]:
    raw = open(path, "rb").read()
    assert raw[:4] == b"\x0a\x0d\x0d\x0a" and raw[8:12] == b"\x4d\x3c\x2b\x1a", path
    out, i = b"", 0
    while i < len(raw):
        kind, total = struct.unpack_from("<II", raw, i)
        body = raw[i + 8:i + total - 4]
        if kind in DROP:
            if kind == SHB:
                assert body[8:16] == b"\xff" * 8, "section length is set; not handled"
            fixed = FIXED[kind]
            body = body[:fixed] + keep_options(body[fixed:], DROP[kind])
        size = len(body) + 12
        out += struct.pack("<II", kind, size) + body + struct.pack("<I", size)
        i += total
    open(path, "wb").write(out)
    print(f"{path}: {len(raw)} -> {len(out)} bytes")
