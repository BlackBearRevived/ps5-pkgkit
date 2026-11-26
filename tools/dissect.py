#!/usr/bin/env python3
"""Print the structures of a reference PS5 package for the Python writer.

    python3 tools/dissect.py PS5-PKG-Hello-World.pkg
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import struct
import sys
import zipfile

BLOCK = 0x10000


def le64(data: bytes, at: int) -> int:
    return int.from_bytes(data[at:at + 8], "little")


def le32(data: bytes, at: int) -> int:
    return int.from_bytes(data[at:at + 4], "little")


def be32(data: bytes, at: int) -> int:
    return int.from_bytes(data[at:at + 4], "big")


def main() -> int:
    path = Path(sys.argv[1])
    data = path.read_bytes()
    print(f"file {path.name}: {len(data)} bytes sha256 {hashlib.sha256(data).hexdigest()}")

    fih = data[:BLOCK]
    print("FIH")
    for label, at, size in (
        ("magic", 0, 4), ("version", 6, 1), ("pfs_offset", 0x10, 8),
        ("outer_size", 0x18, 8), ("superblock_abs", 0x20, 8),
        ("meta_blocks", 0x50, 4), ("cnt_offset", 0x58, 8),
        ("inner_blocks", 0x90, 4), ("content_inodes", 0x94, 4),
        ("content_version", 0x9C, 4), ("inner_size", 0xA0, 8),
        ("naps_len", 0xA8, 8), ("app_files", 0xF0, 4), ("flt_count", 0xF8, 4),
    ):
        raw = fih[at:at + size]
        value = int.from_bytes(raw, "little")
        print(f"  {label:16} {value:#x} ({value})")

    sb_at = le64(fih, 0x20)
    sb = data[sb_at:sb_at + BLOCK]
    print(f"outer superblock at {sb_at:#x}")
    print(f"  magic {le64(sb, 0x08):#x} dinodes {le64(sb, 0x30)}"
          f" ndblock {le64(sb, 0x38)} flags {int.from_bytes(sb[0x1C:0x1E], 'little'):#x}")
    print(f"  table block {le64(sb, 0xD8)} seed {sb[0x370:0x380]!r}")

    table = data[sb_at + BLOCK:sb_at + 2 * BLOCK]
    print("dinodes")
    for index in range(5):
        at = index * 0x2C8
        d = table[at:at + 0x2C8]
        mode = int.from_bytes(d[0:2], "little")
        nlink = int.from_bytes(d[2:4], "little")
        flags = le32(d, 4)
        size = le64(d, 8)
        stored = le64(d, 0x10)
        blocks = le32(d, 0x60)
        direct = [le32(d, 0x64 + slot * 36 + 32) for slot in range(12)]
        indirect = le32(d, 0x214 + 32)
        print(f"  ino {index}: mode {mode:#o} nlink {nlink} flags {flags:#x}"
              f" size {size:#x} stored {stored:#x} blocks {blocks}")
        print(f"    direct {direct} indirect {indirect:#x}")

    cnt_at = le64(fih, 0x58)
    cnt = data[cnt_at:]
    print(f"CNT at {cnt_at:#x}")
    print(f"  magic {cnt[:4]!r} count {be32(cnt, 0x10)} table {be32(cnt, 0x18):#x}"
          f" body {struct.unpack_from('>QQ', cnt, 0x20)} padded {be32(cnt, 0x7C):#x}")
    content_id = cnt[0x40:0x64].rstrip(b"\x00").decode("ascii", "replace")
    print(f"  content id {content_id!r}")
    print(f"  drm {be32(cnt, 0x70):#x} type {be32(cnt, 0x74):#x} flags {be32(cnt, 0x78):#x}")
    print(f"  seed {cnt[0x4A0:0x4B0]!r} cnt_offset {le64(cnt, 0x4B0):#x}")

    entries_at = cnt_at + be32(cnt, 0x18)
    count = be32(cnt, 0x10)
    print("  entries")
    for index in range(count):
        row = data[entries_at + index * 32: entries_at + index * 32 + 32]
        entry_id, name_at, flags1, flags2, offset, size = struct.unpack(">6I8x", row)
        print(f"    {entry_id:#06x} name {name_at:#x} flags {flags1:#x}/{flags2:#x}"
              f" off {offset:#x} size {size:#x}")

    si_at = cnt_at + be32(cnt, 0x7C)
    print(f"SI at {si_at:#x} size {len(data) - si_at}")
    with zipfile.ZipFile(io.BytesIO(data[si_at:])) as archive:
        for info in archive.infolist():
            print(f"  {info.filename} {info.file_size} (stored {info.compress_size})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
