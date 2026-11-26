"""Normalise a dumped PS5 executable before it is packaged.

Two defects appear in some dumped executables: the older ``4F 15 3D 1D``
signature rather than the PS5 ``54 14 F5 EE``, and a ``.sceversion`` trailer
that starts up to 15 bytes before the header's marker. The first is rewritten;
for the second, zero bytes are inserted so the records start at the marker
again. A file that matches neither is served byte for byte.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

PROSPERO_MAGIC = bytes([0x54, 0x14, 0xF5, 0xEE])
LEGACY_MAGIC = bytes([0x4F, 0x15, 0x3D, 0x1D])

MAX_SHIFT = 0x0F
MAX_TRAILER = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SelfRepair:
    rewrite_magic: bool
    insert_at: int
    padding: int

    def new_size(self, original_size: int) -> int:
        return original_size + self.padding

    def describe(self) -> str:
        parts = []
        if self.rewrite_magic:
            parts.append("older signature rewritten to the PS5 one")
        if self.padding:
            parts.append(
                f"version records realigned (+{self.padding} bytes at {self.insert_at:#x})"
            )
        return ", ".join(parts)


def is_version_records(records: bytes) -> bool:
    at = 0
    count = 0
    while at < len(records):
        rest = records[at:]
        if len(rest) < 5 or rest[0] != 0 or rest[1] != 0:
            return False
        payload = int.from_bytes(rest[2:4], "little")
        record = payload + 4
        if payload < 18 or record > len(rest) or rest[4] != 8:
            return False
        name_length = payload - 17
        name = rest[5:5 + name_length]
        version = rest[5 + name_length:5 + name_length + 16]
        if (not name.endswith(b":") or len(version) != 16
                or any(not 0x20 <= byte <= 0x7E for byte in name)
                or version[:8] != version[8:]):
            return False
        at += record
        count += 1
    return count > 0


def plan(header: bytes, size: int,
         read: Callable[[int, int], bytes]) -> SelfRepair | None:
    """The repair the header and trailer call for, or ``None`` when none is needed."""
    if len(header) < 0x20 or size < 0x20:
        return None
    magic = header[:4]
    if magic == LEGACY_MAGIC:
        rewrite_magic = True
    elif magic == PROSPERO_MAGIC:
        rewrite_magic = False
    else:
        return None
    only_magic = SelfRepair(True, size, 0) if rewrite_magic else None
    marker = int.from_bytes(header[0x10:0x18], "little")
    if not 0x20 <= marker <= size:
        return only_magic
    start = max(marker - MAX_SHIFT, 0)
    tail_length = size - start
    if tail_length == 0 or tail_length > MAX_TRAILER:
        return only_magic
    tail = read(start, tail_length)
    if len(tail) != tail_length:
        return only_magic
    local = marker - start
    for shift in range(min(MAX_SHIFT, local) + 1):
        if is_version_records(tail[local - shift:]):
            if shift == 0 and not rewrite_magic:
                return None
            return SelfRepair(rewrite_magic, marker - shift, shift)
    return only_magic


def read_repaired(original: bytes, repair: SelfRepair) -> bytes:
    """The whole repaired file, for tests and small inputs."""
    size = len(original)
    output = bytearray()
    position = 0
    gap_end = repair.insert_at + repair.padding
    new_size = repair.new_size(size)
    while position < new_size:
        if position < repair.insert_at:
            stop = min(new_size, repair.insert_at)
            chunk = bytearray(original[position:stop])
            if repair.rewrite_magic and position < 4:
                for index in range(min(4 - position, len(chunk))):
                    chunk[index] = PROSPERO_MAGIC[position + index]
            output += chunk
            position += len(chunk)
        elif position < gap_end:
            stop = min(new_size, gap_end)
            output += bytes(stop - position)
            position = stop
        else:
            source_at = position - repair.padding
            chunk = original[source_at:source_at + (new_size - position)]
            if not chunk:
                break
            output += chunk
            position += len(chunk)
    return bytes(output)
