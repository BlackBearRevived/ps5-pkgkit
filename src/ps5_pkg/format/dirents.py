"""PFS directory entries.

A dirent is a 16-byte header (inode, kind, name length, entry size) followed by
the name and zero padding to 8 bytes. A directory is read one 64 KiB block at a
time, so an entry may not cross a block boundary: when one would, the entry
before it is stretched to the block's end and the next one starts a new block.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from .constants import BLOCK

HEADER_LEN = 16


def dirent_size(name: str) -> int:
    """A dirent's stored size: the header, the UTF-8 name, padded to 8 bytes."""
    raw = len(name.encode("utf-8")) + HEADER_LEN + 1
    return (raw + 7) // 8 * 8


def dirent_extents(names: Iterable[str]) -> list[tuple[int, int]]:
    """Each dirent's ``(offset, stored size)`` inside its directory."""
    output: list[tuple[int, int]] = []
    offset = 0
    for name in names:
        size = dirent_size(name)
        room = BLOCK - offset % BLOCK
        if offset % BLOCK != 0 and size > room:
            if output:
                at, previous = output[-1]
                output[-1] = (at, previous + room)
            offset += room
        output.append((offset, size))
        offset += size
    return output


def dirents_bytes(dirents: Sequence[tuple[str, int, int]]) -> bytes:
    """Serialize ``(name, inode, kind)`` dirents, in the order given."""
    output = bytearray()
    extents = dirent_extents(name for name, _, _ in dirents)
    for (name, inode, kind), (at, size) in zip(dirents, extents):
        if len(output) != at:
            raise ValueError(f"dirent offset mismatch at {name!r}")
        encoded = name.encode("utf-8")
        output += inode.to_bytes(4, "little")
        output += kind.to_bytes(4, "little", signed=True)
        output += len(encoded).to_bytes(4, "little")
        output += size.to_bytes(4, "little")
        output += encoded
        output += bytes(size - HEADER_LEN - len(encoded))
    return bytes(output)
