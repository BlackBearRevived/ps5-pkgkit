"""The PlayGo tables: ``playgo-chunk.dat``, ``playgo-hash-table.dat`` and ``playgo-ficm.dat``.

One chunk keeps the shape installing single-chunk packages carry: one mchunk
spanning the whole image and empty labels. The hash table is a flat-path table
of the image's files, and the file map repeats it with one chunk id per entry.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import constants as c
from .flt import HEADER_SEED, hash_path

DEFAULT_CHUNKS = 1
MAX_CHUNKS = 255


@dataclass(slots=True)
class PlayGo:
    chunk_dat: bytes
    hash_table: bytes
    ficm: bytes
    chunks: list[list[int]]
    mchunks: list[tuple[int, int]]

    def chunk_size(self, index: int) -> int:
        return sum(self.mchunks[m][1] for m in self.chunks[index])


def _put16(data: bytearray, at: int, value: int) -> None:
    data[at:at + 2] = value.to_bytes(2, "little")


def _put32(data: bytearray, at: int, value: int) -> None:
    data[at:at + 4] = value.to_bytes(4, "little")


def _put64(data: bytearray, at: int, value: int) -> None:
    data[at:at + 8] = value.to_bytes(8, "little")


def chunk_dat(content_id: str, chunks: list[list[int]],
              mchunks: list[tuple[int, int]], labels: bool) -> bytes:
    count = len(chunks)
    chunk_labels = bytearray()
    label_at = []
    for index in range(count):
        label_at.append(len(chunk_labels))
        if labels:
            chunk_labels += f"Chunk #{index}".encode() + b"\0"
    if not labels:
        chunk_labels += b"\0"
        label_at = [0 for _ in label_at]
    scenario_label = b"Scenario #0\0" if labels else b"\0"
    mchunk_list = [m for owned in chunks for m in owned]

    sizes = [
        count * 0x20,
        len(mchunk_list) * 4,
        len(chunk_labels),
        len(mchunks) * 0x10,
        0x20,
        count * 2,
        len(scenario_label),
    ]
    offsets = []
    at = 0x100
    for size in sizes:
        offsets.append(at)
        at = (at + size + 15) // 16 * 16
    total = at

    data = bytearray(total)
    data[0x00:0x04] = b"plgx"
    _put16(data, 0x04, 0x1000)
    _put16(data, 0x08, 1)
    _put16(data, 0x0A, count)
    _put16(data, 0x0E, 1)
    _put32(data, 0x10, total)
    _put16(data, 0x16, 1)
    data[0x1E] = 0x85
    _put16(data, 0x20, len(mchunks))
    data[0x24] = 0x01
    data[0x30] = 0x11
    data[0x38:0x40] = b"\xff" * 8
    data[0x40:0x40 + len(content_id)] = content_id.encode("ascii")
    for index, (offset, size) in enumerate(zip(offsets, sizes)):
        _put32(data, 0xC0 + index * 8, offset)
        _put32(data, 0xC4 + index * 8, size)

    list_at = 0
    for index, owned in enumerate(chunks):
        row = offsets[0] + index * 0x20
        data[row] = 0x80
        data[row + 2] = 0x03
        _put32(data, row + 4, len(owned))
        data[row + 8] = 0x11
        _put64(data, row + 0x10, 0xFFFFFFFFFFFFFFFF)
        _put32(data, row + 0x18, list_at)
        _put32(data, row + 0x1C, label_at[index])
        list_at += len(owned) * 4
    for index, mchunk in enumerate(mchunk_list):
        _put32(data, offsets[1] + index * 4, mchunk)
    data[offsets[2]:offsets[2] + len(chunk_labels)] = chunk_labels
    for index, (offset, size) in enumerate(mchunks):
        _put64(data, offsets[3] + index * 0x10, offset)
        _put64(data, offsets[3] + index * 0x10 + 8, size)
    scenario = offsets[4]
    data[scenario] = 0x21
    _put16(data, scenario + 0x14, 1)
    _put16(data, scenario + 0x16, count)
    for index in range(count):
        _put16(data, offsets[5] + index * 2, index)
    data[offsets[6]:offsets[6] + len(scenario_label)] = scenario_label
    return bytes(data)


def hash_table(entries: list[tuple[int, int]]) -> bytes:
    data = bytearray(0x38 + len(entries) * 8)
    _put32(data, 0x00, 1)
    _put32(data, 0x04, 0x08000000)
    _put32(data, 0x08, 0x38)
    _put32(data, 0x0C, len(entries) * 8)
    data[0x18:0x1C] = b"\x7fFLT"
    _put32(data, 0x24, len(entries))
    data[0x28:0x38] = HEADER_SEED
    for index, (path_hash, _) in enumerate(entries):
        _put64(data, 0x38 + index * 8, path_hash)
    return bytes(data)


def ficm(entries: list[tuple[int, int]]) -> bytes:
    data = bytearray(0x10 + len(entries) * 2)
    _put32(data, 0x00, 1)
    _put32(data, 0x08, 0x10)
    _put32(data, 0x0C, len(entries) * 2)
    for index, (_, chunk) in enumerate(entries):
        _put16(data, 0x10 + index * 2, chunk)
    return bytes(data)


def build(content_id: str, files: list[tuple[str, int, int]], cnt_offset: int,
          chunk_count: int = DEFAULT_CHUNKS) -> PlayGo:
    if len(content_id) != 36:
        raise ValueError("content id must be 36 characters")
    if chunk_count < 1 or chunk_count > MAX_CHUNKS:
        raise ValueError(f"PlayGo chunk count must be 1 through {MAX_CHUNKS}")
    data_end = 0
    for _, at, size in files:
        data_end = max(data_end, at + size)
    data_end = c.align_up(data_end, c.BLOCK)
    data_end = min(max(data_end, c.BLOCK), max(cnt_offset, c.BLOCK))
    units = data_end // c.BLOCK
    count = max(min(chunk_count, units), 1)

    if count == 1:
        chunks = [[0]]
        mchunks = [(0, cnt_offset)]
    else:
        mchunks = []
        at = 0
        for index in range(count):
            length = units // count + (1 if index < units % count else 0)
            mchunks.append((at * c.BLOCK, length * c.BLOCK))
            at += length
        chunks = [[index] for index in range(count)]
        if cnt_offset > data_end:
            mchunks.append((data_end, cnt_offset - data_end))
            chunks[0].append(count)
    mchunks = [(int(offset), int(size)) for offset, size in mchunks]

    entries = []
    for path, at, _ in files:
        chunk = 0
        if count != 1:
            for index, (start, length) in enumerate(mchunks[:count]):
                if at < start + length:
                    chunk = index
                    break
        entries.append((hash_path(path), chunk))
    entries.sort()
    return PlayGo(
        chunk_dat=chunk_dat(content_id, chunks, mchunks, count > 1),
        hash_table=hash_table(entries),
        ficm=ficm(entries),
        chunks=chunks,
        mchunks=mchunks,
    )
