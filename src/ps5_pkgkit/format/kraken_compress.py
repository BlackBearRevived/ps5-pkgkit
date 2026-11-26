"""Compress a planned inner image into the block layout a package stores."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
import hashlib
import sys

from . import kraken
from .crypto import sha3
from .kraken_image import UBLOCK, WINDOW

BLOCK = 0x10000


@dataclass(slots=True)
class StoredBlock:
    """The location and encoding of a stored Kraken block.

    Attributes:
        logical: Byte offset in the logical mount.
        length: Length of the uncompressed block in bytes.
        stored_at: Byte offset in the stored image.
        halves: Stored length and LZ flag for each half in order.
        delta: Delta-literal flags for the even and odd halves.
        owner_kind: Which region owns the block: file, gap, or meta.
        owner: Application file ID for a file block, otherwise None.
    """
    logical: int
    length: int
    stored_at: int
    halves: list[tuple[int, bool]]
    delta: tuple[bool, bool]
    owner_kind: str
    owner: int | None

    @property
    def stored_len(self) -> int:
        """The total stored byte length of both halves."""
        return sum(size for size, _ in self.halves)


@dataclass(slots=True)
class KrakenImage:
    """A compressed image and the metadata needed to describe it.

    Attributes:
        image: Stored image bytes padded to whole filesystem blocks.
        blocks: Block descriptions in logical mount order.
        image_len: Padded stored length in bytes.
        file_digests: Raw SHA3-256 digests in AFID order.
        file_stored_at: Stored byte offset of each file's first block, in AFID
            order.
        mount_size: Logical mount length in bytes.
        data_end: Logical end of the file payloads in bytes.
        meta_base: Logical byte offset of the metadata region.
    """
    image: bytes
    blocks: list[StoredBlock]
    image_len: int
    file_digests: list[bytes]
    file_stored_at: list[int]
    mount_size: int
    data_end: int
    meta_base: int

    @property
    def disk_blocks(self) -> int:
        """The number of filesystem blocks in the padded stored image."""
        return self.image_len // BLOCK


def plan_blocks(plan) -> tuple[list[dict], int]:
    """Split the planned mount into file, padding, and metadata blocks.

    Args:
        plan: A Plan with logical file positions and mount geometry.

    Returns:
        Block dictionaries in logical order and the byte offset at which the
        file payloads end.
    """
    todo: list[dict] = []
    end = 0
    for afid, index in enumerate(plan.afid_order):
        item = plan.files[index]
        following = (plan.files[plan.afid_order[afid + 1]].logical_offset
                     if afid + 1 < len(plan.afid_order) else None)
        span = following - item.logical_offset if following is not None else item.size
        offset = 0
        while offset < span:
            length = min(span - offset, UBLOCK)
            todo.append({
                "logical": item.logical_offset + offset,
                "len": length,
                "real": min(max(item.size - offset, 0), length),
                "owner": "file",
                "afid": afid,
                "path": item.path,
                "offset": offset,
                "keystone": item.generated and item.path == "sce_sys/keystone",
            })
            offset += length
        end = max(end, item.logical_offset + item.size)
    at = end
    while at < plan.meta_base:
        length = min(plan.meta_base - at, UBLOCK)
        todo.append({"logical": at, "len": length, "real": 0, "owner": "gap"})
        at += length
    mount = plan.ndblock * BLOCK
    at = plan.meta_base
    while at < mount:
        length = min(mount - at, UBLOCK)
        todo.append({"logical": at, "len": length, "real": 0, "owner": "meta"})
        at += length
    return todo, end


def _encode_checked(data: bytes, level: str, logical: int) -> list[kraken.Half]:
    """Encode a complete Kraken block and check its decoded bytes.

    Args:
        data: Uncompressed block, including any padding.
        level: Kraken compression preset.
        logical: Mount offset to report if the round-trip check fails.

    Returns:
        Encoded halves in their original order.

    Raises:
        ValueError: The encoded block does not decode to the input bytes.
    """
    halves = kraken.encode_block_at(data, level)
    if kraken.decode_block(halves, len(data)) != data:
        raise ValueError(f"block at {logical:#x} does not round-trip")
    return halves


def _encoded_blocks(blocks: Iterable[tuple[dict, bytes]], level: str,
                    jobs: int) -> Iterator[tuple[dict, bytes, list[kraken.Half]]]:
    """Encode blocks and yield their results in layout order.

    Args:
        blocks: Planned blocks paired with their uncompressed bytes.
        level: Kraken compression preset.
        jobs: Maximum number of workers. One runs in the calling process.

    Yields:
        Each planned block, its uncompressed bytes, and its checked halves.
    """
    if jobs == 1:
        for item, data in blocks:
            yield item, data, _encode_checked(data, level, item["logical"])
        return

    # ProcessPoolExecutor supports at most 61 workers on Windows.
    workers = min(jobs, 61) if sys.platform == "win32" else jobs
    with ProcessPoolExecutor(max_workers=workers) as pool:
        pending = deque()
        for item, data in blocks:
            future = pool.submit(_encode_checked, data, level, item["logical"])
            pending.append((item, data, future))
            if len(pending) == 2 * workers:
                first_item, first_data, first_future = pending.popleft()
                yield first_item, first_data, first_future.result()
        for item, data, future in pending:
            yield item, data, future.result()


def compress(plan, metadata: bytes, keystone: bytes, read, level: str = "balanced", *,
             jobs: int = 1) -> KrakenImage:
    """Encode and round-trip-check each planned Kraken block.

    Args:
        plan: A Plan for the compressed inner-image layout.
        metadata: Serialized inner-image metadata filling the mount above its
            base.
        keystone: Payload for the generated keystone, if the plan requests one.
        read: Callable that takes a file path, byte offset, and byte count,
            and returns the requested bytes.
        level: Kraken compression preset.
        jobs: Maximum number of workers used to encode and check blocks.

    Returns:
        Padded stored image, block descriptions, and file offsets and digests.

    Raises:
        ValueError: Metadata length is inconsistent, a file read is short, or an
            encoded block fails to round-trip.
    """
    todo, data_end = plan_blocks(plan)
    mount = plan.ndblock * BLOCK
    if len(metadata) != mount - plan.meta_base:
        raise ValueError("the metadata region does not fill the mount above its base")
    image = bytearray()
    blocks: list[StoredBlock] = []
    file_count = len(plan.afid_order)
    file_hashes: list[bytes | None] = [None] * file_count
    file_stored_at = [0] * file_count
    open_afid: int | None = None
    hasher = None
    cursor = 0

    def input_blocks() -> Iterator[tuple[dict, bytes]]:
        """Yield planned blocks with their padded bytes in mount order."""
        for item in todo:
            if item["owner"] == "file":
                real = item["real"]
                if real == 0:
                    data = b""
                elif item["keystone"]:
                    start = item["offset"]
                    data = keystone[start:start + real]
                    if len(data) != real:
                        raise ValueError("keystone is short")
                else:
                    data = read(item["path"], item["offset"], real)
                    if len(data) != real:
                        raise ValueError("a source file is short")
                data += bytes(item["len"] - len(data))
            elif item["owner"] == "meta":
                at = item["logical"] - plan.meta_base
                data = metadata[at:at + item["len"]]
            else:
                data = bytes(item["len"])
            yield item, data

    workers = min(jobs, max(1, len(todo)))
    for item, data, halves in _encoded_blocks(input_blocks(), level, workers):
        if item["owner"] == "file":
            afid = item["afid"]
            if open_afid != afid:
                if open_afid is not None:
                    file_hashes[open_afid] = hasher.digest()
                hasher = hashlib.sha3_256()
                open_afid = afid
                file_stored_at[afid] = cursor
            hasher.update(data[:item["real"]])
        stored_at = cursor
        parts: list[tuple[int, bool]] = []
        delta = [False, False]
        for position, half in enumerate(halves):
            image += half.data
            cursor += len(half.data)
            parts.append((len(half.data), half.is_lz))
            delta[position] = half.is_delta
        blocks.append(StoredBlock(item["logical"], item["len"], stored_at, parts,
                                  (delta[0], delta[1]), item["owner"],
                                  item["afid"] if item["owner"] == "file" else None))
    if open_afid is not None:
        file_hashes[open_afid] = hasher.digest()
    for afid, index in enumerate(plan.afid_order):
        if plan.files[index].size == 0:
            file_hashes[afid] = sha3(b"")
            match = next((block for block in blocks
                          if block.logical >= plan.files[index].logical_offset), None)
            file_stored_at[afid] = match.stored_at if match else cursor
    image_len = max((cursor + 0xFFFF) // 0x10000 * 0x10000, 0x10000)
    image += bytes(image_len - cursor)
    return KrakenImage(bytes(image), blocks, image_len,
                       [digest if digest is not None else sha3(b"") for digest in file_hashes],
                       file_stored_at, mount, data_end, plan.meta_base)


def _block_record(block: StoredBlock) -> int:
    """Pack a stored block's lengths and modes into a layout record."""
    value = ((block.logical % WINDOW) >> 4) & 0x3FFF
    value |= (block.halves[0][0] - 1) << 14
    value |= 1 << 31
    flags = 0
    if block.halves[0][1]:
        flags |= 1 << 1
        if block.delta[0]:
            flags |= 1
    if len(block.halves) > 1:
        if block.halves[1][1]:
            flags |= 1 << 4
            if block.delta[1]:
                flags |= 1 << 3
        else:
            flags |= 1 << 2
    value |= flags << 32
    value |= ((block.stored_at + block.stored_len) % WINDOW) << 48
    return value


def _anchor_record(position: int) -> int:
    """Pack the stored byte position of a new run into a layout anchor."""
    return ((position >> 20) & ((1 << 26) - 1)) | ((position // WINDOW) << 26) \
        | ((position % WINDOW) << 48)


def layout(image: KrakenImage, file_starts: list[int]) -> bytes:
    """Serialize the NAPS layout for a Kraken-compressed inner image.

    Args:
        image: Stored image and its logical block descriptions.
        file_starts: Logical byte offsets of files in AFID order.

    Returns:
        The serialized descriptor containing file indexes and block records.

    Raises:
        ValueError: A logical unit contains too many blocks for the index.
    """
    run_end = 1 << 66
    terminator = 2 << 66
    records: list[int] = [0]
    keys: list[int | None] = [0]
    block_index: list[tuple[int, int]] = []
    cursor = 0
    last_block: int | None = None
    for block in image.blocks:
        anchored = False
        if block.stored_at != cursor:
            if last_block is not None:
                records[last_block] |= run_end
            records.append(_anchor_record(block.stored_at))
            keys.append(block.stored_at >> 16)
            anchored = True
        if len(records) % 16 == 0 and not anchored:
            if last_block is not None:
                records[last_block] |= run_end
            records.append(_anchor_record(block.stored_at))
            keys.append(block.stored_at >> 16)
        block_index.append((block.logical, len(records)))
        last_block = len(records)
        records.append(_block_record(block))
        keys.append(block.logical)
        cursor = block.stored_at + block.stored_len
    if last_block is not None:
        records[last_block] |= run_end
    records.append((_anchor_record(cursor) & ~((1 << 26) - 1)) | terminator)
    keys.append(None)
    sentinel = len(records)
    records.append(((image.mount_size % WINDOW) >> 4) & 0x3FFF)
    keys.append(None)
    for index in range(len(records) - 1):
        if keys[index + 1] is not None:
            records[index] |= (keys[index + 1] & 0xF) << 68

    ublocks = (image.mount_size + UBLOCK - 1) // UBLOCK
    files = len(file_starts) + 3
    outer_blocks = (image.image_len + 0xFFFF) // 0x10000
    record_count = len(records)
    first: list[int] = []
    for n in range(ublocks + 1):
        target = n * UBLOCK
        found = sentinel
        for logical, index in block_index:
            if logical >= target:
                found = index
                break
        first.append(found)
    groups = ublocks // 8 + 1

    blob = bytearray()
    word0 = ((files - 1) & 0xFFFFFF) | (2 << 24) | ((ublocks & 0xFFFFFF) << 32)
    word1 = (outer_blocks & 0xFFFFFF) | (((record_count - 2) & 0xFFFFFF) << 24)
    blob += word0.to_bytes(8, "little")
    blob += word1.to_bytes(8, "little")
    blob += bytes(outer_blocks * 8)
    entries = [(start, 0) for start in file_starts]
    entries.append((image.data_end, 0))
    entries.append((image.meta_base, 0))
    entries.append((image.mount_size, 0x40))
    for offset, kind in entries:
        blob += offset.to_bytes(5, "little") + bytes([kind])
    for group in range(groups):
        def at(slot: int) -> int:
            """Return the block index or the end-of-image sentinel."""
            index = group * 8 + slot
            return first[index] if index < len(first) else sentinel
        base = at(0)
        blob += (base & 0xFFFFFF).to_bytes(3, "little")
        for slot in range(1, 8):
            delta = at(slot) - base
            if delta > 0xFF:
                raise ValueError("ublocks hold too many blocks for the descriptor")
            blob.append(delta)
    blob += bytes(-len(blob) % 8)
    blob += b"\x00\x00\x04"
    for record in records:
        blob += (record & ((1 << 72) - 1)).to_bytes(9, "little")
    blob += bytes(-len(blob) % 8)
    return bytes(blob)
