"""Wrap the stored inner image and its descriptor in the outer PFS image.

The stored inner image comes first, followed by its descriptor, the superblock,
inode table, root directory, flat-path table, indirect tables, and uroot
directory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import constants as c
from .crypto import sha3, SIGNED_SECTOR_FLAG
from .dirents import dirents_bytes
from .flt import hash_path, pack_inode_entry, write as write_table
from .constants import DIRENT_DOT, DIRENT_DOTDOT, DIRENT_FILE, DIRENT_DIR

DINODE_LEN = 0x2C8
DINODES = 5
DIRECT_SLOTS = 12
INDIRECT_SLOTS = 5
PER_INDIRECT = c.BLOCK // 36


def max_inner_blocks() -> int:
    """Return the largest inner image addressable by an outer inode."""
    cover = DIRECT_SLOTS
    for level in range(INDIRECT_SLOTS):
        cover += PER_INDIRECT ** (level + 1)
    return min(cover, 0xFFFFFFFF)


@dataclass(slots=True)
class IndirectTable:
    """One outer-image indirect pointer block.

    Attributes:
        block: Physical outer-image block number of the table.
        children: Child table block numbers, or None for a leaf table.
        first_data: First payload block index covered by this table.
        naps: Whether this table points into the layout descriptor.
    """
    block: int
    children: list[int] | None
    first_data: int
    naps: bool


@dataclass(slots=True)
class IndirectLayout:
    """The indirect table tree for one outer-image file.

    Attributes:
        tables: Pointer tables in child-before-parent write order.
        slots: Root table block numbers to place in the inode.
    """
    tables: list[IndirectTable] = field(default_factory=list)
    slots: list[int] = field(default_factory=list)


def _build_table(level: int, first_data: int, data: int, next_block: list[int],
                 output: list[IndirectTable], naps: bool) -> int:
    """Allocate one subtree of indirect pointer tables.

    Args:
        level: Tree depth, where zero creates a leaf table.
        first_data: First payload block index covered by the subtree.
        data: Number of payload blocks covered.
        next_block: One-element list with the next free block number, updated in
            place.
        output: Table list extended in child-before-parent order.
        naps: Whether the payload is the inner-image layout descriptor.

    Returns:
        Physical block number of the new subtree root.
    """
    if level == 0:
        block = next_block[0]
        next_block[0] += 1
        output.append(IndirectTable(block, None, first_data, naps))
        return block
    per_child = PER_INDIRECT ** level
    children = []
    at = first_data
    while at < first_data + data:
        take = min(per_child, first_data + data - at)
        children.append(_build_table(level - 1, at, take, next_block, output, naps))
        at += take
    block = next_block[0]
    next_block[0] += 1
    output.append(IndirectTable(block, children, first_data, naps))
    return block


def _cover(blocks: int, first_table: int, naps: bool) -> IndirectLayout:
    """Plan indirect tables for blocks beyond the direct inode slots.

    Args:
        blocks: Total payload block count, including direct blocks.
        first_table: Physical block number available for the first table.
        naps: Whether this layout describes the layout descriptor.

    Returns:
        Allocated tables and inode slot pointers.

    Raises:
        ValueError: The file exceeds the available indirect levels.
    """
    next_block = [first_table]
    output: list[IndirectTable] = []
    slots: list[int] = []
    remaining = max(blocks - DIRECT_SLOTS, 0)
    first_data = DIRECT_SLOTS
    level = 0
    while remaining > 0:
        if len(slots) >= INDIRECT_SLOTS:
            raise ValueError("this many blocks needs more indirect levels than a dinode has")
        span = PER_INDIRECT ** (level + 1)
        take = min(span, remaining)
        slots.append(_build_table(level, first_data, take, next_block, output, naps))
        first_data += take
        remaining -= take
        level += 1
    return IndirectLayout(output, slots)


def indirect_layout(inner_blocks: int, first_table: int) -> IndirectLayout:
    """Plan the inner-image file's indirect block tables.

    Args:
        inner_blocks: Number of blocks occupied by the stored inner image.
        first_table: First available outer-image block number for indirect
            tables.

    Returns:
        The allocated tables and the inode's indirect slot pointers.

    Raises:
        ValueError: The inner image requires more levels than the inode
            supports.
    """
    return _cover(inner_blocks, first_table, False)


def naps_indirect_layout(naps_blocks: int, first_table: int) -> IndirectLayout:
    """Plan the layout descriptor's indirect block tables.

    Args:
        naps_blocks: Number of blocks occupied by the descriptor.
        first_table: First available outer-image block number for indirect
            tables.

    Returns:
        Indirect layout, empty if the descriptor fits in direct slots.

    Raises:
        ValueError: The descriptor requires more levels than the inode supports.
    """
    if naps_blocks <= DIRECT_SLOTS:
        return IndirectLayout()
    return _cover(naps_blocks, first_table, True)


@dataclass(slots=True)
class Layout:
    """Block positions for each region of the outer PFS image.

    Attributes:
        naps_block: First block of the inner-image layout descriptor.
        naps_blocks: Number of blocks reserved for the descriptor.
        superblock_block: Block containing the superblock.
        table_block: Block containing the inode table.
        root_block: Block containing the root directory entries.
        flt_block: Block containing the flat-path table.
        uroot_block: Block containing the uroot directory entries.
        indirect: Indirect pointer tables for the stored inner image.
        naps_indirect: Indirect pointer tables for the layout descriptor.
        ndblock: Total number of outer-image blocks.
    """
    naps_block: int
    naps_blocks: int
    superblock_block: int
    table_block: int
    root_block: int
    flt_block: int
    uroot_block: int
    indirect: IndirectLayout
    naps_indirect: IndirectLayout
    ndblock: int


def layout(inner_blocks: int, naps_len: int) -> Layout:
    """Compute the outer image block layout.

    Args:
        inner_blocks: Stored inner-image block count.
        naps_len: Length of the layout descriptor in bytes.

    Returns:
        Block positions, indirect tables, and total outer-image block count.

    Raises:
        ValueError: The inner image is empty or too large, or an indirect layout
            exceeds the inode's capacity.
    """
    if inner_blocks == 0 or inner_blocks > max_inner_blocks():
        raise ValueError("inner image is past what a dinode can describe")
    naps_blocks = max((naps_len + c.BLOCK - 1) // c.BLOCK, 1)
    after_naps = inner_blocks + naps_blocks
    indirect = indirect_layout(inner_blocks, after_naps + 4)
    naps_indirect = naps_indirect_layout(
        naps_blocks, after_naps + 4 + len(indirect.tables))
    uroot_block = after_naps + 4 + len(indirect.tables) + len(naps_indirect.tables)
    return Layout(
        naps_block=inner_blocks,
        naps_blocks=naps_blocks,
        superblock_block=after_naps,
        table_block=after_naps + 1,
        root_block=after_naps + 2,
        flt_block=after_naps + 3,
        uroot_block=uroot_block,
        indirect=indirect,
        naps_indirect=naps_indirect,
        ndblock=uroot_block + 1,
    )


def superblock_icv(superblock: bytes) -> bytes:
    """Compute the integrity check value from an outer superblock.

    Args:
        superblock: Outer superblock bytes, with or without the stored ICV.

    Returns:
        SHA3-256 digest of the covered prefix with its ICV field cleared.
    """
    zeroed = bytearray(superblock[:0x5A0])
    zeroed[0x380:0x3A0] = bytes(0x20)
    return sha3(bytes(zeroed))


def _padded(data: bytes) -> bytes:
    """Pad a metadata value to one outer image block.

    Args:
        data: Unpadded metadata bytes.

    Returns:
        The data with trailing zeroes up to one block.

    Raises:
        ValueError: The value is larger than one block.
    """
    if len(data) > c.BLOCK:
        raise ValueError("an outer metadata block overflows")
    return data + bytes(c.BLOCK - len(data))


def _write_dinode(table: bytearray, index: int, mode: int, nlink: int, flags: int,
                  size: int, size_stored: int, direct: list[tuple[int, bytes]],
                  blocks: int, time: tuple[int, int],
                  indirect: list[tuple[int, bytes]] | None = None) -> None:
    """Write one outer-image inode into the inode table.

    Args:
        table: Inode table buffer to modify in place.
        index: Index of the inode to write.
        mode: File mode bits.
        nlink: Link count.
        flags: Inode flags.
        size: Logical file size in bytes.
        size_stored: Stored file size in bytes.
        direct: Direct block number and digest pairs.
        blocks: Number of blocks the file occupies.
        time: Timestamp as (seconds, nanoseconds).
        indirect: Optional indirect table block number and digest pairs.
    """
    at = index * DINODE_LEN
    inode = bytearray(DINODE_LEN)
    inode[0:2] = mode.to_bytes(2, "little")
    inode[2:4] = nlink.to_bytes(2, "little")
    inode[4:8] = flags.to_bytes(4, "little")
    inode[8:16] = size.to_bytes(8, "little")
    inode[0x10:0x18] = size_stored.to_bytes(8, "little")
    for slot in range(4):
        inode[0x18 + slot * 8:0x20 + slot * 8] = time[0].to_bytes(8, "little", signed=True)
    for slot in range(4):
        inode[0x38 + slot * 4:0x3C + slot * 4] = time[1].to_bytes(4, "little")
    inode[0x60:0x64] = blocks.to_bytes(4, "little")
    for slot, (block, digest) in enumerate(direct):
        offset = 0x64 + slot * 36
        inode[offset:offset + 32] = digest
        inode[offset + 32:offset + 36] = block.to_bytes(4, "little")
    for slot, (block, digest) in enumerate(indirect or []):
        offset = 0x214 + slot * 36
        inode[offset:offset + 32] = digest
        inode[offset + 32:offset + 36] = block.to_bytes(4, "little")
    table[at:at + DINODE_LEN] = inode


@dataclass(slots=True)
class OuterImage:
    """The serialized outer image and its block metadata.

    Attributes:
        image: Serialized outer image bytes.
        plaintext_digests: SHA3-256 digests in physical outer block order.
        superblock_block: Physical index of the outer superblock.
        seed: Seed value recorded in the superblock.
        layout: Block placement for the outer-image regions.
    """
    image: bytes
    plaintext_digests: list[bytes]
    superblock_block: int
    seed: bytes
    layout: Layout


def _metadata_blocks(lay: Layout, inner_blocks: int, naps: bytes,
                     data_digests: list[bytes], seed: bytes,
                     time: tuple[int, int],
                     mount_size: int | None = None) -> list[tuple[int, bytes, bytes]]:
    """Serialize the metadata blocks that follow the stored inner image.

    Args:
        lay: Outer image block layout.
        inner_blocks: Number of stored inner-image blocks.
        naps: Serialized inner-image layout descriptor.
        data_digests: SHA3-256 digests of the stored inner-image blocks.
        seed: 16-byte superblock seed.
        time: Timestamp as (seconds, nanoseconds).
        mount_size: Optional logical size of the inner mount in bytes.

    Returns:
        Metadata tuples of (outer block index, digest, block bytes) in write
        order.
    """
    output: list[tuple[int, bytes, bytes]] = []

    def push(index: int, block: bytes) -> None:
        """Append a metadata block with its index and SHA3-256 digest."""
        output.append((index, sha3(block), block))

    naps_digests: list[tuple[int, bytes]] = []
    for offset in range(0, len(naps), c.BLOCK):
        block = _padded(naps[offset:offset + c.BLOCK])
        naps_digests.append((lay.naps_block + offset // c.BLOCK, sha3(block)))
        push(lay.naps_block + offset // c.BLOCK, block)

    superblock = bytearray(c.BLOCK)
    superblock[0x00:0x08] = (2).to_bytes(8, "little", signed=True)
    superblock[0x08:0x10] = (20_130_315).to_bytes(8, "little", signed=True)
    superblock[0x1A] = 1
    superblock[0x1C:0x1E] = (0x0D).to_bytes(2, "little")
    superblock[0x20:0x24] = c.BLOCK.to_bytes(4, "little")
    superblock[0x28:0x30] = (1).to_bytes(8, "little", signed=True)
    superblock[0x30:0x38] = DINODES.to_bytes(8, "little", signed=True)
    superblock[0x38:0x40] = lay.ndblock.to_bytes(8, "little", signed=True)
    superblock[0x40:0x48] = (1).to_bytes(8, "little", signed=True)
    superblock[0x52:0x54] = (1).to_bytes(2, "little")
    superblock[0x58:0x60] = c.BLOCK.to_bytes(8, "little", signed=True)
    superblock[0x60:0x68] = c.BLOCK.to_bytes(8, "little", signed=True)
    for slot in range(4):
        superblock[0x68 + slot * 8:0x70 + slot * 8] = time[0].to_bytes(
            8, "little", signed=True)
    for slot in range(4):
        superblock[0x88 + slot * 4:0x8C + slot * 4] = time[1].to_bytes(4, "little")
    superblock[0xB0:0xB8] = (1).to_bytes(8, "little", signed=True)
    superblock[0x36C:0x370] = (1).to_bytes(4, "little")
    superblock[0x370:0x380] = seed
    superblock_slot = len(output)
    push(lay.superblock_block, bytes(superblock))

    records: dict[int, bytes] = {}
    slots: list[tuple[int, bytes]] = []
    naps_slots: list[tuple[int, bytes]] = []
    table_blocks: list[tuple[int, bytes]] = []
    for table in lay.indirect.tables + lay.naps_indirect.tables:
        block = bytearray(c.BLOCK)
        if table.children is None:
            for slot in range(PER_INDIRECT):
                if table.naps:
                    index = table.first_data + slot
                    if index >= lay.naps_blocks:
                        break
                    digest = naps_digests[index][1]
                    block_index = lay.naps_block + index
                else:
                    index = table.first_data + slot
                    if index >= inner_blocks:
                        break
                    digest = data_digests[index]
                    block_index = index
                at = slot * 36
                block[at:at + 32] = digest
                block[at + 32:at + 36] = block_index.to_bytes(4, "little")
        else:
            for slot, child in enumerate(table.children):
                digest = records.get(child)
                if digest is None:
                    raise ValueError("an indirect table is missing its child")
                at = slot * 36
                block[at:at + 32] = digest
                block[at + 32:at + 36] = child.to_bytes(4, "little")
        digest = sha3(bytes(block))
        records[table.block] = digest
        if table.block in lay.indirect.slots:
            slots.append((table.block, digest))
        if table.block in lay.naps_indirect.slots:
            naps_slots.append((table.block, digest))
        table_blocks.append((table.block, bytes(block)))
    slots.sort()
    naps_slots.sort()

    flt_entries = []
    for index, name in enumerate(("pfs_image.dat", "naps_pkg_layout.dat")):
        flt_entries.append(
            (hash_path(name), pack_inode_entry(3 + index, False, False, index)))
    flt_bytes = write_table(flt_entries)
    root_dirents = [
        ("inode_flat_path_table", 1, DIRENT_FILE),
        ("uroot", 2, DIRENT_DIR),
    ]
    root_bytes = _padded(dirents_bytes(root_dirents))
    uroot_dirents = [
        (".", 2, DIRENT_DOT),
        ("..", 2, DIRENT_DOTDOT),
        ("pfs_image.dat", 3, DIRENT_FILE),
        ("naps_pkg_layout.dat", 4, DIRENT_FILE),
    ]
    uroot_bytes = _padded(dirents_bytes(uroot_dirents))

    table = bytearray(c.BLOCK)
    flt_block = _padded(flt_bytes)
    _write_dinode(table, 0, 0o40555, 1, 0x2000C, c.BLOCK, c.BLOCK,
                  [(lay.root_block, sha3(root_bytes))], 1, time)
    _write_dinode(table, 1, 0o100555, 1, 0x2000C, len(flt_bytes), len(flt_bytes),
                  [(lay.flt_block, sha3(flt_block))], 1, time)
    _write_dinode(table, 2, 0o40555, 3, 0xC, c.BLOCK, c.BLOCK,
                  [(lay.uroot_block, sha3(uroot_bytes))], 1, time)
    _write_dinode(table, 3, 0o100555, 1, 0xD, inner_blocks * c.BLOCK,
                  mount_size if mount_size is not None else inner_blocks * c.BLOCK,
                  [(index, data_digests[index])
                   for index in range(min(inner_blocks, DIRECT_SLOTS))],
                  inner_blocks, time, slots)
    _write_dinode(table, 4, 0o100555, 1, 0xD, len(naps), len(naps),
                  naps_digests[:DIRECT_SLOTS], lay.naps_blocks, time, naps_slots)
    table_digest = sha3(bytes(table))
    push(lay.table_block, bytes(table))
    push(lay.root_block, root_bytes)
    push(lay.flt_block, flt_block)
    for index, block in table_blocks:
        push(index, block)
    push(lay.uroot_block, uroot_bytes)
    for previous, following in zip(output, output[1:]):
        if following[0] != previous[0] + 1:
            raise ValueError("outer metadata blocks are out of order")

    _, _, superblock = output[superblock_slot]
    superblock = bytearray(superblock)
    superblock[0xB8:0xD8] = table_digest
    superblock[0xD8:0xE0] = lay.table_block.to_bytes(8, "little", signed=True)
    superblock[0x380:0x3A0] = superblock_icv(bytes(superblock))
    output[superblock_slot] = (output[superblock_slot][0],
                               sha3(bytes(superblock)), bytes(superblock))
    if len(output) != lay.ndblock - inner_blocks:
        raise ValueError("outer layout block count is inconsistent")
    return output


def write(inner: bytes, naps: bytes, seed: bytes,
          time: tuple[int, int] = (0, 0), mount_size: int | None = None) -> OuterImage:
    """Assemble the outer image around a stored or compressed inner image.

    Args:
        inner: Stored inner-image bytes, aligned to full blocks.
        naps: Serialized layout descriptor for the inner image.
        seed: 16-byte value to record in the superblock.
        time: Timestamp as (seconds, nanoseconds), defaulting to zero.
        mount_size: Logical mount size in bytes, if different from the stored
            length.

    Returns:
        The plaintext outer image, block digests, and block layout.

    Raises:
        ValueError: The image length, seed length, or resulting block layout is
            invalid.
    """
    if not inner or len(inner) % c.BLOCK:
        raise ValueError("the inner image must be a non-empty whole number of blocks")
    if len(seed) != 16:
        raise ValueError("the superblock seed is 16 bytes")
    inner_blocks = len(inner) // c.BLOCK
    lay = layout(inner_blocks, len(naps))
    data_digests = [sha3(inner[at:at + c.BLOCK])
                    for at in range(0, len(inner), c.BLOCK)]
    image = bytearray(inner)
    plaintext_digests = list(data_digests)
    for index, digest, block in _metadata_blocks(
            lay, inner_blocks, naps, data_digests, seed, time, mount_size):
        plaintext_digests.append(digest)
        image += block
    return OuterImage(bytes(image), plaintext_digests, lay.superblock_block,
                      seed, lay)
