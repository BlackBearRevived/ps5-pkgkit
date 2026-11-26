"""The inner image (``pfs_image.dat``): data-first, metadata stored above it.

File payloads sit at their afid-order on-disk offsets; the block-info table
occupies the padding block after the data; the metadata region starts at the
256 KiB-aligned ``meta_base`` and holds the inner PFS superblock, the inode
table, the super-root dirents, both flat-path tables, the afid table and one
dirent stream per directory.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from . import constants as c
from .crypto import hmac_sha256
from .dirents import dirents_bytes
from .flt import write as write_table
from .keys import KEYSTONE_HMAC_1, KEYSTONE_HMAC_2
from .plan import Plan, super_root_dirents

BLOCK_INFO_ENTRIES = 32
BLOCK_INFO_TEMPLATE = 0x00FC_FF27
BLOCK_INFO_VERSION = 0x0040_0003
BLOCK_INFO_BASE = 0x0027_373C


def keystone(passcode: str) -> bytes:
    """Build the 96-byte sce_sys/keystone file for a passcode.

    Args:
        passcode: Passcode to encode as UTF-8.

    Returns:
        The complete keystone record.
    """
    output = bytearray(96)
    output[0:8] = b"keystone"
    output[8:10] = (3).to_bytes(2, "little")
    output[10] = 0x01
    output[0x20:0x40] = hmac_sha256(KEYSTONE_HMAC_1, passcode.encode("utf-8"))
    output[0x40:0x60] = hmac_sha256(KEYSTONE_HMAC_2, bytes(output[:0x40]))
    return bytes(output)


def block_info_table(plan: Plan) -> bytes:
    """Serialize the block-info table that follows the file data.

    Args:
        plan: Inner-image plan whose application file sizes determine the final
            row.

    Returns:
        The 256-byte block-info table.
    """
    uroot_sum = sum(item.size for item in plan.files if not item.sce_sys)
    subtracted = (4 * uroot_sum) & 0xF_FFFF
    big_endian = (BLOCK_INFO_BASE - subtracted) & 0xFF_FFFF
    value = ((big_endian & 0xFF) << 16) | (big_endian & 0xFF00) | ((big_endian >> 16) & 0xFF)
    table = bytearray(BLOCK_INFO_ENTRIES * 8)
    for index in range(BLOCK_INFO_ENTRIES):
        entry = value if index + 1 == BLOCK_INFO_ENTRIES else BLOCK_INFO_TEMPLATE
        table[index * 8:index * 8 + 4] = entry.to_bytes(4, "little")
        table[index * 8 + 4:index * 8 + 8] = BLOCK_INFO_VERSION.to_bytes(4, "little")
    return bytes(table)


def inode_offset(index: int) -> int:
    """Return the byte offset of an inode within the inode table."""
    return (index // c.INODES_PER_BLOCK) * c.BLOCK + (index % c.INODES_PER_BLOCK) * c.INODE_LEN


def _dir_size(entry_bytes: int) -> int:
    """Round a dirent stream length up to at least one full block."""
    return max(c.align_up(entry_bytes, c.BLOCK), c.BLOCK)


@dataclass(slots=True)
class _Inode:
    """Fields used to serialize one inner-image inode.

    Attributes:
        mode: Inode type and permission bits.
        nlink: Link count.
        flags: Inode flags for data, tables, or modules.
        size: Logical length of the node's data in bytes.
        logical_offset: Byte offset of the data in the logical mount.
        db1: Application file ID for a file, or -1 when unused.
        db2: Parent inode when applicable, otherwise -1.
        db3: Byte offset of the parent directory entry when applicable.
    """
    mode: int
    nlink: int
    flags: int
    size: int
    logical_offset: int
    db1: int = -1
    db2: int = -1
    db3: int = -1


def _write_inode(table: bytearray, index: int, record: _Inode,
                 build_time: tuple[int, int]) -> None:
    """Write one record into an existing inode table.

    Args:
        table: Inode table buffer to modify in place.
        index: Zero-based inode index.
        record: Inode fields to serialize.
        build_time: Timestamp as (seconds, nanoseconds).
    """
    at = inode_offset(index)

    def put(offset: int, data: bytes) -> None:
        """Write bytes at an offset relative to the current inode."""
        table[at + offset:at + offset + len(data)] = data

    put(0x00, record.mode.to_bytes(2, "little"))
    put(0x02, record.nlink.to_bytes(2, "little"))
    put(0x04, record.flags.to_bytes(4, "little"))
    put(0x08, record.size.to_bytes(8, "little"))
    put(0x10, record.size.to_bytes(8, "little"))
    for slot in range(4):
        put(0x18 + slot * 8, build_time[0].to_bytes(8, "little", signed=True))
    for slot in range(4):
        put(0x38 + slot * 4, build_time[1].to_bytes(4, "little"))
    put(0x60, record.logical_offset.to_bytes(8, "little"))
    put(0x68, record.db1.to_bytes(4, "little", signed=True))
    put(0x6C, record.db2.to_bytes(4, "little", signed=True))
    put(0x70, record.db3.to_bytes(4, "little", signed=True))


def _metadata_region(plan: Plan, build_time: tuple[int, int]) -> bytes:
    """Serialize the inner-image metadata at its planned offsets.

    Args:
        plan: Layout containing the superblock geometry, inodes, and tables.
        build_time: Timestamp as (seconds, nanoseconds).

    Returns:
        The metadata region, beginning at the planned metadata base.
    """
    inode_count = 4 + len(plan.dirs) + len(plan.files)
    region = bytearray(plan.metadata.blocks * c.BLOCK)

    superblock = bytearray(c.BLOCK)
    superblock[0x00:0x08] = (2).to_bytes(8, "little", signed=True)
    superblock[0x08:0x10] = (20_130_315).to_bytes(8, "little", signed=True)
    superblock[0x1A] = 1
    superblock[0x1C:0x1E] = (0x18).to_bytes(2, "little")
    superblock[0x20:0x24] = c.BLOCK.to_bytes(4, "little")
    superblock[0x28:0x30] = (1).to_bytes(8, "little", signed=True)
    superblock[0x30:0x38] = inode_count.to_bytes(8, "little", signed=True)
    superblock[0x38:0x40] = plan.ndblock.to_bytes(8, "little", signed=True)
    table_blocks = max(-(-plan.metadata.inode_table[1] // c.BLOCK), 1)
    superblock[0x40:0x48] = table_blocks.to_bytes(8, "little", signed=True)
    superblock[0x50:0x52] = (0).to_bytes(2, "little")
    superblock[0x52:0x54] = (1).to_bytes(2, "little")
    superblock[0x54:0x58] = (0x10).to_bytes(4, "little")
    superblock[0x58:0x60] = (table_blocks * c.BLOCK).to_bytes(8, "little", signed=True)
    superblock[0x60:0x68] = (table_blocks * c.BLOCK).to_bytes(8, "little", signed=True)
    for slot in range(4):
        superblock[0x68 + slot * 8:0x70 + slot * 8] = build_time[0].to_bytes(
            8, "little", signed=True)
    for slot in range(4):
        superblock[0x88 + slot * 4:0x8C + slot * 4] = build_time[1].to_bytes(4, "little")
    superblock[0xB0:0xB8] = table_blocks.to_bytes(8, "little", signed=True)
    superblock[0xD8:0xE0] = (plan.metadata.inode_table[0] // c.BLOCK).to_bytes(
        8, "little", signed=True)
    superblock[0x368] = 1
    region[0:c.BLOCK] = superblock

    flt_inode = write_table(plan.flt_inode)
    flt_apr = write_table(plan.flt_apr)
    afid_bytes = b"".join(value.to_bytes(4, "little", signed=True)
                          for value in plan.afid_to_ino)
    table_at, table_bytes = plan.metadata.inode_table
    table_start = table_at - plan.meta_base
    table = bytearray(region[table_start:table_start + table_bytes])

    _write_inode(table, c.SUPER_ROOT_INODE, _Inode(
        mode=c.MODE_DIR_UROOT, nlink=1, flags=c.FLAGS_TABLE,
        size=_dir_size(plan.metadata.super_root[1]),
        logical_offset=plan.metadata.super_root[0],
    ), build_time)
    for index, size, offset in (
        (c.INODE_FLT_INODE, plan.metadata.flt[1], plan.metadata.flt[0]),
        (c.APR_FLT_INODE, plan.metadata.flt_apr[1], plan.metadata.flt_apr[0]),
        (c.AFID_TABLE_INODE, plan.metadata.afid[1], plan.metadata.afid[0]),
    ):
        _write_inode(table, index, _Inode(
            mode=c.MODE_FILE, nlink=1, flags=c.FLAGS_TABLE,
            size=size, logical_offset=offset,
        ), build_time)
    for index, directory in enumerate(plan.dirs):
        is_root = index == 0
        system = not is_root and directory.sce_sys
        span = plan.metadata.dirs[index]
        _write_inode(table, 4 + index, _Inode(
            mode=c.MODE_DIR if system else c.MODE_DIR_UROOT,
            nlink=directory.nlink,
            flags=c.FLAGS_TABLE if system else c.FLAGS_DATA,
            size=_dir_size(span[1]),
            logical_offset=span[0],
            db1=-1,
            db2=directory.parent_inode,
            db3=directory.dirent_offset,
        ), build_time)
    for index, item in enumerate(plan.files):
        _write_inode(table, 4 + len(plan.dirs) + index, _Inode(
            mode=item.mode,
            nlink=1,
            flags=item.inode_flags,
            size=item.size,
            logical_offset=item.logical_offset,
            db1=item.afid,
            db2=item.parent_inode,
            db3=item.dirent_offset,
        ), build_time)
    region[table_start:table_start + table_bytes] = table

    def place(span: tuple[int, int], data: bytes) -> None:
        """Copy bytes into the metadata buffer at a planned mount offset."""
        at = span[0] - plan.meta_base
        region[at:at + len(data)] = data

    place(plan.metadata.super_root, dirents_bytes(super_root_dirents()))
    place(plan.metadata.flt, flt_inode)
    place(plan.metadata.flt_apr, flt_apr)
    place(plan.metadata.afid, afid_bytes)
    for index, directory in enumerate(plan.dirs):
        place(plan.metadata.dirs[index], dirents_bytes(directory.dirents))
    return bytes(region)


@dataclass(slots=True)
class Placement:
    """The stored and logical positions of a file payload.

    Attributes:
        on_disk_offset: Byte offset in the stored inner image.
        size: Payload length in bytes.
        logical_offset: Byte offset in the logical mount image.
    """
    on_disk_offset: int
    size: int
    logical_offset: int


@dataclass(slots=True)
class InnerImage:
    """An assembled inner image and its layout metadata.

    Attributes:
        image: Complete stored image bytes.
        meta_base: Logical byte offset of the metadata region.
        ndblock: Planned mount size in blocks.
        block_info_offset: Stored byte offset of the block-info table.
        placements: File locations in plan file order.
        afid_files: Triples of logical offset, stored offset, and size in AFID
            order.
        metadata: Serialized metadata region.
        blocks: Pairs of logical byte offset and length for metadata blocks.
    """
    image: bytes
    meta_base: int
    ndblock: int
    block_info_offset: int
    placements: list[Placement]
    afid_files: list[tuple[int, int, int]]
    metadata: bytes
    blocks: list[tuple[int, int]] = field(default_factory=list)

    @property
    def disk_blocks(self) -> int:
        """The number of blocks needed to hold the stored image."""
        return (len(self.image) + c.BLOCK - 1) // c.BLOCK


def metadata_region(plan: Plan, build_time: tuple[int, int] = (0, 0)) -> bytes:
    """Serialize the metadata region for an inner-image plan.

    Args:
        plan: Inner-image layout to serialize.
        build_time: Timestamp as (seconds, nanoseconds), defaulting to zero.

    Returns:
        Bytes starting at the metadata base, without the preceding file data.
    """
    return _metadata_region(plan, build_time)


def write_stored(plan: Plan, passcode: str,
                 read: Callable[[str], bytes],
                 build_time: tuple[int, int] = (0, 0)) -> InnerImage:
    """Assemble a stored inner image from its plan and file payloads.

    Args:
        plan: Planned file placements and metadata geometry.
        passcode: Passcode for generating a missing keystone.
        read: Callable that returns all bytes for a source-relative file path.
        build_time: Timestamp as (seconds, nanoseconds), defaulting to zero.

    Returns:
        Stored image bytes and their on-disk and logical layout.

    Raises:
        ValueError: A payload length or region does not fit the plan.
    """
    payloads: list[bytes] = []
    for item in plan.files:
        data = keystone(passcode) if item.generated and item.path == c.KEYSTONE else read(item.path)
        if len(data) != item.size:
            raise ValueError(
                f"{item.path} is {len(data)} bytes but the plan fixed {item.size}"
            )
        payloads.append(data)

    image = bytearray(plan.ndblock * c.BLOCK)
    placements = [Placement(0, 0, 0) for _ in plan.files]
    afid_files: list[tuple[int, int, int]] = []
    for afid, index in enumerate(plan.afid_order):
        item = plan.files[index]
        start = item.on_disk_offset
        end = start + len(payloads[index])
        if end > len(image):
            raise ValueError(f"{item.path} runs past the mount")
        image[start:end] = payloads[index]
        placements[index] = Placement(item.on_disk_offset, len(payloads[index]),
                                      item.logical_offset)
        afid_files.append((item.logical_offset, item.on_disk_offset, item.size))

    block_info_offset = c.align_up(plan.data_end, c.BLOCK)
    table = block_info_table(plan)
    if block_info_offset + len(table) > plan.meta_base:
        raise ValueError("no room for the block-info table before the metadata")
    image[block_info_offset:block_info_offset + len(table)] = table

    region = _metadata_region(plan, build_time)
    if len(region) != plan.metadata_blocks * c.BLOCK:
        raise ValueError("metadata region does not match the planned blocks")
    tail_end = plan.meta_base + len(region)
    del image[c.align_up(tail_end, c.BLOCK):]
    image[plan.meta_base:tail_end] = region

    return InnerImage(
        image=bytes(image),
        meta_base=plan.meta_base,
        ndblock=plan.ndblock,
        block_info_offset=block_info_offset,
        placements=placements,
        afid_files=afid_files,
        metadata=region,
        blocks=[(plan.meta_base + index * c.BLOCK, c.BLOCK)
                for index in range(plan.metadata_blocks)],
    )
