"""``naps_pkg_layout.dat``: the map from the on-disk inner image to its mount.

Layout: a 16-byte header, the outer-block digests, the ``fidx`` file offsets,
the ``u2c`` ublock mapping and the 9-byte ``cblockinfo`` records. A stored
image carries a run at every file's start and one every 16 records, and ends
with a terminator record that marks the mount's end.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import constants as c

U2C_LEN = 10
FIDX_LEN = 6
CBLOCK_LEN = 9
OUTER_DIGEST_LEN = 8
UBLOCK = 0x40000
FIDX_TYPE_MOUNT_END = 0x40
KDE_PAYLOAD = 0
CLEN_MAX = 0x1FFFF

COMP_ZLIB = 1
COMP_KRAKEN = 2


@dataclass(slots=True)
class RunBase:
    """The base offset and key slot for a run of blocks.

    Attributes:
        coffset_end_mod_256k: End of the previous stored run within its 256 KiB
            unit.
        tweak: Tweak index stored for this run.
        key_slot: Key slot recorded for the run.
        coffset_start_256k: Stored start of the run in 256 KiB units.
    """
    coffset_end_mod_256k: int
    tweak: int
    key_slot: int
    coffset_start_256k: int


@dataclass(slots=True)
class Block:
    """A data block or end marker in the NAPS layout.

    Attributes:
        coffset_start_mod_256k: Stored start within the current 256 KiB unit.
        reserved19: Bit used by the writer to mark the terminator.
        uoffset_start: Logical start within the current 256 KiB unit.
        clen_even_minus1: Stored even-half length minus one.
        even: Mode of the even half.
        odd: Mode of the odd half.
        kde: Encoded block kind.
        shuffle: Shuffle pattern selector.
    """
    coffset_start_mod_256k: int
    reserved19: bool
    uoffset_start: int
    clen_even_minus1: int
    even: int
    odd: int
    kde: int
    shuffle: int


Cblock = RunBase | Block


@dataclass(slots=True)
class Layout:
    """The decoded NAPS header, lookup tables, and block records.

    Attributes:
        num_files: File count encoded in the header.
        compression_type: Numeric compression method.
        num_keys: Encoded key-slot count.
        num_shuffle: Number of shuffle patterns.
        num_ublocks: Count of 256 KiB logical units.
        num_outer_blocks: Count of stored outer blocks.
        outer_digests: One digest field for each outer block.
        shuffle_patterns: Raw shuffle pattern records.
        fidx: File offsets and their record types.
        u2c: Logical-to-stored block map records.
        cblocks: Run bases and data block records in descriptor order.
    """
    num_files: int
    compression_type: int
    num_keys: int
    num_shuffle: int
    num_ublocks: int
    num_outer_blocks: int
    outer_digests: list[bytes]
    shuffle_patterns: list[bytes]
    fidx: list[tuple[int, int]]
    u2c: list[tuple[int, bytes]]
    cblocks: list[Cblock]

    @property
    def mount_size(self) -> int:
        """The mount length in bytes, or zero without file-index records."""
        return self.fidx[-1][0] if self.fidx else 0

    @staticmethod
    def u2c_count(num_ublocks: int) -> int:
        """Return the number of u2c records for the logical unit count."""
        return (num_ublocks + 7) // 8 + 1


def decode_cblock(raw: bytes) -> Cblock:
    """Decode the fields of a nine-byte block record.

    Args:
        raw: Bytes starting with the little-endian block record.

    Returns:
        A run base or data block, depending on the record tag.
    """
    value = int.from_bytes(raw[:CBLOCK_LEN], "little")

    def field(low: int, high: int) -> int:
        """Extract an inclusive range of bits from the record word."""
        return (value >> low) & ((1 << (high - low + 1)) - 1)

    coffset = field(0, 17)
    if (value >> 18) & 1:
        return RunBase(coffset, field(19, 46), field(47, 49), field(50, 71))
    return Block(
        coffset_start_mod_256k=coffset,
        reserved19=bool((value >> 19) & 1),
        uoffset_start=field(20, 37),
        clen_even_minus1=field(38, 54),
        even=field(55, 57),
        odd=field(58, 60),
        kde=field(61, 66),
        shuffle=field(68, 71),
    )


def encode_cblock(record: Cblock) -> bytes:
    """Serialize a block record in the NAPS on-disk format.

    Args:
        record: Run base or data block to encode.

    Returns:
        The nine-byte little-endian block record.
    """
    value = 0
    if isinstance(record, Block):
        value |= record.coffset_start_mod_256k & 0x3FFFF
        value |= int(record.reserved19) << 19
        value |= (record.uoffset_start & 0x3FFFF) << 20
        value |= (record.clen_even_minus1 & 0x1FFFF) << 38
        value |= (record.even & 0x7) << 55
        value |= (record.odd & 0x7) << 58
        value |= (record.kde & 0x3F) << 61
        value |= (record.shuffle & 0xF) << 68
    else:
        value |= record.coffset_end_mod_256k & 0x3FFFF
        value |= 1 << 18
        value |= (record.tweak & 0x0FFFFFFF) << 19
        value |= (record.key_slot & 0x7) << 47
        value |= (record.coffset_start_256k & 0x3FFFFF) << 50
    return value.to_bytes(CBLOCK_LEN, "little")


def parse(blob: bytes) -> Layout:
    """Read the NAPS layout descriptor into its constituent tables.

    Args:
        blob: Complete serialized layout descriptor.

    Returns:
        Header values, digest and index sections, and decoded block records.

    Raises:
        ValueError: The header is short or the sections do not fit the
            descriptor.
    """
    if len(blob) < 16:
        raise ValueError("naps layout is shorter than its header")
    word0 = int.from_bytes(blob[0:8], "little")
    word1 = int.from_bytes(blob[8:16], "little")
    num_files = (word0 & 0xFFFFFF) + 1
    compression_type = (word0 >> 24) & 0x3
    num_keys = ((word0 >> 26) & 0x3) + 1
    num_shuffle = (word0 >> 28) & 0xF
    num_ublocks = (word0 >> 32) & 0xFFFFFF
    num_outer_blocks = word1 & 0xFFFFFF
    num_cblock = ((word1 >> 24) & 0xFFFFFF) + 2
    at = 16
    outer_digests = [blob[at + i * OUTER_DIGEST_LEN:at + (i + 1) * OUTER_DIGEST_LEN]
                     for i in range(num_outer_blocks)]
    at += num_outer_blocks * OUTER_DIGEST_LEN
    shuffle_patterns = [blob[at + i * 8:at + (i + 1) * 8] for i in range(num_shuffle)]
    at += num_shuffle * 8
    after_u2c = len(blob) - num_cblock * CBLOCK_LEN
    fidx_bytes = after_u2c - (at + Layout.u2c_count(num_ublocks) * U2C_LEN)
    if fidx_bytes < 0 or fidx_bytes % FIDX_LEN:
        raise ValueError("naps layout has no room for its fidx section")
    fidx = []
    for _ in range(fidx_bytes // FIDX_LEN):
        raw = blob[at:at + FIDX_LEN]
        fidx.append((int.from_bytes(raw[:5], "little"), raw[5]))
        at += FIDX_LEN
    u2c = []
    for _ in range(Layout.u2c_count(num_ublocks)):
        raw = blob[at:at + U2C_LEN]
        u2c.append((int.from_bytes(raw[:3], "little"), raw[3:10]))
        at += U2C_LEN
    cblocks = []
    for _ in range(num_cblock):
        cblocks.append(decode_cblock(blob[at:at + CBLOCK_LEN]))
        at += CBLOCK_LEN
    if at != len(blob):
        raise ValueError("naps layout has trailing bytes")
    return Layout(num_files, compression_type, num_keys, num_shuffle, num_ublocks,
                  num_outer_blocks, outer_digests, shuffle_patterns, fidx, u2c,
                  cblocks)


@dataclass(slots=True)
class _Plan:
    """A block's positions and modes before packing NAPS records.

    Attributes:
        start_run: Whether to start a new run before this block.
        on_disk: Starting byte offset in the stored image.
        logical: Starting byte offset in the logical mount.
        even_chunk_len: Byte length of the even half.
        stream_len: Stored byte length of the complete block.
        even: Mode of the even half.
        odd: Mode of the odd half.
        kde: Encoded block kind.
        shuffle: Shuffle pattern selector.
        terminator: Whether this block marks the end of the mount.
    """
    start_run: bool
    on_disk: int
    logical: int
    even_chunk_len: int
    stream_len: int
    even: int
    odd: int
    kde: int
    shuffle: int
    terminator: bool = False


def _stored(start_run: bool, on_disk: int, logical: int, stream_len: int) -> _Plan:
    """Create a plan for a stored data block with up to two halves."""
    return _Plan(start_run, on_disk, logical, min(stream_len, 0x20000),
                 stream_len, 1, int(stream_len > 0x20000), KDE_PAYLOAD, 0)


def _needs_run(plans: list[_Plan], at: int, counter: int) -> bool:
    """Check whether to insert a run base before a record boundary."""
    index = at
    while index < len(plans):
        if counter % 16 == 0:
            return False
        if plans[index].start_run and (counter + 1) % 16 == 0:
            return True
        counter += 1
        index += 1
    return False


def _walk(plans: list[_Plan]) -> tuple[list[Cblock], list[tuple[int, int]]]:
    """Convert planned blocks to NAPS records and index positions.

    Args:
        plans: Planned blocks in stored stream order.

    Returns:
        Block records and pairs of record index and logical offset for data
        records.
    """
    entries: list[Cblock] = []
    by_std: list[tuple[int, int]] = []
    cursor = 0
    for index, plan in enumerate(plans):
        if not plan.start_run and _needs_run(plans, index, len(entries)):
            entries.append(RunBase(cursor & 0x3FFFF, cursor >> 15, 0, cursor // UBLOCK))
        if plan.start_run or (entries and len(entries) % 16 == 0):
            end = cursor & 0x3FFFF
            offset = plan.on_disk if plan.start_run else cursor
            cursor = offset
            entries.append(RunBase(end, 0 if plan.terminator else offset >> 15,
                                   0, offset // UBLOCK))
        if plan.terminator:
            clen = 0
        else:
            clen = min(max(plan.even_chunk_len - 1, 0), CLEN_MAX)
        by_std.append((len(entries), plan.logical))
        entries.append(Block(
            coffset_start_mod_256k=cursor & 0x3FFFF,
            reserved19=plan.terminator,
            uoffset_start=plan.logical & 0x3FFFF,
            clen_even_minus1=clen,
            even=plan.even,
            odd=plan.odd,
            kde=plan.kde,
            shuffle=plan.shuffle,
        ))
        cursor += plan.stream_len
    return entries, by_std


def build(image_len: int, ndblock: int, files: list[tuple[int, int, int]],
          data_end: int, meta_base: int) -> bytes:
    """Build the NAPS descriptor for an uncompressed inner image.

    Args:
        image_len: Stored inner-image length in bytes.
        ndblock: Logical mount length in filesystem blocks.
        files: Triples of logical offset, stored offset, and size in AFID order.
        data_end: Logical byte offset at the end of the file data.
        meta_base: Logical byte offset of the metadata region, aligned to 256
            KiB.

    Returns:
        Serialized layout descriptor.

    Raises:
        ValueError: The image or mount is empty or the metadata base is
            unaligned.
    """
    if image_len == 0 or ndblock == 0 or meta_base % UBLOCK:
        raise ValueError("naps needs a non-empty image with 256 KiB-aligned metadata")
    mount_size = ndblock * c.BLOCK
    num_ublocks = (mount_size + UBLOCK - 1) // UBLOCK
    num_outer_blocks = (image_len + c.BLOCK - 1) // c.BLOCK
    num_files = len(files) + 3

    plans: list[_Plan] = []
    expected = 0
    for logical, on_disk, size in files:
        full, tail = divmod(size, UBLOCK)
        for k in range(full):
            d, logical_at = on_disk + k * UBLOCK, logical + k * UBLOCK
            plans.append(_stored(d != expected, d, logical_at, UBLOCK))
            expected = d + UBLOCK
        if tail > 0 or full == 0:
            d, logical_at = on_disk + full * UBLOCK, logical + full * UBLOCK
            plans.append(_stored(d != expected, d, logical_at, tail))
            expected = d + tail

    padding = data_end & ~(UBLOCK - 1)
    plans.append(_stored(False, data_end, padding, 0x10))
    meta_ublocks = (mount_size - meta_base + UBLOCK - 1) // UBLOCK
    for index in range(meta_ublocks):
        logical = meta_base + index * UBLOCK
        length = min(UBLOCK, mount_size - logical)
        plans.append(_stored(index == 0, meta_base + index * UBLOCK, logical, length))
    meta_end = meta_base + meta_ublocks * UBLOCK
    plans.append(_Plan(True, meta_end, mount_size, 0, 0, 0, 0, 0, 0, True))

    cblocks, by_std = _walk(plans)
    num_cblock = len(cblocks)
    sorted_std = sorted(by_std, key=lambda item: item[1])
    terminator = num_cblock - 1
    first: list[int] = []
    pointer = 0
    for ublock in range(num_ublocks):
        target = ublock * UBLOCK
        while pointer < len(sorted_std) and sorted_std[pointer][1] < target:
            pointer += 1
        first.append(sorted_std[pointer][0] if pointer < len(sorted_std) else terminator)
    u2c: list[tuple[int, bytes]] = []
    for group in range(Layout.u2c_count(num_ublocks)):
        base = first[group * 8] if group * 8 < len(first) else terminator
        deltas = bytearray(7)
        for slot in range(7):
            position = group * 8 + 1 + slot
            value = first[position] if position < len(first) else terminator
            delta = value - base
            if delta > 0xFF:
                raise ValueError("ublocks hold too many records for the flat descriptor")
            deltas[slot] = delta
        u2c.append((base, bytes(deltas)))

    fidx = [(logical, 0) for logical, _, _ in files]
    fidx.append((data_end, 0))
    fidx.append((meta_base, 0))
    fidx.append((mount_size, FIDX_TYPE_MOUNT_END))

    blob = bytearray()
    word0 = ((num_files - 1) & 0xFFFFFF) | (COMP_KRAKEN & 0x3) << 24
    word0 |= (num_ublocks & 0xFFFFFF) << 32
    word1 = (num_outer_blocks & 0xFFFFFF) | ((num_cblock - 2) & 0xFFFFFF) << 24
    blob += word0.to_bytes(8, "little")
    blob += word1.to_bytes(8, "little")
    blob += bytes(num_outer_blocks * OUTER_DIGEST_LEN)
    for offset, kind in fidx:
        blob += offset.to_bytes(5, "little") + bytes([kind])
    for base, deltas in u2c:
        blob += base.to_bytes(3, "little") + deltas
    for record in cblocks:
        blob += encode_cblock(record)
    return bytes(blob)
