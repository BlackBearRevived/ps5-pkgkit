"""Interpret a Kraken layout descriptor and decode its image blocks."""

from __future__ import annotations

from dataclasses import dataclass

from . import kraken

GAP_TYPE = 0x40
UBLOCK = 0x40000
WINDOW = 0x40000
SHUFFLE_UNIT = 0x10000

SHUFFLES = (
    (), (4, 4), (2, 2, 4), (1, 1, 6), (1, 1, 1, 1, 1, 1, 1, 1), (8, 2, 2, 4),
    (1, 1, 6, 2, 2, 4), (1, 1, 6, 1, 1, 6), (4, 4, 4, 4), (8, 8), (8, 4, 4),
    (2, 6), (2, 6, 2, 6),
)


@dataclass(slots=True)
class DescribedBlock:
    """The stored span and encoding of one logical Kraken block.

    Attributes:
        logical: Logical byte offset of the block in the mount.
        length: Decoded block length in bytes.
        stored_at: Starting byte offset in the stored image.
        even_len: Stored length of the first half.
        stored_len: Combined stored length of the halves.
        even_lz: Whether the first half uses LZ commands.
        odd_lz: Whether the second half uses LZ commands.
        mode_bits: Packed flags that include the literal mode for each half.
        shuffle: Index of the shuffle pattern to undo after decoding.
    """
    logical: int
    length: int
    stored_at: int
    even_len: int
    stored_len: int
    even_lz: bool
    odd_lz: bool
    mode_bits: int
    shuffle: int


def _word(blob: bytes, at: int) -> int:
    """Read a little-endian 64-bit word at the requested byte offset."""
    return int.from_bytes(blob[at:at + 8], "little")


def describe(blob: bytes) -> list[DescribedBlock]:
    """Interpret a Kraken layout as a sequence of logical block spans.

    Args:
        blob: Complete serialized Kraken layout descriptor.

    Returns:
        Block descriptions in logical mount order.

    Raises:
        ValueError: The descriptor is truncated or has unsupported or
            inconsistent records.
    """
    if len(blob) < 16:
        raise ValueError("descriptor too short")
    w0, w1 = _word(blob, 0), _word(blob, 8)
    files = (w0 & 0xFFFFFF) + 1
    ublocks = (w0 >> 32) & 0xFFFFFF
    outer = w1 & 0xFFFFFF
    shuffle_count = (w0 >> 28) & 0xF
    records = ((w1 >> 24) & 0xFFFFFF) + 2
    fidx_at = 16 + (outer + shuffle_count) * 8
    u2c_end = fidx_at + files * 6 + (ublocks // 8 + 1) * 10
    rec_at = (u2c_end + 7) // 8 * 8 + 3
    if len(blob) < rec_at + records * 9:
        raise ValueError("descriptor shorter than its records")

    table = []
    for pattern in range(shuffle_count):
        entry = blob[16 + (outer + pattern) * 8:16 + (outer + pattern) * 8 + 8]
        used = next((index for index, value in enumerate(entry) if value == 0), 8)
        match = None
        for index, fields in enumerate(SHUFFLES):
            if tuple(entry[used:]) == (0,) * (8 - used) and tuple(fields) == tuple(entry[:used]):
                match = index
                break
        if match is None:
            raise ValueError(f"shuffle pattern {pattern}: unknown descriptor")
        table.append(match)

    entries = []
    for index in range(files):
        raw = blob[fidx_at + index * 6:fidx_at + index * 6 + 6]
        entries.append((int.from_bytes(raw[:5], "little"), raw[5]))
    mount = entries[-1][0] if entries else 0
    if any(offset > mount for offset, _ in entries):
        raise ValueError("a file boundary lies past the mount's end")
    bounds = sorted({offset for offset, _ in entries})
    ordinary = {offset for offset, kind in entries if kind != GAP_TYPE}
    gaps = {}
    for offset, kind in entries:
        if kind == GAP_TYPE and offset < mount and offset not in ordinary:
            import bisect
            position = bisect.bisect_right(bounds, offset)
            gaps[offset] = bounds[position] if position < len(bounds) else mount

    strict = blob[rec_at - 3:rec_at] == b"\x00\x00\x04"

    def rec(index: int) -> int:
        """Read one packed block record by its index."""
        return int.from_bytes(blob[rec_at + index * 9:rec_at + index * 9 + 9], "little")

    def field(value: int, low: int, width: int) -> int:
        """Extract a bit field of a given width starting at the low bit."""
        return (value >> low) & ((1 << width) - 1)

    output: list[DescribedBlock] = []
    cursor = 0
    logical = 0
    next_is_anchor = True
    carried_nibble = 0
    for index in range(max(records - 1, 0)):
        value = rec(index)
        nibble = carried_nibble
        carried_nibble = field(value, 68, 4)
        anchor = next_is_anchor
        next_is_anchor = field(value, 66, 1) == 1 and not anchor
        if anchor:
            cursor = (field(value, 26, 22) << 18) | field(value, 48, 18)
            terminator = index + 2 == records
            if strict and index > 0 and not terminator and nibble != (cursor >> 16) & 0xF:
                raise ValueError(f"record {index}: the anchor's position nibble disagrees")
            continue
        while logical in gaps:
            logical = gaps[logical]
        if strict and index > 0 and nibble != logical & 0xF:
            raise ValueError(f"record {index}: the exact start's low nibble disagrees")
        if logical >= mount:
            raise ValueError(f"record {index}: a block starts past the mount's end")
        next_bound = next((bound for bound in bounds if bound > logical), mount)
        if (logical % WINDOW) >> 4 != field(value, 0, 14):
            raise ValueError(f"record {index}: logical offset disagrees")
        cap = logical + min(min(next_bound, mount) - logical, UBLOCK)
        next_record = index + 2 if field(value, 66, 1) == 1 else index + 1
        after_cap = cap
        while after_cap in gaps:
            after_cap = gaps[after_cap]
        next_key = rec(min(next_record, records - 1)) & 0x3FFF
        leaves_off_at_cap = (next_key == (after_cap % WINDOW) >> 4
                             and (not strict or (rec(next_record - 1) >> 68) & 0xF == after_cap & 0xF))
        if next_record + 1 < records and not leaves_off_at_cap:
            at16 = (logical & ~(WINDOW - 1)) | (next_key << 4)
            if at16 <= logical & ~0xF:
                at16 += WINDOW
            low = (rec(next_record - 1) >> 68) & 0xF if strict else logical & 0xF
            exact = at16 | low
            length = exact - logical if (at16 + 16 <= cap or (strict and exact < cap)) else cap - logical
        else:
            length = cap - logical
        end = (cursor & ~(WINDOW - 1)) | field(value, 48, 18)
        if end < cursor:
            end += WINDOW
        even_raw = field(value, 33, 1) == 0 and field(value, 14, 17) + 1 == min(length, kraken.HALF)
        odd_raw = field(value, 36, 1) == 0
        if end == cursor and even_raw and odd_raw and length > kraken.HALF:
            end += WINDOW
        shuffle_index = field(value, 44, 4)
        if shuffle_index:
            if shuffle_index - 1 >= len(table):
                raise ValueError(f"record {index}: shuffle index past the table")
            shuffle = table[shuffle_index - 1]
        else:
            shuffle = 0
        output.append(DescribedBlock(
            logical=logical,
            length=length,
            stored_at=cursor,
            even_len=field(value, 14, 17) + 1,
            stored_len=end - cursor,
            even_lz=field(value, 33, 1) == 1,
            odd_lz=field(value, 36, 1) == 1,
            mode_bits=field(value, 32, 5),
            shuffle=shuffle,
        ))
        cursor = end
        logical += length
    while logical in gaps:
        logical = gaps[logical]
    if logical != mount:
        raise ValueError(f"blocks tile to {logical:#x}, the mount is {mount:#x}")
    return output


def deshuffle(data: bytearray, pattern: int) -> None:
    """Reassemble interleaved fields in each data unit in place.

    Args:
        data: Mutable decoded bytes to transform.
        pattern: Index of the layout's shuffle pattern, with zero for no
            shuffle.

    Raises:
        ValueError: The pattern index exceeds the supported table.
    """
    if pattern >= len(SHUFFLES):
        raise ValueError(f"shuffle pattern {pattern} is not one of the known ones")
    fields = SHUFFLES[pattern]
    stride = sum(fields)
    if stride == 0:
        return
    for start in range(0, len(data), SHUFFLE_UNIT):
        chunk = bytearray(data[start:start + SHUFFLE_UNIT])
        vectors = len(chunk) // stride
        at = 0
        offset = 0
        for field in fields:
            for vector in range(vectors):
                chunk[vector * stride + offset:vector * stride + offset + field] = \
                    data[start + at:start + at + field]
                at += field
            offset += field
        data[start:start + len(chunk)] = chunk


def decode_described(image: bytes, block: DescribedBlock) -> bytes:
    """Decode and deshuffle one block from the stored image.

    Args:
        image: Complete stored inner-image bytes.
        block: Stored span, decoded length, and modes from the layout
            descriptor.

    Returns:
        Uncompressed bytes for the logical block.

    Raises:
        ValueError: The geometry, encoded payload, or shuffle pattern is
            invalid.
    """
    if block.length == 0 or block.length > UBLOCK:
        raise ValueError("not a Kraken block length")
    if block.stored_len > 2 * WINDOW or block.even_len > block.stored_len:
        raise ValueError("not a Kraken block span")
    start = block.stored_at
    end = start + block.stored_len
    if end > len(image):
        raise ValueError("a block runs past the image")
    source = image[start:end]
    even_logical = min(block.length, kraken.HALF)
    halves = []

    def half(data: bytes, is_lz: bool, delta: bool, logical: int) -> kraken.Half:
        """Classify one half as raw, entropy-coded, or LZ-coded."""
        if is_lz:
            return kraken.Half("delta" if delta else "lz", data)
        if len(data) < logical:
            return kraken.Half("entropy", data)
        return kraken.Half("raw", data)

    even = source[:block.even_len]
    halves.append(half(even, block.even_lz, bool(block.mode_bits & 1), even_logical))
    if block.length > kraken.HALF:
        odd = source[block.even_len:]
        halves.append(half(odd, block.odd_lz, bool(block.mode_bits & 0b1000),
                           block.length - kraken.HALF))
    data = bytearray(kraken.decode_block(halves, block.length))
    deshuffle(data, block.shuffle)
    return bytes(data)


def decode_image(image: bytes, blob: bytes) -> bytes:
    """Reconstruct the logical mount from a Kraken image and layout.

    Args:
        image: Stored inner-image bytes.
        blob: Complete Kraken layout descriptor.

    Returns:
        Concatenated decoded blocks in logical mount order.

    Raises:
        ValueError: The layout or a stored block is invalid.
    """
    output = bytearray()
    for block in describe(blob):
        output += decode_described(image, block)
    return bytes(output)
