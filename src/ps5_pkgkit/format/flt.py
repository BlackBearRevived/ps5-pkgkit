"""The PS5 ``\\x7fFLT`` flat-path table: path hash, entry packing and writer.

Both image layers index their files with a 64-bit hash of the ASCII-uppercased
path with its leading slash stripped. The hash is a three-lane sponge with fixed
seeds; the table is a 0x40-byte header followed by 16-byte entries sorted by
hash.
"""

from __future__ import annotations

from collections.abc import Iterable

SEED0 = 0x92CA8AAB26A24F51
SEED1 = 0x09BBB761A41BC44D
ROUND_CONST = 0x8000000080008081
MASK64 = (1 << 64) - 1

HEADER_LEN = 0x40
ENTRY_LEN = 16
HEADER_SEED = bytes(
    [0x51, 0x4F, 0xA2, 0x26, 0xAB, 0x8A, 0xCA, 0x92,
     0x4D, 0xC4, 0x1B, 0xA4, 0x61, 0xB7, 0xBB, 0x09]
)

#: Flat-path-table bit for a zero-length file.
FLAG_EMPTY = 0x20000000


def _rotl(value: int, count: int) -> int:
    """Rotate a 64-bit word left by the given bit count."""
    count &= 63
    return ((value << count) | (value >> (64 - count))) & MASK64


def _rotr(value: int, count: int) -> int:
    """Rotate a 64-bit word right by the given bit count."""
    count &= 63
    return ((value >> count) | (value << (64 - count))) & MASK64


def _ascii_upper(data: bytes) -> bytes:
    """Uppercase ASCII lowercase bytes, preserving all other bytes."""
    return bytes(byte - 32 if 0x61 <= byte <= 0x7A else byte for byte in data)


def hash_bytes(data: bytes) -> int:
    """Compute the raw three-lane sponge hash of the supplied bytes."""
    s0 = SEED0
    s1 = _rotl(SEED0, 11)
    s2 = _rotl(SEED0, 23)
    tail = 0
    if data:
        words = (len(data) - 1) >> 3
        a0, a1, a2 = s0, s1, s2
        offset = 0
        for _ in range(words):
            a0 ^= int.from_bytes(data[offset:offset + 8], "little")
            offset += 8
            t18 = _rotr(_rotl(a2 ^ a1, 5) ^ a0, 11)
            t12 = _rotl(_rotl(a2 ^ a0, 17) ^ a1, 11)
            a2 = _rotr(_rotl(a1 ^ a0, 1) ^ a2, 5)
            a0 = ((~t12 & MASK64) & a2) ^ t18 ^ ROUND_CONST
            a1 = ((~a2 & MASK64) & t18) ^ t12
            a2 ^= (~t18 & MASK64) & t12
            a0 &= MASK64
            a1 &= MASK64
            a2 &= MASK64
        s0, s1, s2 = a0, a1, a2
        tail = int.from_bytes(data[offset:] + bytes(8 - (len(data) - offset)), "little")
    u16 = s1
    u11 = s2
    u6 = (tail ^ s0 ^ SEED1) & MASK64
    u17 = (_rotl(u11 ^ u16, 5) ^ u6) & MASK64
    u18 = (_rotl(u11 ^ u6, 17) ^ u16) & MASK64
    u11 = (_rotl(u16 ^ u6, 1) ^ u11) & MASK64
    return ((~ _rotl(u18, 11) & MASK64) & _rotr(u11, 5)) ^ _rotr(u17, 11) ^ ROUND_CONST


def hash_path(path: str) -> int:
    """Compute a flat-path-table hash from a package path.

    Args:
        path: Path to normalize by removing one leading slash and uppercasing
            ASCII characters after UTF-8 encoding.

    Returns:
        Unsigned 64-bit path hash.
    """
    if path.startswith("/"):
        path = path[1:]
    return hash_bytes(_ascii_upper(path.encode("utf-8")))


def pack_inode_entry(inode: int, is_dir: bool, is_subtree: bool, afid: int) -> int:
    """Pack an inode flat-path-table payload.

    The inode occupies the low 24 bits. Bits 30 and 31 mark a directory and an
    entry outside the top-level APR set, respectively.

    Args:
        inode: Inode number.
        is_dir: Whether the entry represents a directory.
        is_subtree: Whether the entry is outside the top-level APR set.
        afid: Application file ID to store for a regular file.

    Returns:
        Packed inode, flags, and application file ID.
    """
    packed = inode & 0xFF_FFFF
    if is_dir:
        packed |= 0x4000_0000
        packed |= 0xFF_FFFF << 40
    else:
        packed |= (afid & 0xFF_FFFF) << 40
    if is_subtree:
        packed |= 0x8000_0000
    return packed


def pack_apr_entry(uncompressed_size: int, afid: int) -> int:
    """Pack an APR flat-path-table payload.

    Args:
        uncompressed_size: File size in bytes, stored in the low 40 bits.
        afid: Application file ID, stored in the upper 24 bits.

    Returns:
        Packed file size and application file ID.
    """
    return (uncompressed_size & 0xFF_FFFF_FFFF) | ((afid & 0xFF_FFFF) << 40)


def write(entries: Iterable[tuple[int, int]]) -> bytes:
    """Serialize a flat-path table in ascending hash order.

    Args:
        entries: Iterable of (path hash, packed payload) pairs.

    Returns:
        Table header followed by the 16-byte entry records.
    """
    ordered = sorted(entries, key=lambda entry: entry[0])
    output = bytearray(HEADER_LEN + len(ordered) * ENTRY_LEN)
    output[0:4] = (1).to_bytes(4, "little")
    output[4] = ENTRY_LEN
    output[8:12] = HEADER_LEN.to_bytes(4, "little")
    output[0x20:0x24] = b"\x7fFLT"
    output[0x2C:0x30] = len(ordered).to_bytes(4, "little")
    output[0x30:0x40] = HEADER_SEED
    for index, (path_hash, packed) in enumerate(ordered):
        at = HEADER_LEN + index * ENTRY_LEN
        output[at:at + 8] = path_hash.to_bytes(8, "little")
        output[at + 8:at + 16] = packed.to_bytes(8, "little")
    return bytes(output)
