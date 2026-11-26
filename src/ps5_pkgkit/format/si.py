"""Serialize the install-metadata CRC table, metrics, and stored ZIP."""

from __future__ import annotations

import struct

from .aes import Xts
from .constants import BLOCK
from .crypto import crc32c, sha3
from .keys import (
    NAPS_META_18_DATA_KEY,
    NAPS_META_18_TWEAK_KEY,
    NAPS_META_18_TWEAK_SECTOR,
)

FIXED_DATE = (1980, 1, 1, 0, 0, 0)


def chunk_crc(mount_image: bytes) -> bytes:
    """Compute the PlayGo CRC table for the mount image.

    Args:
        mount_image: Finalized-image header, outer image, and container
            concatenated.

    Returns:
        Little-endian CRC-32C values for successive 64 KiB blocks, including any
        trailing partial block.
    """
    blocks = (len(mount_image) + BLOCK - 1) // BLOCK
    output = bytearray(blocks * 4)
    for index in range(blocks):
        at = index * BLOCK
        output[index * 4:index * 4 + 4] = crc32c(
            mount_image[at:min(at + BLOCK, len(mount_image))]).to_bytes(4, "little")
    return bytes(output)


def naps_meta_300(inner_size: int) -> bytes:
    """Build a fixed-size NAPS mount metadata record.

    Args:
        inner_size: Logical inner-image size in bytes.

    Returns:
        The 48-byte record shared by the 300, 301, 302, and 308 members.
    """
    r = max(inner_size - BLOCK, 0)
    data = bytearray(48)
    data[0x10:0x18] = r.to_bytes(8, "little")
    data[0x18:0x20] = (0x3E9).to_bytes(8, "little")
    data[0x20:0x28] = r.to_bytes(8, "little")
    data[0x28:0x30] = BLOCK.to_bytes(8, "little")
    return bytes(data)


def _dos_time(date_time: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    """Pack a ZIP timestamp into DOS time and date fields, in that order."""
    year, month, day, hour, minute, second = date_time
    return ((hour << 11) | (minute << 5) | (second // 2),
            ((year - 1980) << 9) | (month << 5) | day)


def zip_members(members: list[tuple[str, bytes]],
                date_time: tuple[int, int, int, int, int, int] | None = None) -> bytes:
    """Serialize an uncompressed ZIP archive in the given member order.

    Args:
        members: Filename and payload pairs in archive order.
        date_time: Optional (year, month, day, hour, minute, second) used for
            every member. Uses the fixed default timestamp when omitted.

    Returns:
        Complete ZIP archive bytes.
    """
    from .crypto import crc32

    stamp = date_time or FIXED_DATE
    time_field, date_field = _dos_time(stamp)
    output = bytearray()
    directory = bytearray()
    for name, data in members:
        encoded = name.encode("utf-8")
        checksum = crc32(data)
        offset = len(output)
        output += struct.pack(
            "<4s5H3I2H", b"PK\x03\x04", 20, 0, 0, time_field, date_field,
            checksum, len(data), len(data), len(encoded), 0)
        output += encoded
        output += data
        directory += struct.pack(
            "<4s6H3I5H2I", b"PK\x01\x02", 0, 20, 0, 0, time_field, date_field,
            checksum, len(data), len(data), len(encoded), 0, 0, 0, 0, 0, offset)
        directory += encoded
    directory_at = len(output)
    output += directory
    output += struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, len(members),
                          len(members), len(directory), directory_at, 0)
    return bytes(output)


def _tlv(tag: bytes, payload: bytes) -> bytes:
    """Pack a four-byte tag, length, and payload as one metric record."""
    return bytes([tag[3], tag[2], tag[1], tag[0], 1, 0, 0, 0]) + \
        len(payload).to_bytes(8, "little") + payload


def _block_map(files: list[tuple[str, int, int]], data_end: int,
               meta_base: int, mount_size: int):
    """Build metric block records for the stored inner image.

    Args:
        files: Triples of file path, logical byte offset, and size in AFID
            order.
        data_end: Logical byte position at the end of file data.
        meta_base: Starting byte position of the metadata region.
        mount_size: Logical size of the mount in bytes.

    Returns:
        Metric block tuples for file data, padding, and metadata.
    """
    blocks = []
    for index, (_, offset, size) in enumerate(files):
        blocks.append((offset, size, size, size, 0, 0x40090000, index, offset))
    at = (data_end + 0x3FFFF) // 0x40000 * 0x40000
    while at < meta_base:
        size = min(0x40000, meta_base - at)
        blocks.append((at, size, size, size, 0, 0x40110000, None, at))
        at += 0x40000
    at = meta_base
    while at < mount_size:
        size = min(0x40000, mount_size - at)
        blocks.append((at, size, size, size, 0, 0x40050000, None, at))
        at += 0x40000
    return blocks


def naps_meta_18(stored_size: int, mount_size: int, block_digests: list[bytes],
                 file_digests: list[bytes], meta: bytes,
                 files: list[tuple[str, int, int]], data_end: int, meta_base: int,
                 game_digest: bytes, blocks=None) -> bytes:
    """Build the encrypted NAPS metric stream for install metadata.

    Args:
        stored_size: Stored inner-image length in bytes.
        mount_size: Logical mount length in bytes.
        block_digests: Digests of stored blocks, in block order.
        file_digests: File payload digests in AFID order.
        meta: Plaintext inner-image metadata bytes.
        files: Triples of path, logical offset, and size in AFID order.
        data_end: Logical byte offset at the end of file data.
        meta_base: Logical byte offset of the metadata region.
        game_digest: Digest of the outer superblock.
        blocks (list of tuples or None): Optional prepared metric block map,
            otherwise derived from the stored layout.

    Returns:
        The TLV stream encrypted as one AES-128-XTS data unit.

    Raises:
        ValueError: The assembled stream is not aligned to a whole AES block.
    """
    output = bytearray()
    inner_blocks = (stored_size + BLOCK - 1) // BLOCK
    phdr = b"".join(value.to_bytes(4, "little")
                    for value in (1, 0x30, inner_blocks, 0x40000, 1, BLOCK))
    output += _tlv(b"phdr", phdr)

    meta_len = mount_size - meta_base
    body = bytearray()
    for index, (_, _, size) in enumerate(files):
        body += size.to_bytes(8, "little")
        body += index.to_bytes(4, "little")
        body += (1).to_bytes(4, "little")
        body += (0).to_bytes(4, "little")
        body += (0 if index == 0 else 1).to_bytes(4, "little")
    body += meta_len.to_bytes(8, "little")
    body += len(files).to_bytes(4, "little")
    body += (3).to_bytes(4, "little")
    body += (0x3E9).to_bytes(4, "little")
    body += (0).to_bytes(4, "little")
    output += _tlv(b"file", bytes(body))

    if blocks is None:
        blocks = _block_map(files, data_end, meta_base, mount_size)
    output += _tlv(b"ibcl", bytes(
        0x01 if owner is not None and owner > 0 else 0x0F
        for _, _, _, _, _, _, owner, _ in blocks))

    i2ob = bytearray()
    i2op = bytearray()
    for co, cs, ps, c0, c1, flag, _, _ in blocks:
        i2ob += co.to_bytes(8, "little")
        for value in (cs, ps, c0, c1, co >> 16, 0, 1, flag):
            i2ob += value.to_bytes(4, "little")
        i2op += co.to_bytes(8, "little")
        i2op += (co >> 16).to_bytes(4, "little")
        i2op += (0).to_bytes(4, "little")
    output += _tlv(b"i2ob", bytes(i2ob))
    output += _tlv(b"i2op", bytes(i2op))

    zeros = bytes(0x40000)
    ihsh = bytearray()
    for _, _, ps, _, _, flag, owner, logical in blocks:
        if flag == 0x40110000:
            digest = sha3(zeros[:ps])
        elif owner is not None:
            digest = file_digests[owner]
        else:
            at = max(logical - meta_base, 0)
            span = meta[at:at + ps]
            digest = sha3(span if len(span) == ps else zeros[:ps])
        ihsh += (0).to_bytes(4, "little")
        ihsh += ps.to_bytes(4, "little")
        ihsh += digest
        ihsh += ((0x3E9 if flag & 0x400000 else 0)).to_bytes(8, "little")
    output += _tlv(b"ihsh", bytes(ihsh))

    rhsh = bytearray(0xB0)
    rhsh[:32] = game_digest
    output += _tlv(b"rhsh", bytes(rhsh))

    fstr = bytearray()
    for path, _, _ in files:
        fstr += path.encode("utf-8") + b"\x00"
    fstr += b"*PFSmetadata\x00"
    output += _tlv(b"fstr", bytes(fstr))

    twek = bytearray(0x14)
    twek[0x04] = 4
    output += _tlv(b"twek", bytes(twek))

    output += _tlv(b"obdg", b"".join(block_digests))

    descriptor = naps_meta_300(mount_size)
    for tag in (b"pgpl", b"pgil", b"pgpi", b"pgpu"):
        output += _tlv(tag, descriptor)
    output += _tlv(b"zero", bytes((16 - len(output) % 16) % 16))
    if len(output) % 16:
        raise ValueError("naps_meta_18 plaintext is not a multiple of 16 bytes")
    return Xts(NAPS_META_18_DATA_KEY, NAPS_META_18_TWEAK_KEY).encrypt(
        NAPS_META_18_TWEAK_SECTOR, bytes(output))


def kraken_blocks(image) -> list[tuple]:
    """Build metric block records for a Kraken-compressed image.

    Args:
        image (KrakenImage): Compressed image with its block descriptors.

    Returns:
        One metric block tuple per stored block, in image order.
    """
    blocks = []
    for block in image.blocks:
        compressed = any(is_lz for _, is_lz in block.halves)
        if compressed:
            flag = 0x40050000
        elif block.owner_kind == "gap":
            flag = 0x40110000
        elif block.owner_kind == "meta":
            flag = 0x40050000
        else:
            flag = 0x40090000
        odd = block.halves[1][0] if len(block.halves) > 1 else 0
        blocks.append((block.stored_at, block.stored_len, block.length,
                       block.halves[0][0], odd, flag, block.owner, block.logical))
    return blocks


def kraken_meta_18(image, mount_size: int, metadata_plain: bytes,
                   files: list[tuple[str, int, int]], game_digest: bytes) -> bytes:
    """Build the NAPS metric stream for a compressed image.

    Args:
        image (KrakenImage): Compressed image and its stored block layout.
        mount_size: Logical mount length in bytes.
        metadata_plain: Plaintext inner-image metadata.
        files: Triples of path, logical offset, and size in AFID order.
        game_digest: Digest of the outer superblock.

    Returns:
        Encrypted NAPS metric stream bytes.
    """
    from .crypto import sha3 as digest

    block_digests = [digest(image.image[at:at + BLOCK])
                     for at in range(0, len(image.image), BLOCK)]
    return naps_meta_18(image.image_len, mount_size, block_digests,
                        image.file_digests, metadata_plain, files,
                        image.data_end, image.meta_base, game_digest,
                        blocks=kraken_blocks(image))


def parse_meta_18(blob: bytes) -> list[tuple[bytes, bytes]]:
    """Decrypt and read the NAPS metric stream.

    Args:
        blob: Encrypted contents of naps_meta_18.dat.

    Returns:
        Pairs of raw tag and payload bytes, in record order.

    Raises:
        ValueError: The encrypted data unit has an invalid length or a TLV
            header is truncated.
    """
    plain = Xts(NAPS_META_18_DATA_KEY, NAPS_META_18_TWEAK_KEY).decrypt(
        NAPS_META_18_TWEAK_SECTOR, blob)
    records = []
    at = 0
    while at < len(plain):
        if at + 16 > len(plain):
            raise ValueError("truncated TLV header")
        tag = bytes(reversed(plain[at:at + 4]))
        length = int.from_bytes(plain[at + 8:at + 16], "little")
        start = at + 16
        records.append((tag, plain[start:start + length]))
        at = start + length
    return records
