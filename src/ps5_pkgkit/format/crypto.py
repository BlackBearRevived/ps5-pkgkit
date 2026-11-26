"""Hashes, key derivation and CRCs used by PS5 packages."""

from __future__ import annotations

import hashlib
import hmac as _hmac
import zlib

from . import keys
from .aes import cbc_encrypt

DEFAULT_PASSCODE = "00000000000000000000000000000000"

#: Set on the sector number of signed (metadata) blocks.
SIGNED_SECTOR_FLAG = 1 << 47


def sha3(data: bytes) -> bytes:
    """Compute the raw SHA3-256 digest of the input bytes."""
    return hashlib.sha3_256(data).digest()


def sha3_file(path) -> bytes:
    """Compute SHA3-256 over a file in chunks.

    Args:
        path (str or os.PathLike): Path of the file to hash.

    Returns:
        Raw SHA3-256 digest.

    Raises:
        OSError: The file cannot be opened or read.
    """
    digest = hashlib.sha3_256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.digest()


def hmac_sha256(key: bytes, *parts: bytes) -> bytes:
    """Compute an HMAC over the byte parts in the order supplied.

    Args:
        key: Raw HMAC key.
        *parts: Message parts to authenticate as one concatenated input.

    Returns:
        Raw SHA-256 HMAC digest.
    """
    mac = _hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.digest()


def derive_pfs_key(content_id: str, passcode: str, index: int) -> bytes:
    """Derive an indexed PFS key for a package.

    Args:
        content_id: Content identifier, encoded as UTF-8 and made 48 bytes wide.
        passcode: Passcode encoded as UTF-8.
        index: Unsigned 32-bit key index.

    Returns:
        Raw 32-byte PFS key.
    """
    padded = content_id.encode("utf-8")[:48].ljust(48, b"\0")
    return sha3(sha3(index.to_bytes(4, "big")) + sha3(padded) + passcode.encode("utf-8"))


def derive_ekpfs(content_id: str, passcode: str) -> bytes:
    """Derive the PFS image key for a debug package.

    Args:
        content_id: Package content identifier.
        passcode: Package passcode.

    Returns:
        Raw 32-byte PFS image key.
    """
    return derive_pfs_key(content_id, passcode, 1)


def derive_xts_keys(ekpfs: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """Derive the AES-XTS keys for an image.

    Args:
        ekpfs: Raw PFS image key.
        seed: Seed stored in the image superblock.

    Returns:
        Two 16-byte keys in (tweak key, data key) order.
    """
    step = hmac_sha256(ekpfs, seed)
    derived = hmac_sha256(step, (1).to_bytes(4, "little"), seed)
    return derived[:16], derived[16:]


def encrypt_entry(row: bytes, entry_key: bytes, data: bytes) -> bytes:
    """Encrypt a protected content-container entry.

    Args:
        row: Serialized 32-byte entry table row.
        entry_key: Raw 32-byte key for the entry.
        data: Entry payload padded to whole AES blocks.

    Returns:
        The encrypted payload, preserving the padded length.

    Raises:
        ValueError: The row, key, or payload length is invalid.
    """
    if len(row) != 32 or len(entry_key) != 32 or len(data) % 16:
        raise ValueError("protected entry shapes are fixed")
    material = sha3(row + entry_key)
    return cbc_encrypt(material[16:], material[:16], data)


def _crc32c_table() -> list[int]:
    """Generate the lookup table for the Castagnoli CRC."""
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ 0x82F63B78 if value & 1 else value >> 1
        table.append(value & 0xFFFFFFFF)
    return table


_CRC32C = _crc32c_table()


def crc32c(data: bytes) -> int:
    """Compute the unsigned Castagnoli CRC used by PlayGo chunks."""
    value = 0xFFFFFFFF
    for byte in data:
        value = _CRC32C[(value ^ byte) & 0xFF] ^ (value >> 8)
    return value ^ 0xFFFFFFFF


def crc32(data: bytes) -> int:
    """Compute the unsigned CRC-32 used for ZIP members."""
    return zlib.crc32(data) & 0xFFFFFFFF
