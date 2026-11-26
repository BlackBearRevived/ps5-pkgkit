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
    return hashlib.sha3_256(data).digest()


def sha3_file(path) -> bytes:
    digest = hashlib.sha3_256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.digest()


def hmac_sha256(key: bytes, *parts: bytes) -> bytes:
    mac = _hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.digest()


def derive_pfs_key(content_id: str, passcode: str, index: int) -> bytes:
    """``SHA3(SHA3(index as BE32) ‖ SHA3(content id padded to 48) ‖ passcode)``."""
    padded = content_id.encode("utf-8")[:48].ljust(48, b"\0")
    return sha3(sha3(index.to_bytes(4, "big")) + sha3(padded) + passcode.encode("utf-8"))


def derive_ekpfs(content_id: str, passcode: str) -> bytes:
    """The PFS image key for a debug package."""
    return derive_pfs_key(content_id, passcode, 1)


def derive_xts_keys(ekpfs: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """``(tweak key, data key)`` for an image with this superblock seed."""
    step = hmac_sha256(ekpfs, seed)
    derived = hmac_sha256(step, (1).to_bytes(4, "little"), seed)
    return derived[:16], derived[16:]


def encrypt_entry(row: bytes, entry_key: bytes, data: bytes) -> bytes:
    """Encrypt a protected container entry: AES-128-CBC with key/iv from SHA3(row ‖ key)."""
    if len(row) != 32 or len(entry_key) != 32 or len(data) % 16:
        raise ValueError("protected entry shapes are fixed")
    material = sha3(row + entry_key)
    return cbc_encrypt(material[16:], material[:16], data)


def _crc32c_table() -> list[int]:
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ 0x82F63B78 if value & 1 else value >> 1
        table.append(value & 0xFFFFFFFF)
    return table


_CRC32C = _crc32c_table()


def crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), as the PlayGo chunk CRC table stores it."""
    value = 0xFFFFFFFF
    for byte in data:
        value = _CRC32C[(value ^ byte) & 0xFF] ^ (value >> 8)
    return value ^ 0xFFFFFFFF


def crc32(data: bytes) -> int:
    """The classic ZIP member CRC."""
    return zlib.crc32(data) & 0xFFFFFFFF
