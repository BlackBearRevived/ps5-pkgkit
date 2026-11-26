"""The debug license entries a package carries: ``license.dat`` and ``license.info``.

Both are pure functions of the content id. The RIF encrypts a key block with
the debug RIF key and signs its first 768 bytes with the debug RIF RSA key.
"""

from __future__ import annotations

import hashlib

from .aes import cbc_encrypt
from .keys import DEBUG_RIF_MODULUS, DEBUG_RIF_PRIVATE_EXPONENT, RIF_DEBUG_KEY

LICENSE_DAT_LEN = 1024
LICENSE_INFO_LEN = 512
APPLICATION = 32
PS5_DRM = 16

SHA256_DIGEST_INFO = bytes([
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
])


def _sign_sha256(digest: bytes) -> bytes:
    encoded = bytearray(b"\xff" * 256)
    encoded[0] = 0x00
    encoded[1] = 0x01
    at = 256 - len(SHA256_DIGEST_INFO) - len(digest)
    encoded[at - 1] = 0x00
    encoded[at:at + len(SHA256_DIGEST_INFO)] = SHA256_DIGEST_INFO
    encoded[at + len(SHA256_DIGEST_INFO):] = digest
    modulus = int.from_bytes(DEBUG_RIF_MODULUS, "big")
    exponent = int.from_bytes(DEBUG_RIF_PRIVATE_EXPONENT, "big")
    signature = pow(int.from_bytes(encoded, "big"), exponent, modulus).to_bytes(256, "big")
    return signature.rjust(256, b"\x00")


def license_dat(content_id: str, drm_type: int = PS5_DRM,
                content_type: int = APPLICATION) -> bytes:
    content = content_id.encode("ascii")
    data = bytearray(LICENSE_DAT_LEN)
    data[0:4] = b"RIF\0"
    data[4:8] = bytes([0x00, 0x01, 0xFF, 0xFF])
    data[20:32] = bytes([0x51, 0x50, 0x61, 0x43, 0x7F, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF])
    data[32:32 + len(content)] = content
    data[80:82] = (512).to_bytes(2, "big")
    data[82:84] = drm_type.to_bytes(2, "big")
    data[84:86] = content_type.to_bytes(2, "big")
    data[86:88] = (3).to_bytes(2, "big")
    data[103] = 1

    padded = content.ljust(48, b"\x00")
    digest = hashlib.sha256(padded).digest()
    block = bytearray(digest[16:32] + bytes(128))
    encrypted = cbc_encrypt(RIF_DEBUG_KEY, digest[:16], bytes(block))
    data[608:624] = digest[:16]
    data[624:768] = encrypted[:144]

    signature = _sign_sha256(hashlib.sha256(bytes(data[:768])).digest())
    data[768:1024] = signature
    return bytes(data)


def license_info(content_id: str, content_type: int = APPLICATION) -> bytes:
    content = content_id.encode("ascii")
    data = bytearray(LICENSE_INFO_LEN)
    data[:len(content)] = content
    data[68:72] = content_type.to_bytes(4, "big")
    data[76:80] = (1).to_bytes(4, "big")
    return bytes(data)
