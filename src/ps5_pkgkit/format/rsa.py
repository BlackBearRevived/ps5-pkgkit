"""PKCS#1 v1.5 encryption under a big-endian modulus, exponent 65537.

The padding is deterministic (``00 02 FF...FF 00 message``), so an identically
built package is byte-identical.
"""

from __future__ import annotations

E = 65537


def pkcs1_encrypt(modulus: bytes, message: bytes) -> bytes:
    size = len(modulus)
    if size < 11 or len(message) + 11 > size:
        raise ValueError("message does not fit the modulus")
    block = bytearray(size)
    block[1] = 0x02
    block[2:size - len(message) - 1] = b"\xff" * (size - len(message) - 3)
    block[size - len(message):] = message
    value = pow(int.from_bytes(block, "big"), E, int.from_bytes(modulus, "big"))
    return value.to_bytes(size, "big")
