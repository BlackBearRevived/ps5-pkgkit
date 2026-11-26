"""Pure-Python AES-128, with the CBC and XTS modes PS5 packages use.

Packages encrypt a metadata region (AES-XTS, one 64 KiB block per data unit)
and a few protected container entries (AES-128-CBC). Both are whole 16-byte
blocks here, so no ciphertext stealing is needed.
"""

from __future__ import annotations


def _build_sbox() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inverse = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        p &= 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        value = (q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6))
                 ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))) & 0xFF
        sbox[p] = value ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    for index, value in enumerate(sbox):
        inverse[value] = index
    return sbox, inverse


_SBOX, _INV_SBOX = _build_sbox()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(value: int) -> int:
    value <<= 1
    return (value ^ 0x1B) & 0xFF if value & 0x100 else value


def _mul(value: int, factor: int) -> int:
    result = 0
    for bit in range(8):
        if factor & (1 << bit):
            result ^= value
        value = _xtime(value)
    return result


class Aes128:
    """AES-128 block cipher (FIPS-197)."""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 needs a 16-byte key")
        words = [list(key[index:index + 4]) for index in range(0, 16, 4)]
        for index in range(4, 44):
            word = list(words[index - 1])
            if index % 4 == 0:
                word = word[1:] + word[:1]
                word = [_SBOX[value] for value in word]
                word[0] ^= _RCON[index // 4 - 1]
            words.append([a ^ b for a, b in zip(word, words[index - 4])])
        self._round_keys = [bytes(sum(words[4 * r:4 * r + 4], [])) for r in range(11)]

    def _add_round_key(self, state: list[int], round_number: int) -> None:
        key = self._round_keys[round_number]
        for index in range(16):
            state[index] ^= key[index]

    @staticmethod
    def _shift_rows(state: list[int]) -> None:
        state[:] = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]

    @staticmethod
    def _inverse_shift_rows(state: list[int]) -> None:
        state[:] = [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3],
        ]

    @staticmethod
    def _mix_columns(state: list[int]) -> None:
        for column in range(4):
            at = 4 * column
            a0, a1, a2, a3 = state[at:at + 4]
            state[at] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
            state[at + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
            state[at + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
            state[at + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)

    @staticmethod
    def _inverse_mix_columns(state: list[int]) -> None:
        for column in range(4):
            at = 4 * column
            a0, a1, a2, a3 = state[at:at + 4]
            state[at] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
            state[at + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
            state[at + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
            state[at + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, 0)
        for round_number in range(1, 10):
            state = [_SBOX[value] for value in state]
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round_number)
        state = [_SBOX[value] for value in state]
        self._shift_rows(state)
        self._add_round_key(state, 10)
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, 10)
        for round_number in range(9, 0, -1):
            self._inverse_shift_rows(state)
            state = [_INV_SBOX[value] for value in state]
            self._add_round_key(state, round_number)
            self._inverse_mix_columns(state)
        self._inverse_shift_rows(state)
        state = [_INV_SBOX[value] for value in state]
        self._add_round_key(state, 0)
        return bytes(state)


def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("CBC data must be whole 16-byte blocks")
    cipher = Aes128(key)
    output = bytearray()
    previous = iv
    for at in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[at:at + 16], previous))
        previous = cipher.encrypt_block(block)
        output += previous
    return bytes(output)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("CBC data must be whole 16-byte blocks")
    cipher = Aes128(key)
    output = bytearray()
    previous = iv
    for at in range(0, len(data), 16):
        stored = data[at:at + 16]
        block = cipher.decrypt_block(stored)
        output += bytes(a ^ b for a, b in zip(block, previous))
        previous = stored
    return bytes(output)


def _xts_double(tweak: bytearray) -> None:
    carry = tweak[15] >> 7
    for index in range(15, 0, -1):
        tweak[index] = ((tweak[index] << 1) | (tweak[index - 1] >> 7)) & 0xFF
    tweak[0] = ((tweak[0] << 1) & 0xFF) ^ (0x87 if carry else 0)


class Xts:
    """AES-128-XTS for one data unit (IEEE 1619), as PFS images use it."""

    def __init__(self, data_key: bytes, tweak_key: bytes):
        self._data = Aes128(data_key)
        self._tweak = Aes128(tweak_key)

    def _start_tweak(self, sector: int) -> bytearray:
        block = sector.to_bytes(8, "little") + bytes(8)
        return bytearray(self._tweak.encrypt_block(block))

    def _apply(self, sector: int, data: bytes, *, encrypt: bool) -> bytes:
        if not data or len(data) % 16:
            raise ValueError("XTS data unit must be a non-zero multiple of 16 bytes")
        tweak = self._start_tweak(sector)
        output = bytearray()
        for at in range(0, len(data), 16):
            mixed = bytes(a ^ b for a, b in zip(data[at:at + 16], tweak))
            transformed = (self._data.encrypt_block(mixed) if encrypt
                           else self._data.decrypt_block(mixed))
            output += bytes(a ^ b for a, b in zip(transformed, tweak))
            _xts_double(tweak)
        return bytes(output)

    def encrypt(self, sector: int, data: bytes) -> bytes:
        return self._apply(sector, data, encrypt=True)

    def decrypt(self, sector: int, data: bytes) -> bytes:
        return self._apply(sector, data, encrypt=False)
