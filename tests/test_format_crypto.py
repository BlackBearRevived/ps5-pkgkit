"""Check crypto and checksum primitives against known vectors."""

import unittest

from ps5_pkgkit.format import crypto
from ps5_pkgkit.format.aes import Aes128, Xts, cbc_decrypt, cbc_encrypt


class CryptoVectorTests(unittest.TestCase):
    """Check raw hashes, CRC polynomials, and package-derived keys."""
    def test_key_derivation_matches_the_reference_package(self):
        """Match the derived image, data, and tweak keys to the fixture."""
        ekpfs = crypto.derive_ekpfs(
            "EP7579-PPSA17599_00-EXP33DLC10000PS5", crypto.DEFAULT_PASSCODE
        )
        self.assertEqual(
            ekpfs.hex(),
            "6f2545336d611af09f15be54263809f1e2f0bc0062335e637463a9e7bee39b73",
        )
        seed = bytes.fromhex("3ace520f1ddbd3cb8acbc4543f95fba6")
        tweak, data = crypto.derive_xts_keys(ekpfs, seed)
        self.assertEqual(tweak.hex(), "04c9c2c17ea72b2be706be8ae56c9bff")
        self.assertEqual(data.hex(), "66cb5805c75c915a157f8ab9ccb80cab")

    def test_crc_check_values(self):
        """Distinguish Castagnoli CRC from ZIP CRC with known inputs."""
        self.assertEqual(crypto.crc32c(b"123456789"), 0xE3069283)
        self.assertEqual(crypto.crc32(b"123456789"), 0xCBF43926)
        self.assertEqual(crypto.crc32(b"hello"), 0x3610A686)

    def test_hmac_and_sha3_use_the_standard_algorithms(self):
        """Check SHA3 of empty input and HMAC of a short keyed message."""
        self.assertEqual(
            crypto.sha3(b"").hex(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
        self.assertEqual(
            crypto.hmac_sha256(b"key", b"data").hex(),
            "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0",
        )


class AesTests(unittest.TestCase):
    """Exercise single-block AES and the package's block modes."""
    def test_fips_197_block_vector(self):
        """Encrypt the FIPS 197 sample block and recover its plaintext."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = Aes128(key)
        encrypted = cipher.encrypt_block(plain)
        self.assertEqual(encrypted.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(cipher.decrypt_block(encrypted), plain)

    def test_cbc_round_trip(self):
        """Recover the original plaintext from a multi-block CBC stream."""
        key = bytes(range(16))
        iv = bytes(range(16, 32))
        data = bytes(index * 7 % 256 for index in range(160))
        encrypted = cbc_encrypt(key, iv, data)
        self.assertEqual(cbc_decrypt(key, iv, encrypted), data)
        self.assertNotEqual(encrypted, data)

    def test_xts_matches_the_reference_vector(self):
        """Check exact ciphertext and decoding for a two-block XTS unit."""
        xts = Xts(bytes(range(16)), bytes(range(16, 32)))
        encrypted = xts.encrypt(0, bytes(32))
        self.assertEqual(
            encrypted.hex(),
            "f071a2b402c105ea37024133e24d6ef6212e8cc0175e1b6b32657d54f159daf6",
        )
        self.assertEqual(xts.decrypt(0, encrypted), bytes(32))

    def test_xts_signed_sector_flag_is_part_of_the_tweak(self):
        """Compare reference ciphertext prefixes for both sector modes."""
        xts = Xts(bytes(range(16)), bytes(range(16, 32)))
        plain = bytes((index * 7) & 0xFF for index in range(0x10000))
        data = xts.encrypt(5, plain)
        signed = xts.encrypt(crypto.SIGNED_SECTOR_FLAG | 5, plain)
        self.assertEqual(data[:16].hex(), "7cd15324d71af9c318a1a7cd1cdf33e4")
        self.assertEqual(signed[:16].hex(), "20e0ed830c5b7fa7536743e0f93b91fb")


if __name__ == "__main__":
    unittest.main()
