"""Exercise Kraken block and Huffman round trips with synthetic inputs."""

import unittest
from unittest.mock import patch

from ps5_pkgkit.format import kraken, kraken_compress


def text_data(size):
    """Repeat a fixed text pattern to the requested length.

    Args:
        size: Integer number of bytes to generate.

    Returns:
        A byte string with exactly that length.
    """
    pattern = b"entry: the quick brown fox jumps over the lazy dog\n"
    return (pattern * (size // len(pattern) + 1))[:size]


def records(size):
    """Create deterministic structured data for compression tests.

    Args:
        size: Integer number of bytes to generate.

    Returns:
        The generated record stream truncated to that length.
    """
    data = bytearray()
    index = 0
    while len(data) < size:
        data += (index * 3).to_bytes(4, "little")
        data += (1000 + index // 7).to_bytes(4, "little")
        data += bytes([index % 5, 0x40, 0, 0])
        index += 1
    return bytes(data[:size])


class KrakenRoundTripTests(unittest.TestCase):
    """Compare decoded bytes with the original across compression modes."""
    def _roundtrip(self, data, level):
        """Check exact decoding and measure the stored payload lengths.

        Args:
            data: Original uncompressed block as bytes.
            level: Encoder preset name as a string.

        Returns:
            Combined stored byte length of the halves.
        """
        halves = kraken.encode_block_at(data, level)
        self.assertEqual(kraken.decode_block(halves, len(data)), data)
        return sum(len(half.data) for half in halves)

    def test_text_compresses_at_every_level(self):
        """Require the text fixture to shrink at each compression preset."""
        data = text_data(4096)
        for level in ("fast", "balanced", "smallest"):
            stored = self._roundtrip(data, level)
            self.assertLess(stored, len(data), level)

    def test_structured_records_round_trip(self):
        """Reconstruct synthetic records at fast and balanced settings."""
        data = records(8192)
        for level in ("fast", "balanced"):
            self._roundtrip(data, level)

    def test_raw_noise_round_trips(self):
        """Reconstruct a deterministic byte pattern with the fast encoder."""
        data = bytes((index * 131 + 17) % 251 for index in range(3333))
        halves = kraken.encode_block_at(data, "fast")
        self.assertEqual(kraken.decode_block(halves, len(data)), data)

    def test_parallel_blocks_match_in_serial_order(self):
        """Compare enough distinct blocks to fill and drain the worker queue."""
        blocks = [({"logical": i * 4096}, bytes([i]) * 4096) for i in range(9)]
        with patch.object(kraken_compress, "ProcessPoolExecutor") as pool:
            serial = list(kraken_compress._encoded_blocks(blocks, "fast", 1))
            pool.assert_not_called()
        parallel = list(kraken_compress._encoded_blocks(blocks, "fast", 2))
        self.assertEqual(parallel, serial)

    def test_raw_half_decodes(self):
        """Decode an explicitly stored raw half as an unchanged payload."""
        data = bytes(range(64))
        halves = [kraken.Half("raw", data)]
        self.assertEqual(kraken.decode_block(halves, 64), data)

    def test_traditional_offsets_match_the_reference_formula(self):
        """Reconstruct several match distances from their split encodings."""
        for distance in (8, 9, 15, 16, 100, 1000, 99999):
            code, extra, bits = kraken.traditional_offset(distance)
            self.assertLess(code, 0xF0)
            self.assertEqual(bits, (code >> 4) + 4)
            restored = (((1 << bits) | extra) << 4) + (code & 0xF) - 248
            self.assertEqual(restored, distance)


class HuffmanTests(unittest.TestCase):
    """Check Kraken entropy coding separately from LZ block compression."""
    def test_encode_decode_round_trip(self):
        """Reconstruct a mixed-frequency array from its Huffman payload."""
        data = (b"A" * 400 + b"BC" * 150 + bytes(range(32, 96)) * 4)
        body = kraken.huff_encode(data)
        self.assertIsNotNone(body)
        self.assertEqual(kraken.huff_decode(body, len(data)), data)

    def test_short_arrays_stay_raw(self):
        """Check that the encoder declines a 100-byte repeated array."""
        self.assertIsNone(kraken.huff_encode(b"x" * 100))


if __name__ == "__main__":
    unittest.main()
