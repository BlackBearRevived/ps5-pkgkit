import unittest

from ps5_pkgkit.format import kraken


def text_data(size):
    pattern = b"entry: the quick brown fox jumps over the lazy dog\n"
    return (pattern * (size // len(pattern) + 1))[:size]


def records(size):
    data = bytearray()
    index = 0
    while len(data) < size:
        data += (index * 3).to_bytes(4, "little")
        data += (1000 + index // 7).to_bytes(4, "little")
        data += bytes([index % 5, 0x40, 0, 0])
        index += 1
    return bytes(data[:size])


class KrakenRoundTripTests(unittest.TestCase):
    def _roundtrip(self, data, level):
        halves = kraken.encode_block_at(data, level)
        self.assertEqual(kraken.decode_block(halves, len(data)), data)
        return sum(len(half.data) for half in halves)

    def test_text_compresses_at_every_level(self):
        data = text_data(4096)
        for level in ("fast", "balanced", "smallest"):
            stored = self._roundtrip(data, level)
            self.assertLess(stored, len(data), level)

    def test_structured_records_round_trip(self):
        data = records(8192)
        for level in ("fast", "balanced"):
            self._roundtrip(data, level)

    def test_raw_noise_round_trips(self):
        data = bytes((index * 131 + 17) % 251 for index in range(3333))
        halves = kraken.encode_block_at(data, "fast")
        self.assertEqual(kraken.decode_block(halves, len(data)), data)

    def test_raw_half_decodes(self):
        data = bytes(range(64))
        halves = [kraken.Half("raw", data)]
        self.assertEqual(kraken.decode_block(halves, 64), data)

    def test_traditional_offsets_match_the_reference_formula(self):
        for distance in (8, 9, 15, 16, 100, 1000, 99999):
            code, extra, bits = kraken.traditional_offset(distance)
            self.assertLess(code, 0xF0)
            self.assertEqual(bits, (code >> 4) + 4)
            restored = (((1 << bits) | extra) << 4) + (code & 0xF) - 248
            self.assertEqual(restored, distance)


class HuffmanTests(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        data = (b"A" * 400 + b"BC" * 150 + bytes(range(32, 96)) * 4)
        body = kraken.huff_encode(data)
        self.assertIsNotNone(body)
        self.assertEqual(kraken.huff_decode(body, len(data)), data)

    def test_short_arrays_stay_raw(self):
        self.assertIsNone(kraken.huff_encode(b"x" * 100))


if __name__ == "__main__":
    unittest.main()
