import unittest

from ps5_pkgkit.format import fih
from ps5_pkgkit.format.constants import BLOCK
from ps5_pkgkit.format.crypto import sha3


class FihTests(unittest.TestCase):
    def test_header_carries_the_template_fields(self):
        naps = bytes([7]) * 104
        header = fih.write(fih.FihParams(
            outer_size=7 * BLOCK,
            superblock_block=2,
            game_digest=bytes([1]) * 32,
            cnt_offset=7 * BLOCK,
            naps=naps,
            inner_size=4 * BLOCK,
            meta_base=0x30000,
            inner_blocks=4,
            content_inodes=3,
            content_version=0x0100_1000,
            app_file_count=1,
            flt_count=1,
        ))
        self.assertEqual(len(header), BLOCK)
        self.assertEqual(header[0:5], b"\x7fFIH\x01")
        self.assertEqual(header[5], 0x00)
        self.assertEqual(header[6], 0x03)
        self.assertEqual(int.from_bytes(header[0x50:0x54], "little"), 3)
        self.assertEqual(int.from_bytes(header[0x58:0x60], "little"), 7 * BLOCK)
        self.assertEqual(header[0x30:0x50], bytes([1]) * 32)
        self.assertEqual(header[0xB0:0xD0], sha3(naps))
        self.assertEqual(int.from_bytes(header[0x20:0x28], "little"), 3 * BLOCK)

    def test_empty_regions_stay_zero(self):
        header = fih.write(fih.FihParams(
            outer_size=BLOCK, superblock_block=0, game_digest=bytes(32),
            cnt_offset=2 * BLOCK, naps=b"", inner_size=BLOCK, meta_base=0,
            inner_blocks=1, content_inodes=0, content_version=0,
            app_file_count=0, flt_count=1,
        ))
        self.assertEqual(header[0x38:0x50], bytes(0x18))


if __name__ == "__main__":
    unittest.main()
