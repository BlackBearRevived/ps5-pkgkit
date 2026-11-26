"""Check flat-path hashing and serialization against sampled tables."""

import unittest

from ps5_pkgkit.format import flt


class FlatPathTableTests(unittest.TestCase):
    """Exercise raw hashing, path normalization, and inode entry packing."""
    def test_sample_path_hashes(self):
        """Match reference hashes for the two files in the outer image."""
        self.assertEqual(flt.hash_path("pfs_image.dat"), 0xA65627BDD8154701)
        self.assertEqual(flt.hash_path("naps_pkg_layout.dat"), 0xC683F67A1DECECAF)

    def test_path_is_uppercased_and_slash_stripped(self):
        """Compare the normalized and raw spellings of the same path."""
        self.assertEqual(flt.hash_path("/PFS_IMAGE.DAT"), flt.hash_path("pfs_image.dat"))

    def test_empty_and_short_inputs_terminate(self):
        """Check distinct hashes for zero-, one-, and two-byte inputs."""
        self.assertNotEqual(flt.hash_bytes(b""), flt.hash_bytes(b"a"))
        self.assertNotEqual(flt.hash_bytes(b"a"), flt.hash_bytes(b"ab"))

    def test_writes_the_samples_outer_table(self):
        """Compare the serialized outer table with the captured bytes."""
        table = flt.write([
            (flt.hash_path("pfs_image.dat"), flt.pack_inode_entry(3, False, False, 0)),
            (flt.hash_path("naps_pkg_layout.dat"),
             flt.pack_inode_entry(4, False, False, 1)),
        ])
        expected = (
            "0100000010000000400000000000000000000000000000000000000000000000"
            "7f464c54000000000000000002000000514fa226ab8aca924dc41ba461b7bb09"
            "014715d8bd2756a60300000000000000afecec1d7af683c60400000000010000"
        )
        self.assertEqual(table.hex(), expected)

    def test_inode_entry_packs_directory_and_subtree_bits(self):
        """Check both flags while preserving the low 24-bit inode number."""
        packed = flt.pack_inode_entry(7, True, True, 0)
        self.assertEqual(packed & 0xFF_FFFF, 7)
        self.assertTrue(packed & 0x4000_0000)
        self.assertTrue(packed & 0x8000_0000)
        self.assertEqual(packed >> 40, 0xFF_FFFF)
        self.assertEqual(flt.pack_apr_entry(0x1234, 9), 0x1234 | (9 << 40))


if __name__ == "__main__":
    unittest.main()
