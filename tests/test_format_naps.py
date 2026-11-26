"""Test layout records with a Kraken reference and a stored-image plan."""

import os
from pathlib import Path
import unittest

from ps5_pkgkit.format import constants as c
from ps5_pkgkit.format import naps

DEFAULT = Path(__file__).resolve().parents[1] / ".artifacts" / "hello-world"
FIXTURE = Path(os.environ.get("PS5_PKGKIT_REFERENCE", DEFAULT))
PACKAGE = FIXTURE / "PS5-PKG-Hello-World.pkg"


@unittest.skipUnless(PACKAGE.is_file(), "reference package is not available")
class ReferenceNapsTests(unittest.TestCase):
    """Round-trip checks for the reference package's layout records.

    Attributes:
        blob: Serialized descriptor extracted from the fixture.
        layout: Parsed descriptor for the current test.
    """
    def setUp(self):
        """Extract and parse the layout descriptor from the reference image."""
        package = PACKAGE.read_bytes()
        self.blob = package[0x20000:0x20000 + 0x190]
        self.layout = naps.parse(self.blob)

    def test_header_fields(self):
        """Match the reference file count, compression mode, and unit count."""
        layout = self.layout
        self.assertEqual(layout.num_files, 8)
        self.assertEqual(layout.compression_type, naps.COMP_KRAKEN)
        self.assertEqual(layout.num_ublocks, 23)
        self.assertEqual(layout.num_outer_blocks, 1)
        self.assertEqual(len(layout.cblocks), 32)
        self.assertEqual(layout.mount_size, 0x5B0000)

    def test_every_record_reencodes_to_its_bytes(self):
        """Compare each parsed block record with its exact nine-byte source."""
        at = len(self.blob) - len(self.layout.cblocks) * naps.CBLOCK_LEN
        for record in self.layout.cblocks:
            raw = self.blob[at:at + naps.CBLOCK_LEN]
            self.assertEqual(naps.encode_cblock(record), raw)
            at += naps.CBLOCK_LEN


class NapsBuildTests(unittest.TestCase):
    """Validate the descriptor emitted for a stored inner image."""
    def test_stored_layout_round_trips(self):
        """Check parsed geometry and terminator from a known stored layout."""
        files = [
            (0, 0x00000, 96),
            (96, 0x10000, 895),
            (991, 0x20000, 16547),
            (17538, 0x30000, 18),
            (17556, 0x40000, 1284682),
        ]
        blob = naps.build(0x5B0000, 0x5B, files, 0x180000, 0x500000)
        layout = naps.parse(blob)
        self.assertEqual(layout.mount_size, 0x5B0000)
        self.assertEqual(layout.num_ublocks, 23)
        self.assertEqual(layout.num_outer_blocks, 91)
        self.assertEqual(len(layout.fidx), len(files) + 3)
        self.assertEqual(layout.fidx[-1][1], naps.FIDX_TYPE_MOUNT_END)
        self.assertEqual(layout.cblocks[-1].reserved19, True)
        self.assertEqual(layout.u2c_count(23), len(layout.u2c))


if __name__ == "__main__":
    unittest.main()
