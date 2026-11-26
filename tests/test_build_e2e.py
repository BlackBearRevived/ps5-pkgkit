"""Test package creation and verification with the Hello World fixture.

Use the staged title and reference package from the configured fixture
directory. The parity test reuses the reference ZIP timestamp.
"""

import hashlib
import io
import os
from pathlib import Path
import tempfile
import time
import unittest
import zipfile

from ps5_pkgkit import BuildError, build_package, verify_package

DEFAULT = Path(__file__).resolve().parents[1] / ".artifacts" / "hello-world"
FIXTURE = Path(os.environ.get("PS5_PKGKIT_REFERENCE", DEFAULT))
SOURCE = FIXTURE / "PPSA99771"
PACKAGE = FIXTURE / "PS5-PKG-Hello-World.pkg"


@unittest.skipUnless(SOURCE.is_dir(), "reference source folder is not available")
class BuildEndToEndTests(unittest.TestCase):
    """Exercise the uncompressed build path with a real staged title."""
    def test_builds_a_verifiable_package(self):
        """Check that the stored build verifies against its returned digest."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hello.pkg"
            result = build_package(SOURCE, output, kraken=False)
            self.assertTrue(output.is_file())
            self.assertEqual(result.title_id, "PPSA99771")
            self.assertEqual(result.content_version, "01.000.000")
            self.assertEqual(result.content_id, "UP9000-PPSA99771_00-PKGHELLOWORLD001")
            self.assertEqual(result.file_count, 5)
            self.assertTrue(any("repairing eboot.bin" in warning
                                for warning in result.warnings))
            verified = verify_package(output, expected_sha256=result.sha256)
            self.assertEqual(verified.title_id, "PPSA99771")
            self.assertEqual(verified.container_entries, 19)

    def test_content_id_override_is_applied(self):
        """Verify the override in the build result and the emitted container."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hello.pkg"
            result = build_package(
                SOURCE, output, kraken=False,
                content_id="UP9000-PPSA99771_00-PKGHELLOWORLD002")
            self.assertEqual(result.content_id, "UP9000-PPSA99771_00-PKGHELLOWORLD002")
            self.assertEqual(verify_package(output).content_id, result.content_id)

    def test_a_failed_build_leaves_no_output(self):
        """Reject a bad build without leaving the output or partial file."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hello.pkg"
            with self.assertRaises(BuildError):
                build_package(SOURCE, output, firmware="not-a-version")
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + ".partial").exists())


@unittest.skipUnless(PACKAGE.is_file() and SOURCE.is_dir(),
                     "reference artifacts are not available")
class ReferenceParityTest(unittest.TestCase):
    """Compare the compressed build against the reference byte stream."""
    def test_compressed_build_is_byte_identical(self):
        """Reuse the reference ZIP timestamp and compare SHA-256 and size."""
        data = PACKAGE.read_bytes()
        cnt_at = int.from_bytes(data[0x58:0x60], "little")
        si_at = cnt_at + int.from_bytes(data[cnt_at + 0x7C:cnt_at + 0x80], "big")
        archive = zipfile.ZipFile(io.BytesIO(data[si_at:]))
        year, month, day, hour, minute, second = archive.infolist()[0].date_time
        stamp = time.mktime((year, month, day, hour, minute, second, 0, 0, -1))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hello.pkg"
            result = build_package(SOURCE, output, timestamp=stamp)
            self.assertEqual(result.sha256, hashlib.sha256(data).hexdigest())
            self.assertEqual(result.size, len(data))


if __name__ == "__main__":
    unittest.main()
