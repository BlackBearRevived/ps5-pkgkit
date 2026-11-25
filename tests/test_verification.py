import hashlib
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from ps5_pkg import VerificationError, verify_package


class MalformedPackageTests(unittest.TestCase):
    def test_truncated_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.pkg"
            path.write_bytes(b"\x7fFIH")
            with self.assertRaisesRegex(VerificationError, "finalized-image header"):
                verify_package(path)

    def test_out_of_file_container_rejected_before_read(self):
        header = bytearray(256)
        header[:4] = b"\x7fFIH"
        struct.pack_into("<H", header, 6, 3)
        struct.pack_into("<QQ", header, 16, 256, 256)
        struct.pack_into("<Q", header, 88, (1 << 64) - 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "out-of-range.pkg"
            path.write_bytes(header)
            with self.assertRaisesRegex(VerificationError, "container header"):
                verify_package(path)


class HelloWorldReferenceTests(unittest.TestCase):
    expected_sha256 = "f4746fdf4c66f4e8f664ae5f50bd1ecdca2b741bc9e8647c7ca1070664abae09"

    @classmethod
    def setUpClass(cls):
        cls.reference = Path(os.environ.get(
            "PS5_PKG_REFERENCE",
            ".artifacts/hello-world/PS5-PKG-Hello-World.pkg",
        ))
        if not cls.reference.is_file():
            raise unittest.SkipTest("set PS5_PKG_REFERENCE to the verified Hello World reference")

    def test_verify_title_and_digest(self):
        result = verify_package(self.reference, expected_sha256=self.expected_sha256)
        self.assertTrue(result.expected_sha256_verified)
        self.assertEqual(result.title_id, "PPSA99771")
        self.assertEqual(result.content_version, "01.000.000")
        self.assertEqual(result.container_entries, 19)

    def test_reject_container_body_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corrupt.pkg"
            shutil.copyfile(self.reference, path)
            with path.open("r+b") as package:
                header = package.read(256)
                container, = struct.unpack_from("<Q", header, 88)
                package.seek(container + 32)
                body, body_size = struct.unpack(">QQ", package.read(16))
                position = container + body + body_size - 1
                package.seek(position)
                original = package.read(1)
                package.seek(position)
                package.write(bytes([original[0] ^ 1]))
            with self.assertRaisesRegex(VerificationError, "container body SHA3-256 mismatch"):
                verify_package(path)

    def test_reject_wrong_expected_digest(self):
        other_sha256 = hashlib.sha256(b"other package").hexdigest()
        with self.assertRaisesRegex(VerificationError, "package SHA-256 mismatch"):
            verify_package(self.reference, expected_sha256=other_sha256)
