import io
import os
from pathlib import Path
import unittest
import zipfile

from ps5_pkg.format import si

DEFAULT = Path("/mnt/c/Users/denis/Documents/PolarComet/ps5-pkg/.artifacts/hello-world")
FIXTURE = Path(os.environ.get("PS5_PKG_REFERENCE", DEFAULT))
PACKAGE = FIXTURE / "PS5-PKG-Hello-World.pkg"


@unittest.skipUnless(PACKAGE.is_file(), "reference package is not available")
class ReferenceMetaTests(unittest.TestCase):
    def test_tlv_stream_decrypts_and_parses(self):
        data = PACKAGE.read_bytes()
        cnt_at = 0x80000
        si_at = cnt_at + int.from_bytes(data[cnt_at + 0x7C:cnt_at + 0x80], "big")
        archive = zipfile.ZipFile(io.BytesIO(data[si_at:]))
        records = si.parse_meta_18(archive.read("common/etc/naps_meta_18.dat"))
        tags = [tag for tag, _ in records]
        self.assertEqual(tags, [
            b"phdr", b"file", b"ibcl", b"i2ob", b"i2op", b"ihsh", b"rhsh",
            b"fstr", b"twek", b"obdg", b"pgpl", b"pgil", b"pgpi", b"pgpu", b"zero",
        ])
        phdr = dict(records)[b"phdr"]
        self.assertEqual([int.from_bytes(phdr[at:at + 4], "little")
                          for at in range(0, 24, 4)],
                         [1, 0x30, 1, 0x40000, 1, 0x10000])
        names = dict(records)[b"fstr"].split(b"\x00")
        self.assertEqual(names[:5], [
            b"sce_sys/keystone", b"sce_sys/param.json", b"eboot.bin",
            b"assets/banner.txt", b"sce_module/libc.prx",
        ])
        self.assertEqual(len(dict(records)[b"obdg"]), 32)


class MetaBuildTests(unittest.TestCase):
    def test_built_stream_round_trips(self):
        files = [
            ("sce_sys/keystone", 0, 96),
            ("sce_sys/param.json", 96, 895),
            ("eboot.bin", 991, 16547),
            ("assets/banner.txt", 17538, 18),
            ("sce_module/libc.prx", 17556, 1284682),
        ]
        block_digests = [bytes([index]) * 32 for index in range(91)]
        file_digests = [bytes([index + 1]) * 32 for index in range(len(files))]
        meta = bytes(11 * 0x10000)
        blob = si.naps_meta_18(0x5B0000, 0x5B0000, block_digests, file_digests,
                               meta, files, 0x180000, 0x500000, bytes(32))
        self.assertEqual(len(blob) % 16, 0)
        records = dict(si.parse_meta_18(blob))
        phdr = records[b"phdr"]
        self.assertEqual(int.from_bytes(phdr[8:12], "little"), 91)
        self.assertEqual(len(records[b"obdg"]), 91 * 32)
        self.assertEqual(records[b"fstr"].split(b"\x00")[-2], b"*PFSmetadata")


if __name__ == "__main__":
    unittest.main()
