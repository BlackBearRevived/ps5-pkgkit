"""Checks against the reference Hello World package recorded in the artifacts."""

import os
from pathlib import Path
import unittest

from ps5_pkg.format import (
    cnt,
    constants as c,
    crypto,
    fih,
    license,
    manifest,
    naps,
    outer,
    paramjson,
    plan,
    playgo,
    sdkrules,
    selfrepair,
    si,
)

DEFAULT = Path("/mnt/c/Users/denis/Documents/PolarComet/ps5-pkg/.artifacts/hello-world")
FIXTURE = Path(os.environ.get("PS5_PKG_REFERENCE", DEFAULT))
SOURCE = FIXTURE / "PPSA99771"
PACKAGE = FIXTURE / "PS5-PKG-Hello-World.pkg"


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _packaged_param() -> bytes | None:
    if not PACKAGE.is_file():
        return None
    data = PACKAGE.read_bytes()
    cnt_at = int.from_bytes(data[0x58:0x60], "little")
    count = int.from_bytes(data[cnt_at + 0x10:cnt_at + 0x14], "big")
    table = cnt_at + int.from_bytes(data[cnt_at + 0x18:cnt_at + 0x1C], "big")
    for index in range(count):
        row = data[table + index * 32:table + index * 32 + 24]
        entry_id, _, _, _, offset, size = (
            int.from_bytes(row[at:at + 4], "big") for at in range(0, 24, 4)
        )
        if entry_id == 0x2000:
            return data[cnt_at + offset:cnt_at + offset + size]
    return None


@unittest.skipUnless(SOURCE.is_dir(), "reference source folder is not available")
class ReferenceParamTests(unittest.TestCase):
    def test_rewrites_match_the_packaged_param_json(self):
        packaged = _packaged_param()
        if packaged is None:
            self.skipTest("reference package is not available")
        original = _read(SOURCE / "sce_sys" / "param.json")
        rewritten = paramjson.drm_rewrite(original)
        self.assertIsNotNone(rewritten)
        unchanged = paramjson.content_id_rewrite(
            rewritten, "UP9000-PPSA99771_00-PKGHELLOWORLD001")
        self.assertEqual(unchanged, rewritten)
        self.assertIsNone(paramjson.launch_rewrite(unchanged))
        sizes = {}
        for path in SOURCE.rglob("*"):
            if path.is_file() and path.name != "param.json":
                relative = path.relative_to(SOURCE).as_posix()
                sizes[relative] = path.stat().st_size
        sizes["eboot.bin"] += 8
        sizes["sce_module/libc.prx"] += 8
        result = sdkrules.size_class_rewrite(
            unchanged, sum(sizes.values()), len(sizes) + 1)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], packaged)

    def test_size_class_for_the_reference(self):
        chosen = sdkrules.choose_size_class(1 << 29, 8, 0)
        self.assertEqual(chosen.attribute, 0)


@unittest.skipUnless(SOURCE.is_dir(), "reference source folder is not available")
class ReferenceRepairTests(unittest.TestCase):
    def _plan(self, relative):
        path = SOURCE / relative
        data = path.read_bytes()

        def read(offset, length):
            return data[offset:offset + length]

        return len(data), selfrepair.plan(data[:0x20], len(data), read)

    def test_eboot_repair(self):
        size, repair = self._plan("eboot.bin")
        self.assertIsNotNone(repair)
        self.assertTrue(repair.rewrite_magic)
        self.assertEqual(repair.insert_at, 0x3FD8)
        self.assertEqual(repair.padding, 8)
        self.assertEqual(repair.new_size(size), size + 8)

    def test_libc_repair(self):
        size, repair = self._plan("sce_module/libc.prx")
        self.assertIsNotNone(repair)
        self.assertFalse(repair.rewrite_magic)
        self.assertEqual(repair.insert_at, 0x139A28)
        self.assertEqual(repair.padding, 8)
        self.assertEqual(repair.new_size(size), size + 8)


@unittest.skipUnless(PACKAGE.is_file() and SOURCE.is_dir(),
                     "reference artifacts are not available")
class ReferenceGeometryTests(unittest.TestCase):
    CONTAINER_ONLY = {
        "sce_sys/icon0.png", "sce_sys/icon0.dds", "sce_sys/pic0.png",
        "sce_sys/pic0.dds", "sce_sys/pic1.dds", "sce_sys/pic2.dds",
        "sce_sys/snd0.at9", "sce_sys/save_data.png",
    }

    def _files(self):
        packaged = _packaged_param()
        files = []
        for path in sorted(SOURCE.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(SOURCE).as_posix()
            size = path.stat().st_size
            if relative in ("eboot.bin", "sce_module/libc.prx"):
                size += 8
            elif relative == "sce_sys/param.json":
                size = len(packaged)
            if relative in self.CONTAINER_ONLY:
                continue
            files.append((relative, size))
        return files

    def test_plan_matches_the_reference_geometry(self):
        built = plan.build_tree(self._files(), spread=True)
        self.assertEqual(built.meta_base, 0x500000)
        self.assertEqual(built.ndblock, 0x5B)
        self.assertEqual(built.metadata_blocks, 11)
        self.assertEqual(built.content_inodes, 8)
        self.assertEqual(built.app_file_count, 3)
        self.assertEqual(built.metadata.inode_table, (0x510000, 0x10000))
        self.assertEqual(built.metadata.super_root, (0x520000, 144))
        self.assertEqual(built.metadata.flt, (0x530000, 192))
        self.assertEqual(built.metadata.flt_apr, (0x540000, 112))
        self.assertEqual(built.metadata.afid, (0x550000, 32))
        self.assertEqual(built.metadata.dirs,
                         [(0x560000, 160), (0x570000, 80), (0x580000, 80),
                          (0x590000, 112)])
        placements = [(built.files[index].path, built.files[index].logical_offset,
                       built.files[index].size) for index in built.afid_order]
        self.assertEqual(placements, [
            ("sce_sys/keystone", 0, 96),
            ("sce_sys/param.json", 96, len(_packaged_param())),
            ("eboot.bin", 991, 16547),
            ("assets/banner.txt", 17538, 18),
            ("sce_module/libc.prx", 17556, 1284682),
        ])

    def test_outer_image_matches_the_reference_bytes(self):
        package = _read(PACKAGE)
        inner = package[0x10000:0x20000]
        naps = package[0x20000:0x20000 + 0x190]
        ours = outer.write(inner, naps, b"PPRPLAIN-NOAUTH!", mount_size=0x5B0000)
        self.assertEqual(ours.image, package[0x10000:0x80000])

    def test_fih_matches_the_reference_bytes(self):
        package = _read(PACKAGE)
        outer_image = package[0x10000:0x80000]
        game_digest = crypto.sha3(outer_image[2 * 0x10000:3 * 0x10000])
        header = fih.write(fih.FihParams(
            outer_size=len(outer_image),
            superblock_block=2,
            game_digest=game_digest,
            cnt_offset=0x80000,
            naps=package[0x20000:0x20000 + 0x190],
            inner_size=0x5B0000,
            meta_base=0x500000,
            inner_blocks=1,
            content_inodes=8,
            content_version=0x01000000,
            app_file_count=3,
            flt_count=2,
        ))
        self.assertEqual(header, package[:0x10000])


@unittest.skipUnless(PACKAGE.is_file() and SOURCE.is_dir(),
                     "reference artifacts are not available")
class ReferenceContainerTests(unittest.TestCase):
    CONTENT_ID = "UP9000-PPSA99771_00-PKGHELLOWORLD001"

    def _entry_table(self):
        data = _read(PACKAGE)
        cnt_at = int.from_bytes(data[0x58:0x60], "little")
        table = cnt_at + int.from_bytes(data[cnt_at + 0x18:cnt_at + 0x1C], "big")
        entries = {}
        rows = {}
        for index in range(int.from_bytes(data[cnt_at + 0x10:cnt_at + 0x14], "big")):
            row = data[table + index * 32:table + index * 32 + 32]
            values = [int.from_bytes(row[at:at + 4], "big") for at in range(0, 24, 4)]
            entries[values[0]] = (values[4], values[5])
            rows[values[0]] = row
        return data, cnt_at, entries, rows

    def test_license_entries_are_our_bytes_encrypted(self):
        data, cnt_at, entries, rows = self._entry_table()
        for entry_id, plain in ((0x0400, license.license_dat(self.CONTENT_ID)),
                                (0x0401, license.license_info(self.CONTENT_ID))):
            offset, size = entries[entry_id]
            key_index = int.from_bytes(rows[entry_id][12:16], "big") >> 12
            entry_key = crypto.derive_pfs_key(self.CONTENT_ID, crypto.DEFAULT_PASSCODE,
                                               key_index)
            material = crypto.sha3(rows[entry_id] + entry_key)
            stored = data[cnt_at + offset:cnt_at + offset + size]
            self.assertEqual(encrypt_entry(material, stored), plain)
            self.assertEqual(len(plain), size)

    def test_playgo_tables_match(self):
        data, cnt_at, entries, _ = self._entry_table()
        files = [
            ("sce_sys/keystone", 0x10000, 96),
            ("sce_sys/param.json", 0x20000, 895),
            ("eboot.bin", 0x30000, 16547),
            ("assets/banner.txt", 0x40000, 18),
            ("sce_module/libc.prx", 0x50000, 1284682),
        ]
        tables = playgo.build(self.CONTENT_ID, files, 0x80000, 1)
        for entry_id, ours in ((0x1001, tables.chunk_dat),
                               (0x2010, tables.hash_table),
                               (0x2011, tables.ficm)):
            offset, size = entries[entry_id]
            self.assertEqual(data[cnt_at + offset:cnt_at + offset + size], ours)

    def test_container_matches_the_reference_bytes(self):
        data, cnt_at, entries, _ = self._entry_table()

        def payload(entry_id):
            offset, size = entries[entry_id]
            return data[cnt_at + offset:cnt_at + offset + size]

        outer_image = data[0x10000:0x80000]
        imagedigs = [crypto.sha3(outer_image[at:at + 0x10000])
                     for at in range(0, len(outer_image), 0x10000)]
        files = [
            ("sce_sys/keystone", 0x10000, 96),
            ("sce_sys/param.json", 0x20000, 895),
            ("eboot.bin", 0x30000, 16547),
            ("assets/banner.txt", 0x40000, 18),
            ("sce_module/libc.prx", 0x50000, 1284682),
        ]
        tables = playgo.build(self.CONTENT_ID, files, cnt_at, 1)
        extras = [
            cnt.ExtraEntry(0x1240, "snd0.at9",
                           (SOURCE / "sce_sys/snd0.at9").read_bytes()),
            cnt.ExtraEntry(0x12A0, "pic0.dds",
                           (SOURCE / "sce_sys/pic0.dds").read_bytes()),
            cnt.ExtraEntry(0x12C0, "pic1.dds",
                           (SOURCE / "sce_sys/pic1.dds").read_bytes()),
            cnt.ExtraEntry(0x0400, "license.dat",
                           license.license_dat(self.CONTENT_ID), 3),
            cnt.ExtraEntry(0x0401, "license.info",
                           license.license_info(self.CONTENT_ID), 4),
            cnt.ExtraEntry(0x3000, "playgo-scenario.json", payload(0x3000)),
        ]
        built = cnt.write(cnt.CntParams(
            content_id=self.CONTENT_ID,
            param_json=payload(0x2000),
            icon_png=(SOURCE / "sce_sys/icon0.png").read_bytes(),
            icon_dds=b"",
            extras=extras,
            playgo_chunk=tables.chunk_dat,
            playgo_hash_table=tables.hash_table,
            playgo_ficm=tables.ficm,
            imagedigs=imagedigs,
            game_digest=imagedigs[2],
            fih_block=data[:0x10000],
            outer_size=0x70000,
            cnt_offset=cnt_at,
            seed=b"PPRPLAIN-NOAUTH!",
            passcode=crypto.DEFAULT_PASSCODE,
            content_type=0x20,
            drm_type=0x10,
            content_flags=0x02020000,
            inner_size=0x5B0000,
        ))
        si_at = cnt_at + int.from_bytes(data[cnt_at + 0x7C:cnt_at + 0x80], "big")
        self.assertEqual(built.bytes, data[cnt_at:si_at])

    def test_manifest_matches_the_reference_bytes(self):
        data, cnt_at, entries, _ = self._entry_table()

        def payload(entry_id):
            offset, size = entries[entry_id]
            return data[cnt_at + offset:cnt_at + offset + size]

        files = [("eboot.bin", 16547), ("assets/banner.txt", 18),
                 ("sce_module/libc.prx", 1284682), ("sce_sys/param.json", 895)]
        built_plan = plan.build_tree(files, spread=True)
        magic = (c.SELF_PS5, c.SELF_PS4, c.SIGNED_SELF, c.RAW_ELF)
        built_plan.mark_modules(
            lambda path: (SOURCE / path).read_bytes()[:4] in magic)
        outer_ref = data[0x10000:0x80000]
        imagedigs = [crypto.sha3(outer_ref[at:at + 0x10000])
                     for at in range(0, len(outer_ref), 0x10000)]
        outer_image = outer.write(outer_ref[:0x10000],
                                  outer_ref[0x10000:0x10000 + 0x190],
                                  b"PPRPLAIN-NOAUTH!", mount_size=0x5B0000)
        mount_files = [(item.path, 0x10000 + item.on_disk_offset, item.size)
                       for item in built_plan.files]
        tables = playgo.build(self.CONTENT_ID, mount_files, cnt_at, 1)
        extras = [
            cnt.ExtraEntry(0x1240, "snd0.at9",
                           (SOURCE / "sce_sys/snd0.at9").read_bytes()),
            cnt.ExtraEntry(0x12A0, "pic0.dds",
                           (SOURCE / "sce_sys/pic0.dds").read_bytes()),
            cnt.ExtraEntry(0x12C0, "pic1.dds",
                           (SOURCE / "sce_sys/pic1.dds").read_bytes()),
            cnt.ExtraEntry(0x0400, "license.dat",
                           license.license_dat(self.CONTENT_ID), 3),
            cnt.ExtraEntry(0x0401, "license.info",
                           license.license_info(self.CONTENT_ID), 4),
            cnt.ExtraEntry(0x3000, "playgo-scenario.json", payload(0x3000)),
        ]
        container = cnt.write(cnt.CntParams(
            self.CONTENT_ID, payload(0x2000),
            (SOURCE / "sce_sys/icon0.png").read_bytes(), b"", extras,
            tables.chunk_dat, tables.hash_table, tables.ficm, imagedigs,
            imagedigs[2], data[:0x10000], 0x70000, cnt_at,
            b"PPRPLAIN-NOAUTH!", crypto.DEFAULT_PASSCODE, 0x20, 0x10,
            0x02020000, 0x5B0000))
        si_at = cnt_at + int.from_bytes(data[cnt_at + 0x7C:cnt_at + 0x80], "big")
        icv = outer.superblock_icv(outer_ref[2 * 0x10000:3 * 0x10000])
        manifest_bytes = manifest.build(manifest.ManifestParams(
            container.facts, self.CONTENT_ID, 0x20, payload(0x2000), 0x01000000,
            cnt_at, si_at, 0x70000, 0x5B0000, b"PPRPLAIN-NOAUTH!", imagedigs[2],
            icv, tables, outer_image.layout, 0x190, built_plan))
        import io
        import zipfile
        expected = zipfile.ZipFile(io.BytesIO(data[si_at:])).read(
            "common/etc/pfsimage.xml")
        self.assertEqual(manifest_bytes, expected)

    def test_si_members_and_zip_match(self):
        data, cnt_at, entries, _ = self._entry_table()
        si_at = cnt_at + int.from_bytes(data[cnt_at + 0x7C:cnt_at + 0x80], "big")
        theirs = data[si_at:]
        import io
        import zipfile
        archive = zipfile.ZipFile(io.BytesIO(theirs))
        members = [(info.filename, archive.read(info.filename))
                   for info in archive.infolist()]
        self.assertEqual(si.zip_members(members, archive.infolist()[0].date_time), theirs)
        crc = archive.read(f"config/{self.CONTENT_ID}/playgo-chunk.crc")
        self.assertEqual(si.chunk_crc(data[:si_at]), crc)
        self.assertEqual(si.naps_meta_300(0x5B0000),
                         archive.read("common/etc/naps_meta_300.dat"))


def encrypt_entry(material: bytes, stored: bytes) -> bytes:
    from ps5_pkg.format.aes import cbc_decrypt
    return cbc_decrypt(material[16:], material[:16], stored)


if __name__ == "__main__":
    unittest.main()
