import unittest

from ps5_pkgkit.format import plan


def source(paths):
    return [(path, size) for path, size in paths]


class PlanTests(unittest.TestCase):
    def test_reproduces_the_webbrowser_geometry(self):
        built = plan.build_tree(source([
            ("sce_sys/about/right.sprx", 12752),
            ("sce_sys/keystone", 96),
            ("00.dat", 10),
            ("m.dat", 14942),
            ("z.dat", 14734),
        ]))
        self.assertEqual(built.data_end, 0x50000)
        self.assertEqual(len(built.dirs), 3)
        self.assertEqual(built.metadata_blocks, 10)
        self.assertEqual(built.content_inodes, 7)
        self.assertEqual(built.app_file_count, 3)
        offsets = [built.files[index].logical_offset for index in built.afid_order]
        self.assertEqual(offsets, [0, 96, 12848, 12858, 27800])
        on_disk = [built.files[index].on_disk_offset for index in built.afid_order]
        self.assertEqual(on_disk, [0, 0x10000, 0x20000, 0x30000, 0x40000])

    def test_missing_keystone_is_generated_first(self):
        built = plan.build_tree(source([("eboot.bin", 4096)]))
        keystone = built.files[built.afid_order[0]]
        self.assertEqual(keystone.path, "sce_sys/keystone")
        self.assertEqual(keystone.size, 96)
        self.assertTrue(keystone.generated)
        self.assertTrue(keystone.sce_sys)

    def test_case_collisions_are_refused(self):
        with self.assertRaises(ValueError):
            plan.build_tree(source([("Data/a", 1), ("data/b", 2)]))
        with self.assertRaises(ValueError):
            plan.build_tree(source([("data/a", 1)]), ["Data"])

    def test_empty_directories_are_kept(self):
        built = plan.build_tree(source([("eboot.bin", 1)]), ["assets", "assets/empty"])
        paths = {directory.path for directory in built.dirs}
        self.assertIn("assets", paths)
        self.assertIn("assets/empty", paths)

    def test_modules_carry_the_module_flag_and_keystone_never_does(self):
        built = plan.build_tree(source([
            ("eboot.bin", 64),
            ("sce_module/libc.prx", 32),
            ("assets/banner.txt", 8),
        ]))
        built.mark_modules(lambda path: path in {"eboot.bin", "sce_module/libc.prx"})
        flags = {item.path: item.inode_flags for item in built.files}
        self.assertEqual(flags["eboot.bin"], 0x50)
        self.assertEqual(flags["sce_module/libc.prx"], 0x50)
        self.assertEqual(flags["assets/banner.txt"], 0x30)
        self.assertEqual(flags["sce_sys/keystone"], 0x20030)

    def test_spread_keeps_every_file_in_its_own_16_byte_unit(self):
        files = [(f"d/{index:03}", 4000) for index in range(200)]
        packed = plan.build_tree(source(files))
        cursor = 0
        for index in packed.afid_order:
            item = packed.files[index]
            self.assertEqual(item.logical_offset, cursor)
            cursor += item.size
        spaced = plan.build_tree(source(files), spread=True)
        starts = {spaced.files[index].logical_offset // 16 for index in spaced.afid_order}
        self.assertEqual(len(starts), len(spaced.afid_order))


if __name__ == "__main__":
    unittest.main()
