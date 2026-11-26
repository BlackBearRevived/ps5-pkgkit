import unittest

from ps5_pkgkit.format import constants, inner, plan


def make_plan():
    return plan.build_tree([
        ("eboot.bin", 0x400),
        ("sce_sys/param.json", 0x80),
        ("sce_sys/icon0.png", 0x40),
        ("assets/banner.txt", 0x20),
    ])


def payload(path, size):
    seed = sum(path.encode()) & 0xFF
    return bytes((seed + index * 13) & 0xFF for index in range(size))


class InnerImageTests(unittest.TestCase):
    def setUp(self):
        self.plan = make_plan()
        self.passcode = "00000000000000000000000000000000"
        self.image = inner.write_stored(
            self.plan, self.passcode,
            lambda path: payload(path, next(f.size for f in self.plan.files if f.path == path)),
        )

    def test_image_is_the_mount_size(self):
        self.assertEqual(len(self.image.image), self.plan.ndblock * constants.BLOCK)
        self.assertEqual(self.image.disk_blocks, self.plan.ndblock)

    def test_keystone_is_stored_at_offset_zero(self):
        expected = inner.keystone(self.passcode)
        self.assertEqual(self.image.image[:96], expected)
        self.assertEqual(expected[:8], b"keystone")
        self.assertEqual(len(expected), 96)

    def test_superblock_records_the_geometry(self):
        base = self.plan.meta_base
        superblock = self.image.image[base:base + constants.BLOCK]
        self.assertEqual(int.from_bytes(superblock[0x30:0x38], "little"), 4 + 3 + 5)
        self.assertEqual(int.from_bytes(superblock[0x38:0x40], "little"), self.plan.ndblock)
        self.assertEqual(int.from_bytes(superblock[0xD8:0xE0], "little"),
                         self.plan.metadata.inode_table[0] // constants.BLOCK)
        self.assertEqual(superblock[0x368], 1)
        self.assertEqual(superblock[0x1C:0x1E], (0x18).to_bytes(2, "little"))

    def test_block_info_table_sits_after_the_data(self):
        at = self.image.block_info_offset
        table = self.image.image[at:at + 0x100]
        self.assertEqual(int.from_bytes(table[0:4], "little"), inner.BLOCK_INFO_TEMPLATE)
        self.assertEqual(int.from_bytes(table[4:8], "little"), inner.BLOCK_INFO_VERSION)
        uroot_sum = sum(f.size for f in self.plan.files if not f.sce_sys)
        big = (inner.BLOCK_INFO_BASE - 4 * uroot_sum) & 0xFFFFFF
        last = ((big & 0xFF) << 16) | (big & 0xFF00) | ((big >> 16) & 0xFF)
        self.assertEqual(int.from_bytes(table[-8:-4], "little"), last)

    def test_super_root_dirents_name_the_tables(self):
        at = self.plan.metadata.super_root[0]
        entry = self.image.image[at:at + 16 + 21]
        self.assertEqual(int.from_bytes(entry[0:4], "little"), constants.INODE_FLT_INODE)
        self.assertEqual(int.from_bytes(entry[4:8], "little", signed=True), constants.DIRENT_FILE)
        self.assertEqual(int.from_bytes(entry[8:12], "little"), 21)
        self.assertEqual(entry[16:37], b"inode_flat_path_table")

    def test_keystone_inode_carries_afid_zero(self):
        index = 4 + len(self.plan.dirs) + next(
            position for position, item in enumerate(self.plan.files)
            if item.path == constants.KEYSTONE
        )
        at = self.plan.meta_base + self.plan.metadata.inode_table[0] - self.plan.meta_base
        at += inner.inode_offset(index)
        inode = self.image.image[at:at + constants.INODE_LEN]
        self.assertEqual(int.from_bytes(inode[0:2], "little"), constants.MODE_FILE_SCE_SYS)
        self.assertEqual(int.from_bytes(inode[0x68:0x6C], "little", signed=True), 0)
        self.assertEqual(int.from_bytes(inode[8:16], "little"), constants.KEYSTONE_LEN)


if __name__ == "__main__":
    unittest.main()
