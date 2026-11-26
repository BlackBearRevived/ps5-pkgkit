"""Constants of the measured PS5 debug-package format.

Every value here was taken from the format as the reference FPKG builder
implements it: 64 KiB blocks, a data-first inner PFS image whose metadata region
sits on a 256 KiB aligned base, and the plaintext no-auth marker in the seed
slot.
"""

BLOCK = 0x10000
FILE_ALIGN = 0x10000
META_ALIGN = 0x40000
UBLOCK = 0x40000
COMPRESSED_META_GAP = 0x400000
MAX_STARTS_PER_UBLOCK = 16

KEYSTONE = "sce_sys/keystone"
KEYSTONE_LEN = 96
PFS_VERSION_DAT = "pfs-version.dat"

SUPER_ROOT_INODE = 0
INODE_FLT_INODE = 1
APR_FLT_INODE = 2
AFID_TABLE_INODE = 3
FIRST_DIR_INODE = 4

DIRENT_FILE = 2
DIRENT_DIR = 3
DIRENT_DOT = 4
DIRENT_DOTDOT = 5

MODE_FILE = 0x816D
MODE_FILE_SCE_SYS = 0x8168
MODE_DIR_UROOT = 0x416D
MODE_DIR = 0x4168

FLAGS_DATA = 0x10
FLAGS_MODULE = 0x40
FLAGS_BLOB = 0x20
FLAGS_SCE_SYS = 0x00020000
FLAGS_TABLE = 0x00020010

INODES_PER_BLOCK = 390
INODE_LEN = 0xA8

# Written where a native package carries its random seed: the console's patched
# mount path serves an image marked this way without authentication.
PLAINTEXT_MARKER = b"PPRPLAIN-NOAUTH!"

RAW_ELF = b"\x7fELF"
SELF_PS5 = bytes([0x54, 0x14, 0xF5, 0xEE])
SELF_PS4 = bytes([0x4F, 0x15, 0x3D, 0x1D])
SIGNED_SELF = b"SCE\x00"


def align_up(value: int, alignment: int) -> int:
    """Round ``value`` up to a multiple of ``alignment``."""
    return (value + alignment - 1) // alignment * alignment


def inode_table_len(count: int) -> int:
    """Return the inode table length rounded up to whole blocks.

    Args:
        count: Number of inodes the table must hold.

    Returns:
        Length in bytes, with a minimum of one block.
    """
    blocks = max((count + INODES_PER_BLOCK - 1) // INODES_PER_BLOCK, 1)
    return blocks * BLOCK
