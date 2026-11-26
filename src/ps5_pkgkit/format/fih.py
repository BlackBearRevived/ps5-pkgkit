"""The finalized-image header block (``\\x7FFIH``), 0x10000 bytes, little-endian."""

from __future__ import annotations

from dataclasses import dataclass

from .constants import BLOCK
from .crypto import sha3


@dataclass(slots=True)
class FihParams:
    #: The outer image's length in bytes (``0x18``).
    outer_size: int
    #: The outer superblock's block index; its absolute offset goes to ``0x20``.
    superblock_block: int
    #: ``SHA3-256`` of the superblock's plaintext block.
    game_digest: bytes
    #: Absolute offset of the container inside the finalized image.
    cnt_offset: int
    #: ``naps_pkg_layout.dat`` bytes.
    naps: bytes
    #: Mount size or stored size at ``0xA0``; the descriptor's mount size wins when they differ.
    inner_size: int
    #: The inner mount's metadata base in bytes, recorded at ``0x50`` in mount blocks.
    meta_base: int
    #: The stored inner image's length in blocks (``0x90``).
    inner_blocks: int
    #: Directories below uroot plus every file (``0x94``/``0x98``).
    content_inodes: int
    #: The content version's 2-3-3 BCD word (``0x9C``).
    content_version: int
    #: App-payload file count (``0xF0``).
    app_file_count: int
    #: Non-empty flat-path-table count (``0xF8``).
    flt_count: int


def write(params: FihParams) -> bytes:
    header = bytearray(BLOCK)
    header[0:4] = b"\x7fFIH"
    header[4] = 0x01
    header[5] = 0x00  # debug
    header[6] = 0x03
    header[0x08:0x0C] = (1).to_bytes(4, "little")
    header[0x10:0x18] = BLOCK.to_bytes(8, "little")
    header[0x18:0x20] = params.outer_size.to_bytes(8, "little")
    header[0x20:0x28] = (BLOCK + params.superblock_block * BLOCK).to_bytes(8, "little")
    header[0x28:0x30] = BLOCK.to_bytes(8, "little")
    for at in (0x30, 0x70, 0xD0):
        header[at:at + 32] = params.game_digest
    header[0x50:0x54] = (params.meta_base // BLOCK).to_bytes(4, "little")
    header[0x58:0x60] = params.cnt_offset.to_bytes(8, "little")
    header[0x60:0x68] = BLOCK.to_bytes(8, "little")
    header[0x68:0x70] = (0x0000_8000_0000_0000).to_bytes(8, "little")
    header[0x90:0x94] = params.inner_blocks.to_bytes(4, "little")
    header[0x94:0x98] = params.content_inodes.to_bytes(4, "little")
    header[0x98:0x9C] = params.content_inodes.to_bytes(4, "little")
    header[0x9C:0xA0] = params.content_version.to_bytes(4, "little")
    header[0xA0:0xA8] = params.inner_size.to_bytes(8, "little")
    header[0xA8:0xB0] = len(params.naps).to_bytes(8, "little")
    header[0xB0:0xD0] = sha3(params.naps)
    header[0xF0:0xF4] = params.app_file_count.to_bytes(4, "little")
    header[0xF8:0xFC] = params.flt_count.to_bytes(4, "little")
    return bytes(header)
