"""The install manifest (``common/etc/pfsimage.xml``) the SI archive carries."""

from __future__ import annotations

from dataclasses import dataclass

from . import constants as c
from . import paramjson
from .cnt import Facts
from .flt import write as write_table
from .outer import Layout
from .plan import Plan, super_root_dirents
from .playgo import PlayGo


@dataclass(slots=True)
class ManifestParams:
    facts: Facts
    content_id: str
    content_type: int
    param_json: bytes
    content_version: int
    cnt_offset: int
    si_offset: int
    outer_size: int
    inner_size: int
    seed: bytes
    game_digest: bytes
    icv: bytes
    playgo: PlayGo
    outer: Layout
    naps_len: int
    plan: Plan


def _digest(xml: list[str], indent: int, tag: str, value: bytes) -> None:
    pad = " " * indent
    xml.append(f"{pad}<{tag}>\n")
    for at in range(0, len(value), 16):
        row = " ".join(f"0x{byte:02x}" for byte in value[at:at + 16])
        xml.append(f"      {row}\n")
    xml.append(f"{pad}</{tag}>\n")


def _dotted_version(word: int) -> str:
    return f"{(word >> 24) & 0xFF:02x}.{(word >> 12) & 0xFFF:03x}.{word & 0xFFF:03x}"


def _dotted_firmware(word: str) -> str:
    digits = word.strip().removeprefix("0x").removeprefix("0X")
    digits = "".join(char for char in digits if char in "0123456789abcdefABCDEF")
    if len(digits) != 16:
        return "0.0.0.0"
    return f"{digits[0:2]}.{digits[2:5]}.{digits[5:8]}.{digits[8:16]}"


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _param_field(param_json: bytes, key: str) -> str | None:
    parsed = paramjson.parse(param_json)
    if isinstance(parsed, dict) and isinstance(parsed.get(key), str):
        return parsed[key]
    return None


def _inner_file_index(plan: Plan, inode: int) -> int | None:
    first = 4 + len(plan.dirs)
    return inode - first if inode >= first else None


def _inner_dir(xml: list[str], p: ManifestParams, index: int, depth: int) -> None:
    plan = p.plan
    directory = plan.dirs[index]
    offset, byte_count = plan.metadata.dirs[index]
    pad = " " * (depth * 2)
    imode = c.FLAGS_DATA if index == 0 else c.FLAGS_TABLE
    mode = "" if index == 0 else f' mode="{c.MODE_DIR:#06x}"'
    name = "uroot" if index == 0 else directory.path.rsplit("/", 1)[-1]
    xml.append(
        f'{pad}<dir plain="{byte_count}" poffset="{offset}" links="{directory.nlink}"'
        f'{mode} imode="{imode:#010x}" inode="{directory.inode}" name="{_escape(name)}">\n'
    )
    for child_name, inode, kind in directory.dirents:
        if kind in (c.DIRENT_DOT, c.DIRENT_DOTDOT):
            continue
        if kind == c.DIRENT_DIR:
            _inner_dir(xml, p, inode - 4, depth + 1)
        elif kind == c.DIRENT_FILE:
            file_index = _inner_file_index(plan, inode)
            if file_index is None:
                continue
            item = plan.files[file_index]
            xml.append(
                f'{pad}  <file plain="{item.size}" poffset="{item.logical_offset}"'
                f' imode="{item.inode_flags:#010x}" inode="{item.inode}"'
                f' name="{_escape(child_name)}"/>\n'
            )
    xml.append(f"{pad}</dir>\n")


def build(p: ManifestParams) -> bytes:
    mount = p.plan
    facts = p.facts
    add_on = p.content_type == 0x21
    suffix = "AC" if add_on else "GD"
    content_type = f"PS5{suffix}"
    content_version = _dotted_version(p.content_version)
    title = _param_field(p.param_json, "titleName") or ""
    master = _param_field(p.param_json, "masterVersion") or "01.00"
    firmware = _param_field(p.param_json, "requiredSystemSoftwareVersion") \
        or "0x0100000000000000"
    flt_len = len(write_table(mount.flt_inode))
    meta_region = mount.metadata.blocks * c.BLOCK

    def blocks(byte_count: int) -> int:
        return max((byte_count + c.BLOCK - 1) // c.BLOCK, 1)

    xml: list[str] = []
    xml.append('<?xml version="1.0" encoding="utf-8"?>\n')
    xml.append('<package-configuration version="1.0" type="package-info">\n')
    xml.append(f'  <config version="{content_version}" metadata="0" primary="yes">\n')
    xml.append(f"    <content-id>{_escape(p.content_id)}</content-id>\n")
    xml.append(f"    <primary-id>{_escape(p.content_id)}</primary-id>\n")
    xml.append(
        f"    <longname>{_escape(p.content_id)}-C00000000-M0000000000000000"
        f"-{suffix}</longname>\n"
    )
    xml.append(
        f"    <required-system-version>{_dotted_firmware(firmware)}"
        "</required-system-version>\n"
    )
    xml.append('    <drm-type version="1">PS5</drm-type>\n')
    xml.append(f"    <content-type>{content_type}</content-type>\n")
    xml.append("    <num-of-images>1</num-of-images>\n")
    xml.append(f"    <package-size>{p.si_offset}</package-size>\n")
    xml.append("    <version-date>0x20240508</version-date>\n")
    xml.append("    <version-hash>0x090fbfc1</version-hash>\n")
    xml.append("  </config>\n")

    xml.append('  <digests version="1.2" major-param-version="0">\n')
    _digest(xml, 4, "content-digest", facts.content_digest)
    _digest(xml, 4, "game-digest", p.game_digest)
    _digest(xml, 4, "header-digest", facts.header_digest)
    _digest(xml, 4, "system-digest", facts.system_digest)
    _digest(xml, 4, "param-digest", facts.param_digest)
    _digest(xml, 4, "package-digest", facts.package_digest)
    xml.append("  </digests>\n")

    xml.append("  <params>\n")
    xml.append(f"    <contentId>{_escape(p.content_id)}</contentId>\n")
    xml.append(f"    <contentVersion>{content_version}</contentVersion>\n")
    xml.append(f"    <masterVersion>{_escape(master)}</masterVersion>\n")
    xml.append(
        "    <requiredSystemSoftwareVersion>"
        f"{_escape(firmware)}</requiredSystemSoftwareVersion>\n")
    xml.append(f"    <titleName>{_escape(title)}</titleName>\n")
    xml.append("  </params>\n")

    xml.append('  <container nth-of-image="1">\n')
    xml.append(f"    <container-size>0x{facts.container_size:016x}</container-size>\n")
    xml.append(f"    <mandatory-size>0x{facts.mandatory_size:016x}</mandatory-size>\n")
    xml.append(f"    <body-offset>0x{facts.body_offset:016x}</body-offset>\n")
    xml.append(f"    <body-size>0x{facts.body_size:016x}</body-size>\n")
    _digest(xml, 4, "body-digest", facts.body_digest)
    xml.append("  </container>\n")

    xml.append('  <mount-image nth-of-image="1" nested-image="yes">\n')
    xml.append(f"    <pfs-offset-align>0x{c.BLOCK:016x}</pfs-offset-align>\n")
    xml.append(f"    <pfs-size-align>0x{c.BLOCK:016x}</pfs-size-align>\n")
    xml.append(f"    <pfs-image-offset>0x{c.BLOCK:016x}</pfs-image-offset>\n")
    xml.append(f"    <pfs-image-size>0x{p.outer_size:016x}</pfs-image-size>\n")
    xml.append(f"    <fixed-info-size>0x{c.BLOCK:08x}</fixed-info-size>\n")
    xml.append("    <pfs-image-seed>\n")
    for at in range(0, len(p.seed), 16):
        row = " ".join(f"0x{byte:02x}" for byte in p.seed[at:at + 16])
        xml.append(f"      {row}\n")
    xml.append("    </pfs-image-seed>\n")
    _digest(xml, 4, "sblock-digest", p.game_digest)
    _digest(xml, 4, "fixed-info-digest", facts.fih_digest)
    xml.append("    <mount-image-offset>0x0000000000000000</mount-image-offset>\n")
    xml.append(f"    <mount-image-size>0x{p.si_offset:016x}</mount-image-size>\n")
    xml.append(f"    <container-offset>0x{p.cnt_offset:016x}</container-offset>\n")
    xml.append(
        f"    <supplemental-offset>0x{facts.container_size:016x}"
        "</supplemental-offset>\n")
    xml.append("  </mount-image>\n")

    xml.append(f'  <entries nth-of-image="1" num="{len(facts.entries)}">\n')
    for offset, size, name in facts.entries:
        xml.append(
            f'    <entry offset="0x{offset:08x}" size="0x{size:08x}"'
            f' name="{_escape(name)}"/>\n')
    xml.append("  </entries>\n")

    pg = p.playgo
    scenario_type = p.content_type
    count = len(pg.chunks)
    total = sum(size for _, size in pg.mchunks)
    initial = pg.chunk_size(0)
    all_chunks = " ".join(str(index) for index in range(count))
    xml.append(
        f'  <chunkinfo size="{len(pg.chunk_dat)}" nested="true" sdk="0x00850000"'
        ' disps="0x0011">\n')
    xml.append(f"    <contentid>{_escape(p.content_id)}</contentid>\n")
    xml.append('    <languages default="1">0xffffffffffffffff</languages>\n')
    xml.append('    <scenarios num="1" default="0" groups="0">\n')
    xml.append(f'      <scenario id="0" type="{scenario_type}" name="">\n')
    for tag in ("overall", "default"):
        xml.append(
            f'        <{tag} initials="1" num="{count}" init-size="{initial}"'
            f' total="{total}">{all_chunks}</{tag}>\n')
    xml.append("      </scenario>\n")
    xml.append("    </scenarios>\n")
    xml.append(f'    <chunks num="{count}" default="0xffffffffffffffff">\n')
    for index, owned in enumerate(pg.chunks):
        name = "" if count == 1 else f"Chunk #{index}"
        ids = " ".join(str(m) for m in owned)
        xml.append(
            f'      <chunk id="{index}" flag="0x80" locus="0x03"'
            f' language="0xffffffffffffffff" disps="0x0011" num="{len(owned)}"'
            f' size="{pg.chunk_size(index)}" name="{name}">{ids}</chunk>\n')
    xml.append("    </chunks>\n")
    xml.append(
        f'    <outers num="{len(pg.mchunks)}" overlapped="0"'
        ' language-overlapped="0">\n')
    for index, (offset, size) in enumerate(pg.mchunks):
        xml.append(
            f'      <outer id="{index}" image="0" offset="0x{offset:016x}"'
            f' size="0x{size:016x}" chunks="1"/>\n')
    xml.append("    </outers>\n")
    xml.append("  </chunkinfo>\n")

    outer = p.outer
    xml.append(
        f'  <pfs-image version="2" readonly="true" offset="{c.BLOCK}"'
        f' metadata="{(outer.uroot_block + 1) * c.BLOCK}">\n')
    xml.append(
        '    <sblock signed="true" encrypted="true" ignore-case="true"'
        ' index-size="32" blocks="1" backups="0">\n')
    xml.append(
        f'      <image-size block-size="{c.BLOCK}"'
        f' num="{p.outer_size // c.BLOCK}">0x{p.outer_size:016x}</image-size>\n')
    xml.append('      <super-inode blocks="1" inodes="5" root="0">\n')
    xml.append(
        f'        <inode size="{c.BLOCK}" links="1" mode="0x0000"'
        f' imode="0x00000000" index="{outer.table_block}"/>\n')
    xml.append("      </super-inode>\n")
    xml.append(f"      <seed>0x{p.seed.hex().upper()}</seed>\n")
    xml.append(f"      <icv>0x{p.icv.hex().upper()}</icv>\n")
    xml.append("    </sblock>\n")
    xml.append(
        f'    <root size="{c.BLOCK}" links="1" imode="0x0002000c"'
        f' index="{outer.root_block}" inode="0" name="">\n')
    xml.append(
        f'      <file size="{flt_len}" imode="0x0002000c"'
        f' index="{outer.flt_block}" inode="1" name="inode_flat_path_table"/>\n')
    xml.append(
        f'      <dir size="{c.BLOCK}" links="3" imode="0x0000000c"'
        f' index="{outer.uroot_block}" inode="2" name="uroot">\n')
    inner_blocks = blocks(p.inner_size)
    xml.append(
        f'        <file size="{p.inner_size}" plain="{p.inner_size}"'
        f' comp="0% ({inner_blocks}/{inner_blocks})" imode="0x0000000d"'
        f' index="0" inode="3" name="pfs_image.dat"/>\n')
    xml.append(
        f'        <file size="{p.naps_len}" imode="0x0000000d"'
        f' index="{outer.naps_block}" inode="4" name="naps_pkg_layout.dat"/>\n')
    xml.append("      </dir>\n")
    xml.append("    </root>\n")
    xml.append("  </pfs-image>\n")

    meta_blocks = blocks(meta_region)
    xml.append('  <nested-image version="2" readonly="true" offset="0">\n')
    xml.append(
        '    <sblock ignore-case="true" index-size="32" blocks="1" backups="0">\n')
    xml.append(
        f'      <image-size block-size="{c.BLOCK}"'
        f' num="{blocks(p.cnt_offset)}">0x{p.cnt_offset:016x}</image-size>\n')
    xml.append(
        f'      <super-inode blocks="1"'
        f' inodes="{4 + len(mount.dirs) + len(mount.files)}" root="0">\n')
    xml.append(
        f'        <inode size="{c.BLOCK}" links="1" mode="0x0000"'
        f' imode="{c.FLAGS_TABLE:#010x}" index="{mount.meta_base // c.BLOCK}"/>\n')
    xml.append("      </super-inode>\n")
    xml.append("    </sblock>\n")
    xml.append(
        f'    <metadata size="{meta_region}" plain="{meta_region}"'
        f' comp="0% ({meta_blocks}/{meta_blocks})" offset="{mount.meta_base}"'
        f' poffset="{mount.meta_base}" afid="0"/>\n')
    root_at, root_len = mount.metadata.super_root
    xml.append(
        f'    <root plain="{root_len}" poffset="{root_at}" links="1"'
        f' imode="{c.FLAGS_TABLE:#010x}" inode="0" name="">\n')
    for name, inode, kind in super_root_dirents():
        if kind != c.DIRENT_FILE:
            continue
        span = {c.INODE_FLT_INODE: mount.metadata.flt,
                c.APR_FLT_INODE: mount.metadata.flt_apr,
                c.AFID_TABLE_INODE: mount.metadata.afid}.get(inode, (0, 0))
        xml.append(
            f'      <file plain="{span[1]}" poffset="{span[0]}"'
            f' imode="{c.FLAGS_TABLE:#010x}" inode="{inode}"'
            f' name="{_escape(name)}"/>\n')
    _inner_dir(xml, p, 0, 3)
    xml.append("    </root>\n")
    xml.append("  </nested-image>\n")
    xml.append("</package-configuration>\n")
    return "".join(xml).encode("utf-8")
