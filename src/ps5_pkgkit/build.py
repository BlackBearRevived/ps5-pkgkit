"""Build a console-installable PS5 package from a staged title folder.

The writer lays the files out itself; every structure is the measured template
the reference packages carry. The inner image is Kraken-compressed by default,
in the block layout the console's decoder expects; ``kraken=False`` stores it
instead, and a Python Kraken encoder reproduces the reference builder's blocks
byte for byte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import time as _time

from .format import (
    cnt,
    constants as c,
    crypto,
    fih,
    inner,
    license,
    manifest,
    naps,
    outer,
    paramjson,
    plan as plan_module,
    playgo,
    scenario,
    sdkrules,
    selfrepair,
    si,
)
from .source import SourceError, inspect_source
from .verification import VerificationError, verify_package


class BuildError(ValueError):
    """An invalid build input or a package that failed verification."""


@dataclass(slots=True)
class BuildResult:
    """The path, identity, and digest of a successful package build.

    Attributes:
        output: Destination path.
        size: Size of the completed package in bytes.
        sha256: Hexadecimal SHA-256 digest of the package.
        content_id: Content identifier written to the package.
        title_id: Title identifier in the packaged metadata.
        content_version: Content version in the packaged metadata.
        file_count: Number of files in the planned inner image.
        warnings: Notices about exclusions, repairs, or the selected size class.
    """
    output: Path
    size: int
    sha256: str
    content_id: str
    title_id: str
    content_version: str
    file_count: int
    warnings: list[str] = field(default_factory=list)


def _read(path: Path) -> bytes:
    """Read the entire file at the given path."""
    return path.read_bytes()


def _repair_map(root: Path, files: list[tuple[str, int]]) -> dict[str, selfrepair.SelfRepair]:
    """Identify repairs needed for staged executable files.

    Args:
        root: Root of the staged title.
        files: Source-relative paths paired with their original sizes in bytes.

    Returns:
        Repairs keyed by source-relative path. Only files needing repair appear.
    """
    repairs: dict[str, selfrepair.SelfRepair] = {}
    for relative, _ in files:
        if not (relative == "eboot.bin"
                or (relative.startswith("sce_module/")
                    and relative.lower().endswith(".prx"))):
            continue
        data = _read(root / relative)

        def read(offset: int, length: int) -> bytes:
            """Read a byte range from the current executable."""
            return data[offset:offset + length]

        repair = selfrepair.plan(data[:0x20], len(data), read)
        if repair is not None:
            repairs[relative] = repair
    return repairs


def _virtual_reader(root: Path, repairs: dict[str, selfrepair.SelfRepair],
                    param_json: bytes):
    """Create a cached reader for the payloads that will be packaged.

    Args:
        root: Root of the staged title.
        repairs: Executable repairs keyed by source-relative path.
        param_json: Rewritten title metadata to serve in place of the source
            copy.

    Returns:
        Callable that accepts a source-relative path and returns its packaged
        bytes.
    """
    cache: dict[str, bytes] = {}

    def read(relative: str) -> bytes:
        """Read the packaged bytes for a path, applying any scheduled repair.

        Args:
            relative: Slash-separated path relative to the staged title root.

        Returns:
            Rewritten metadata, repaired executable bytes, or the original file
            bytes.
        """
        if relative == "sce_sys/param.json":
            return param_json
        if relative in cache:
            return cache[relative]
        data = _read(root / relative)
        repair = repairs.get(relative)
        if repair is not None:
            data = selfrepair.read_repaired(data, repair)
        cache[relative] = data
        return data

    return read


def _zip_time(stamp: float | None) -> tuple[int, int, int, int, int, int]:
    """Convert a Unix timestamp to a ZIP date tuple in local time.

    Args:
        stamp: Seconds since the Unix epoch, or None to use the current time.

    Returns:
        Year, month, day, hour, minute, and second in that order.
    """
    moment = _time.localtime(stamp if stamp is not None else _time.time())
    return (moment.tm_year, moment.tm_mon, moment.tm_mday,
            moment.tm_hour, moment.tm_min, moment.tm_sec)


def build_package(source_dir: str | Path, output_path: str | Path, *,
                  content_id: str | None = None,
                  firmware: str | None = None,
                  language: str | None = None,
                  passcode: str = crypto.DEFAULT_PASSCODE,
                  timestamp: float | None = None,
                  kraken: bool = True,
                  level: str = "balanced",
                  jobs: int = 1) -> BuildResult:
    """Build and verify a PS5 package from a staged base application.

    The staged files are read in place. The package is written to a sibling
    partial file and moved into place after verification.

    Args:
        source_dir: Staged title directory containing eboot.bin and
            sce_sys/param.json.
        output_path: Destination for the completed package.
        content_id: Optional 36-character ASCII content identifier override.
        firmware: Optional minimum system software version, such as 5.10.
        language: Optional language code to use for the PlayGo scenario.
        passcode: Passcode used to derive package-format values.
        timestamp: Optional Unix timestamp for the install-metadata ZIP.
        kraken: Whether to compress the inner image with Kraken.
        level: Kraken preset: fast, balanced, or smallest.
        jobs: Maximum number of Kraken workers. One compresses serially.
            Stored builds skip compression.

    Returns:
        Output path, package identifiers, digest, size, file count, and
        warnings.

    Raises:
        BuildError: The inputs are invalid, a Kraken worker exits unexpectedly,
            or the finished package fails verification.
        OSError: A source file cannot be read or the destination cannot be
            written.
        ValueError: An input cannot be represented by the selected package
            layout.
    """
    if isinstance(jobs, bool) or not isinstance(jobs, int) or jobs < 1:
        raise BuildError("jobs must be a positive integer")
    root = Path(source_dir)
    output = Path(output_path)
    try:
        inspection = inspect_source(root)
    except SourceError as error:
        raise BuildError(str(error)) from error
    warnings: list[str] = []

    chosen_id = content_id or inspection.content_id
    if len(chosen_id) != 36 or not chosen_id.isascii() or not all(
            char.isalnum() or char in "-_" for char in chosen_id):
        raise BuildError("content id must be 36 characters of letters, digits, - and _")

    # Inventory: exclusions and executable repairs.
    files: list[tuple[str, int]] = []
    for item in inspection.files:
        if sdkrules.excluded(item.path):
            warnings.append(f"leaving out {item.path}")
            continue
        files.append((item.path, item.size))
    repairs = _repair_map(root, files)
    for relative, repair in repairs.items():
        warnings.append(f"repairing {relative}: {repair.describe()}")
        files = [(path, size + (repair.padding if path == relative else 0))
                 for path, size in files]


    # param.json: the packaged copy is a rewrite, never the user's file.
    original_param = _read(root / "sce_sys/param.json")
    packaged_param = paramjson.drm_rewrite(original_param) or original_param
    packaged_param = paramjson.launch_rewrite(packaged_param) or packaged_param
    rewritten = paramjson.content_id_rewrite(packaged_param, chosen_id)
    if rewritten is not None:
        packaged_param = rewritten
    if firmware is not None:
        word = paramjson.firmware_word(firmware)
        if word is None:
            raise BuildError(f"{firmware!r} is not a firmware version")
        packaged_param = paramjson.firmware_rewrite(packaged_param, word) or packaged_param
    unpacked = sum(size for path, size in files if path != "sce_sys/param.json")
    sized = sdkrules.size_class_rewrite(packaged_param, unpacked, len(files))
    if sized is not None:
        packaged_param, what = sized
        warnings.append(f"size class: {what}")
    files = [(path, len(packaged_param) if path == "sce_sys/param.json" else size)
             for path, size in files]

    read = _virtual_reader(root, repairs, packaged_param)

    # Container extras: presentation files, the license, the scenario.
    extras: list[cnt.ExtraEntry] = []
    carried: set[str] = set()

    def add_extra(entry_id: int, relative: str, name: str,
                  key_index: int | None = None) -> None:
        """Add a nonempty staged asset to the container extras.

        Args:
            entry_id: Numeric container entry identifier.
            relative: Path of the staged asset relative to the title root.
            name: Filename to record in the container.
            key_index: Optional key slot for the entry.
        """
        path = root / relative
        if not path.is_file() or path.stat().st_size == 0:
            return
        extras.append(cnt.ExtraEntry(entry_id, name, _read(path), key_index))
        carried.add(relative)

    for entry_id, relative, name in cnt.PRESENTATION:
        add_extra(entry_id, relative, name)
    for entry_id, relative, name, key_index in cnt.PROTECTED:
        add_extra(entry_id, relative, name, key_index)
    extras.append(cnt.ExtraEntry(0x0400, "license.dat", license.license_dat(chosen_id), 3))
    extras.append(cnt.ExtraEntry(0x0401, "license.info", license.license_info(chosen_id), 4))

    stale_scenario = (root / "sce_sys/playgo-scenario.json")
    scenario_bytes = scenario.build(
        _read(stale_scenario) if stale_scenario.is_file() else b"",
        packaged_param, language)
    extras.append(cnt.ExtraEntry(0x3000, "playgo-scenario.json", scenario_bytes))

    icon_png = _read(root / "sce_sys/icon0.png") \
        if (root / "sce_sys/icon0.png").is_file() else b""
    icon_dds = _read(root / "sce_sys/icon0.dds") \
        if (root / "sce_sys/icon0.dds").is_file() else b""
    if icon_png:
        carried.add("sce_sys/icon0.png")
    if icon_dds:
        carried.add("sce_sys/icon0.dds")

    # What the container carries is left out of the image.
    files = [(path, size) for path, size in files
             if not (path in cnt.CONTAINER_ONLY and path in carried)]
    built_plan = plan_module.build_tree(files, spread=kraken)
    magic = (c.SELF_PS5, c.SELF_PS4, c.SIGNED_SELF, c.RAW_ELF)
    built_plan.mark_modules(lambda path: read(path)[:4] in magic)

    mount_size = built_plan.ndblock * c.BLOCK
    compressed = None
    if kraken:
        from concurrent.futures.process import BrokenProcessPool

        from .format import kraken_compress
        metadata_plain = inner.metadata_region(built_plan, (0, 0))

        def read_range(path: str, offset: int, length: int) -> bytes:
            """Read a range from a file as it will appear in the package.

            Args:
                path: Source-relative file path.
                offset: Starting byte offset in the packaged file.
                length: Number of bytes requested.

            Returns:
                The requested slice of the packaged payload.
            """
            return read(path)[offset:offset + length]

        try:
            compressed = kraken_compress.compress(
                built_plan, metadata_plain, inner.keystone(passcode), read_range, level,
                jobs=jobs)
        except BrokenProcessPool as error:
            raise BuildError("a Kraken worker exited unexpectedly") from error
        layout = kraken_compress.layout(
            compressed,
            [built_plan.files[index].logical_offset for index in built_plan.afid_order])
        outer_image = outer.write(compressed.image, layout, c.PLAINTEXT_MARKER,
                                  mount_size=mount_size)
    else:
        image = inner.write_stored(built_plan, passcode, read)
        layout = naps.build(len(image.image), built_plan.ndblock, image.afid_files,
                            built_plan.data_end, built_plan.meta_base)
        outer_image = outer.write(image.image, layout, c.PLAINTEXT_MARKER)
    inner_blocks = compressed.disk_blocks if compressed is not None else image.disk_blocks
    superblock_at = outer_image.superblock_block * c.BLOCK
    game_digest = outer_image.plaintext_digests[outer_image.superblock_block]
    cnt_offset = c.BLOCK + len(outer_image.image)
    content_version = paramjson.content_version_word(packaged_param) or 0
    header = fih.write(fih.FihParams(
        outer_size=len(outer_image.image),
        superblock_block=outer_image.superblock_block,
        game_digest=game_digest,
        cnt_offset=cnt_offset,
        naps=layout,
        inner_size=mount_size,
        meta_base=built_plan.meta_base,
        inner_blocks=inner_blocks,
        content_inodes=built_plan.content_inodes,
        content_version=content_version,
        app_file_count=built_plan.app_file_count,
        flt_count=int(bool(built_plan.flt_apr)) + 1,
    ))
    mount_files = built_plan.mount_files()
    tables = playgo.build(chosen_id, mount_files, cnt_offset, playgo.DEFAULT_CHUNKS)
    content_type, content_flags = cnt.content_class(packaged_param,
                                                    built_plan.has_eboot())
    container = cnt.write(cnt.CntParams(
        content_id=chosen_id,
        param_json=packaged_param,
        icon_png=icon_png,
        icon_dds=icon_dds,
        extras=extras,
        playgo_chunk=tables.chunk_dat,
        playgo_hash_table=tables.hash_table,
        playgo_ficm=tables.ficm,
        imagedigs=outer_image.plaintext_digests,
        game_digest=game_digest,
        fih_block=header,
        outer_size=len(outer_image.image),
        cnt_offset=cnt_offset,
        seed=c.PLAINTEXT_MARKER,
        passcode=passcode,
        content_type=content_type,
        drm_type=cnt.LICENSED_DRM_TYPE,
        content_flags=content_flags,
        inner_size=built_plan.ndblock * c.BLOCK,
    ))
    si_offset = cnt_offset + container.facts.container_size
    manifest_bytes = manifest.build(manifest.ManifestParams(
        facts=container.facts,
        content_id=chosen_id,
        content_type=content_type,
        param_json=packaged_param,
        content_version=content_version,
        cnt_offset=cnt_offset,
        si_offset=si_offset,
        outer_size=len(outer_image.image),
        inner_size=built_plan.ndblock * c.BLOCK,
        seed=c.PLAINTEXT_MARKER,
        game_digest=game_digest,
        icv=outer.superblock_icv(outer_image.image[superblock_at:superblock_at + c.BLOCK]),
        playgo=tables,
        outer=outer_image.layout,
        naps_len=len(layout),
        plan=built_plan,
    ))
    if compressed is not None:
        meta_blob = si.kraken_meta_18(compressed, mount_size, metadata_plain,
                                      built_plan.inner_files(), game_digest)
    else:
        block_digests = [crypto.sha3(image.image[at:at + c.BLOCK])
                         for at in range(0, len(image.image), c.BLOCK)]
        file_digests = [crypto.sha3(image.image[on_disk:on_disk + size])
                        for _, on_disk, size in image.afid_files]
        meta_blob = si.naps_meta_18(
            len(image.image), mount_size, block_digests,
            file_digests, image.metadata, built_plan.inner_files(),
            built_plan.data_end, built_plan.meta_base, game_digest)
    mount = header + outer_image.image + container.bytes
    members = [
        ("common/etc/naps_meta_18.dat", meta_blob),
        ("common/etc/naps_meta_300.dat", si.naps_meta_300(built_plan.ndblock * c.BLOCK)),
        ("common/etc/naps_meta_301.dat", si.naps_meta_300(built_plan.ndblock * c.BLOCK)),
        ("common/etc/naps_meta_302.dat", si.naps_meta_300(built_plan.ndblock * c.BLOCK)),
        ("common/etc/naps_meta_308.dat", si.naps_meta_300(built_plan.ndblock * c.BLOCK)),
        ("common/etc/pfsimage.xml", manifest_bytes),
        ("common/etc/playgo-chunk.dat", tables.chunk_dat),
        (f"config/{chosen_id}/playgo-chunk.crc", si.chunk_crc(mount)),
    ]
    segment = si.zip_members(members, _zip_time(timestamp))

    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name + ".partial")
    try:
        with partial.open("wb") as stream:
            stream.write(header)
            stream.write(outer_image.image)
            stream.write(container.bytes)
            stream.write(segment)
            stream.flush()
            os.fsync(stream.fileno())
        digest = hashlib.sha256(partial.read_bytes()).hexdigest()
        try:
            verify_package(partial)
        except VerificationError as error:
            raise BuildError(f"the built package failed verification: {error}") from error
        os.replace(partial, output)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise

    title_id = paramjson.parse(packaged_param)["titleId"]
    version = paramjson.parse(packaged_param)["contentVersion"]
    return BuildResult(
        output=output,
        size=output.stat().st_size,
        sha256=digest,
        content_id=chosen_id,
        title_id=title_id,
        content_version=version,
        file_count=len(built_plan.files),
        warnings=warnings,
    )
