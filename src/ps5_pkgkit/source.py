"""Validate and inventory a staged application folder without modifying it."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import unicodedata


_CONTENT_ID = re.compile(r"[A-Z]{2}[0-9]{4}-PPSA[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}\Z")
_TITLE_ID = re.compile(r"PPSA[0-9]{5}\Z")
_VERSION = re.compile(r"[0-9]{2}\.[0-9]{3}\.[0-9]{3}\Z")
_BUFFER_SIZE = 1 << 20
_MAX_PARAM_SIZE = 1 << 20


class SourceError(ValueError):
    """The staged title folder is invalid or changed during inspection."""


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One regular file in a staged title.

    Attributes:
        path: Slash-separated path relative to the title root.
        size: File length in bytes.
        sha256: Hexadecimal SHA-256 digest of the file contents.
    """
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class SourceInspection:
    """The identity and sorted file inventory of a staged title.

    Attributes:
        title_id: Title identifier from the metadata.
        content_id: Content identifier from the metadata.
        content_version: Content version from the metadata.
        files: Inspected files in path order.
        total_size: Combined size of the inspected files in bytes.
        manifest_sha256: Hexadecimal SHA-256 digest of the canonical file
            manifest.
    """
    title_id: str
    content_id: str
    content_version: str
    files: tuple[SourceFile, ...]
    total_size: int
    manifest_sha256: str


def _portable_name(name: str, relative: str) -> None:
    """Check that a source path component uses supported characters.

    Args:
        name: Single directory entry name.
        relative: Source-relative path to include in error messages.

    Raises:
        SourceError: The name is empty, reserved, or contains unsupported
            characters or ending punctuation.
    """
    if (name in {"", ".", ".."} or name[-1] in {" ", "."}
            or any(char in name for char in '\\/:*?"<>|')
            or any(ord(char) < 32 for char in name)):
        raise SourceError(f"unsupported source path: {relative}")


def _hash_file(path: Path, scanned: os.stat_result, relative: str) -> SourceFile:
    """Hash a regular file and check that it still matches the scan.

    Args:
        path: Filesystem path to open.
        scanned: File metadata from the directory walk.
        relative: Source-relative path for the returned record and any error.

    Returns:
        File size and hexadecimal SHA-256 recorded under the relative path.

    Raises:
        SourceError: The file changes, is no longer regular, or cannot be read.
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            initial = os.fstat(stream.fileno())
            if (not stat.S_ISREG(initial.st_mode)
                    or (scanned.st_ino and (initial.st_dev, initial.st_ino) != (scanned.st_dev, scanned.st_ino))
                    or initial.st_size != scanned.st_size
                    or initial.st_mtime_ns != scanned.st_mtime_ns):
                raise SourceError(f"source file changed during inspection: {relative}")
            digest = hashlib.sha256()
            size = 0
            while chunk := stream.read(_BUFFER_SIZE):
                digest.update(chunk)
                size += len(chunk)
            final = os.fstat(stream.fileno())
            if (size != initial.st_size or initial.st_size != final.st_size
                    or initial.st_mtime_ns != final.st_mtime_ns):
                raise SourceError(f"source file changed during inspection: {relative}")
            return SourceFile(relative, size, digest.hexdigest())
    except OSError as error:
        raise SourceError(f"cannot read source file {relative}: {error}") from error


def _validate_metadata(root: Path, files: dict[str, SourceFile]) -> tuple[str, str, str]:
    """Validate the required files and base application identity.

    Args:
        root: Staged title root.
        files: Inspected files keyed by source-relative path.

    Returns:
        The title ID, content ID, and content version in that order.

    Raises:
        SourceError: Required files are missing or title metadata is invalid,
            unsupported, or changed during inspection.
    """
    if "eboot.bin" not in files:
        raise SourceError("missing root eboot.bin")
    metadata = files.get("sce_sys/param.json")
    if metadata is None:
        raise SourceError("missing sce_sys/param.json")
    if metadata.size > _MAX_PARAM_SIZE:
        raise SourceError("sce_sys/param.json exceeds the supported size")
    try:
        raw = (root / "sce_sys" / "param.json").read_bytes()
        if len(raw) != metadata.size or hashlib.sha256(raw).hexdigest() != metadata.sha256:
            raise SourceError("sce_sys/param.json changed during inspection")
        param = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, SourceError):
            raise
        raise SourceError("invalid sce_sys/param.json") from error
    if not isinstance(param, dict):
        raise SourceError("sce_sys/param.json must contain a JSON object")
    title_id, content_id, version = (param.get(key) for key in ("titleId", "contentId", "contentVersion"))
    if not isinstance(title_id, str) or _TITLE_ID.fullmatch(title_id) is None:
        raise SourceError("invalid titleId in sce_sys/param.json")
    if not isinstance(content_id, str) or _CONTENT_ID.fullmatch(content_id) is None or f"-{title_id}_" not in content_id:
        raise SourceError("invalid contentId in sce_sys/param.json")
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        raise SourceError("invalid contentVersion in sce_sys/param.json")
    if param.get("applicationCategoryType") != 0 or param.get("applicationDrmType") != "free":
        raise SourceError("unsupported application type in sce_sys/param.json")
    return title_id, content_id, version


def inspect_source(source_dir: str | Path) -> SourceInspection:
    """Validate a staged base application and hash its files.

    The manifest hashes sorted lines in the form sha256, two spaces, and the
    path prefixed with ./, each followed by a newline.

    Args:
        source_dir: Staged title directory containing eboot.bin and
            sce_sys/param.json.

    Returns:
        Title identity, path-sorted file inventory, total size, and manifest
        digest.

    Raises:
        SourceError: The directory cannot be inspected, contains unsupported or
            colliding paths, changes during the scan, or has invalid metadata.
    """
    root = Path(source_dir)
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise SourceError(f"cannot inspect source folder {root}: {error}") from error
    if not stat.S_ISDIR(root_stat.st_mode):
        raise SourceError(f"source folder must be a real directory: {root}")

    files: dict[str, SourceFile] = {}
    seen: dict[str, str] = {}
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as error:
            raise SourceError(f"cannot scan source folder {directory}: {error}") from error
        for entry in entries:
            relative = f"{prefix}{entry.name}"
            _portable_name(entry.name, relative)
            normalized = unicodedata.normalize("NFC", relative).casefold()
            previous = seen.setdefault(normalized, relative)
            if previous != relative:
                raise SourceError(f"case or Unicode path collision: {previous} and {relative}")
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise SourceError(f"cannot stat source path {relative}: {error}") from error
            if stat.S_ISDIR(info.st_mode):
                stack.append((Path(entry.path), relative + "/"))
            elif stat.S_ISREG(info.st_mode):
                files[relative] = _hash_file(Path(entry.path), info, relative)
            else:
                raise SourceError(f"unsupported source entry (including links): {relative}")

    title_id, content_id, version = _validate_metadata(root, files)
    ordered = tuple(files[path] for path in sorted(files))
    manifest = "".join(f"{item.sha256}  ./{item.path}\n" for item in ordered)
    return SourceInspection(
        title_id, content_id, version, ordered,
        sum(item.size for item in ordered), hashlib.sha256(manifest.encode("utf-8")).hexdigest(),
    )
