"""Read the finalized-image and content-container metadata of a PS5 package."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
from typing import BinaryIO, Callable

_FIH_SIZE = 0x100
_CNT_SIZE = 0x1000
_ENTRY = struct.Struct(">I12xII8x")
_PARAM_JSON = 0x2000
_MAX_ENTRIES = 4096
_MAX_PARAM_SIZE = 1 << 20
_BUFFER_SIZE = 1 << 20


class VerificationError(ValueError):
    """A package failed structural or integrity verification."""


@dataclass(frozen=True, slots=True)
class PackageVerification:
    """Verification of the container and, when supplied, a trusted file digest."""

    size: int
    sha256: str
    content_id: str
    title_id: str
    content_version: str
    container_entries: int
    expected_sha256_verified: bool


def _read_at(package: BinaryIO, offset: int, size: int, end: int, name: str) -> bytes:
    if offset > end or size > end - offset:
        raise VerificationError(f"{name} extends past the package")
    package.seek(offset)
    data = package.read(size)
    if len(data) != size:
        raise VerificationError(f"{name} was truncated during verification")
    return data


def _digest_region(
    package: BinaryIO, offset: int, size: int, make_hash: Callable,
) -> bytes:
    digest = make_hash()
    package.seek(offset)
    while size:
        data = package.read(min(size, _BUFFER_SIZE))
        if not data:
            raise VerificationError("package was truncated during hashing")
        digest.update(data)
        size -= len(data)
    return digest.digest()


def verify_package(
    path: str | Path, *, expected_sha256: str | None = None,
) -> PackageVerification:
    """Check package structure, container checksums and optional whole-file SHA-256."""
    if expected_sha256 is not None and re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is None:
        raise VerificationError("expected SHA-256 must contain exactly 64 hexadecimal digits")

    with Path(path).open("rb") as package:
        initial = os.fstat(package.fileno())
        if not stat.S_ISREG(initial.st_mode):
            raise VerificationError("package must be a regular file")
        size = initial.st_size
        fih = _read_at(package, 0, _FIH_SIZE, size, "finalized-image header")
        if fih[:4] != b"\x7fFIH":
            raise VerificationError("unrecognized PS5 finalized-image header")
        version, = struct.unpack_from("<H", fih, 6)
        if version != 3:
            raise VerificationError(f"unsupported PS5 finalized-image version {version}")
        image_offset, image_size = struct.unpack_from("<QQ", fih, 0x10)
        container_offset, = struct.unpack_from("<Q", fih, 0x58)
        if image_offset < _FIH_SIZE or not image_size or image_offset + image_size > container_offset:
            raise VerificationError("filesystem image has an invalid range")

        container = _read_at(package, container_offset, _CNT_SIZE, size, "content container header")
        if container[:4] != b"\x7fCNT":
            raise VerificationError("unrecognized PS5 content container header")
        if hashlib.sha3_256(container[:0xFE0]).digest() != container[0xFE0:]:
            raise VerificationError("content container header SHA3-256 mismatch")

        entry_count, = struct.unpack_from(">I", container, 0x10)
        table_offset, = struct.unpack_from(">I", container, 0x18)
        body_offset, body_size = struct.unpack_from(">QQ", container, 0x20)
        body_end = body_offset + body_size
        if body_offset < _CNT_SIZE or not body_size or body_end > size - container_offset:
            raise VerificationError("content container body has an invalid range")
        table_size = entry_count * _ENTRY.size
        if not 0 < entry_count <= _MAX_ENTRIES:
            raise VerificationError(f"unsupported content container entry count {entry_count}")
        if table_offset < body_offset or table_offset + table_size > body_end:
            raise VerificationError("content container entry table lies outside the body")
        table = _read_at(package, container_offset + table_offset, table_size, size, "entry table")

        entries = {}
        for entry_id, offset, length in _ENTRY.iter_unpack(table):
            if entry_id in entries:
                raise VerificationError(f"duplicate content container entry 0x{entry_id:04x}")
            if offset < body_offset or offset + length > body_end:
                raise VerificationError(f"content container entry 0x{entry_id:04x} lies outside the body")
            entries[entry_id] = (offset, length)

        previous_end = body_offset
        for offset, length in sorted(entries.values()):
            if length and offset < previous_end:
                raise VerificationError("content container entries overlap")
            previous_end = max(previous_end, offset + length)

        body_digest = _digest_region(package, container_offset + body_offset, body_size, hashlib.sha3_256)
        if body_digest != container[0x160:0x180]:
            raise VerificationError("content container body SHA3-256 mismatch")

        param_offset, param_size = entries.get(_PARAM_JSON, (0, 0))
        if not 0 < param_size <= _MAX_PARAM_SIZE:
            raise VerificationError("package lacks supported title metadata")
        raw_param = _read_at(package, container_offset + param_offset, param_size, size, "title metadata")
        try:
            content_id = container[0x40:0x64].rstrip(b"\0").decode("ascii")
            param = json.loads(raw_param.decode("utf-8-sig"))
        except (UnicodeError, ValueError, RecursionError) as error:
            raise VerificationError("invalid content ID or title metadata encoding") from error
        if re.fullmatch(r"[A-Z]{2}[0-9]{4}-PPSA[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}", content_id) is None:
            raise VerificationError("invalid PS5 application content ID")
        if not isinstance(param, dict) or param.get("contentId") != content_id:
            raise VerificationError("title metadata content ID differs from the container")
        title_id = param.get("titleId")
        title_version = param.get("contentVersion")
        if not isinstance(title_id, str) or re.fullmatch(r"PPSA[0-9]{5}", title_id) is None:
            raise VerificationError("invalid PS5 application title ID")
        if not isinstance(title_version, str) or re.fullmatch(r"[0-9]{2}\.[0-9]{3}\.[0-9]{3}", title_version) is None:
            raise VerificationError("invalid PS5 application content version")
        if f"-{title_id}_" not in content_id:
            raise VerificationError("content ID does not identify the declared title")

        digest = _digest_region(package, 0, size, hashlib.sha256).hex()
        final = os.fstat(package.fileno())
        if (initial.st_size, initial.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
            raise VerificationError("package changed during verification")
        if expected_sha256 is not None and digest != expected_sha256.lower():
            raise VerificationError(f"package SHA-256 mismatch (computed {digest})")

    return PackageVerification(
        size, digest, content_id, title_id, title_version, entry_count,
        expected_sha256 is not None,
    )
