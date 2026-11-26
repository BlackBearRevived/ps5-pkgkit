"""Serialize the content container header, entries, payloads, and digests."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import constants as c
from . import keys as key_data
from . import paramjson
from .crypto import derive_pfs_key, encrypt_entry, sha3
from .rsa import pkcs1_encrypt

BODY_AT = 0x2000
PACKAGE_DIGEST_AT = 0xFE0
SIGNATURE_AT = 0x1000
SC_ENTRY_COUNT = 6
ENTRY_ROW = 32
GENERAL_DIGEST_SET = 0x10DE
GENERAL_LEN = 0x20 + 14 * 32

DIGESTS = 0x0001
ENTRY_KEYS = 0x0010
IMAGE_KEY = 0x0020
GENERAL_DIGESTS = 0x0080
METAS = 0x0100
ENTRY_NAMES = 0x0200
IMAGE_DIGESTS = 0x040A
PLAYGO_CHUNK = 0x1001
SAVE_DATA_PNG = 0x100D
ICON0_PNG = 0x1200
PIC0_PNG = 0x1220
SND0_AT9 = 0x1240
ICON0_DDS = 0x1280
PIC0_DDS = 0x12A0
PIC1_DDS = 0x12C0
TROPHY = 0x1480
UDS = 0x14A0
PARAM_JSON = 0x2000
PIC2_DDS = 0x2060
PLAYGO_HASH_TABLE = 0x2010
PLAYGO_FICM = 0x2011
PLAYGO_SCENARIO_JSON = 0x3000

SYSTEM_DIGEST_IDS = (
    SAVE_DATA_PNG, ICON0_PNG, PIC0_PNG, SND0_AT9,
    ICON0_DDS, PIC0_DDS, PIC1_DDS, PIC2_DDS,
)

ENTRIES = (
    (DIGESTS, 0x40000000, ""),
    (ENTRY_KEYS, 0x60000000, ""),
    (IMAGE_KEY, 0x60000000, ""),
    (GENERAL_DIGESTS, 0x60000000, ""),
    (METAS, 0x60000000, ""),
    (ENTRY_NAMES, 0x40000000, ""),
    (IMAGE_DIGESTS, 0x08000000, ""),
    (PLAYGO_CHUNK, 0x08000000, "playgo-chunk.dat"),
    (ICON0_PNG, 0x08000000, "icon0.png"),
    (ICON0_DDS, 0x08000000, "icon0.dds"),
    (PARAM_JSON, 0x00000000, "param.json"),
    (PLAYGO_HASH_TABLE, 0x08000000, "playgo-hash-table.dat"),
    (PLAYGO_FICM, 0x08000000, "playgo-ficm.dat"),
)

PRESENTATION = (
    (SAVE_DATA_PNG, "sce_sys/save_data.png", "save_data.png"),
    (PIC0_PNG, "sce_sys/pic0.png", "pic0.png"),
    (SND0_AT9, "sce_sys/snd0.at9", "snd0.at9"),
    (PIC0_DDS, "sce_sys/pic0.dds", "pic0.dds"),
    (PIC1_DDS, "sce_sys/pic1.dds", "pic1.dds"),
    (TROPHY, "sce_sys/trophy2/trophy00.ucp", "trophy2/trophy00.ucp"),
    (UDS, "sce_sys/uds/uds00.ucp", "uds/uds00.ucp"),
    (PIC2_DDS, "sce_sys/pic2.dds", "pic2.dds"),
)

CONTAINER_ONLY = frozenset({
    "sce_sys/icon0.png", "sce_sys/icon0.dds", "sce_sys/pic0.png",
    "sce_sys/pic0.dds", "sce_sys/pic1.dds", "sce_sys/pic2.dds",
    "sce_sys/snd0.at9", "sce_sys/save_data.png",
})

PROTECTED = (
    (0x0402, "sce_sys/nptitle.dat", "nptitle.dat", 3),
    (0x2020, "sce_sys/uds/npbind.dat", "uds/npbind.dat", 3),
    (0x2021, "sce_sys/trophy2/npbind.dat", "trophy2/npbind.dat", 3),
)

LICENSED_DRM_TYPE = 0x10


@dataclass(frozen=True, slots=True)
class ExtraEntry:
    """An optional payload to add to the content container.

    Attributes:
        id: Numeric entry ID distinct from the fixed and other optional entries.
        name: Name to record in the entry-name table.
        data: Payload bytes before any padding or encryption.
        key_index: Optional key slot for a protected entry.
    """
    id: int
    name: str
    data: bytes
    key_index: int | None = None


def content_class(param_json: bytes, has_eboot: bool) -> tuple[int, int]:
    """Choose the container content type and flags for a title.

    Args:
        param_json: Packaged title metadata as JSON bytes.
        has_eboot: Whether the image contains a root eboot.bin file.

    Returns:
        The numeric content type and content flags, in that order.
    """
    parsed = paramjson.parse(param_json)
    has = lambda key: parsed is not None and key in parsed
    if not has_eboot and parsed is not None and not has("applicationCategoryType") \
            and not has("applicationDrmType"):
        return 0x21, 0x0A020000
    category = 0
    if parsed is not None and isinstance(parsed.get("applicationCategoryType"), int):
        category = parsed["applicationCategoryType"]
    return (0x20, 0x02020000) if category == 0 else (0x26, 0x06020000)


def _body_rank(entry_id: int) -> tuple[int, int]:
    """Return the physical sort key for a container entry ID."""
    fixed = {
        ENTRY_KEYS: (0, 0), IMAGE_KEY: (1, 0), GENERAL_DIGESTS: (2, 0),
        METAS: (3, 0), DIGESTS: (4, 0), ENTRY_NAMES: (5, 0),
        PARAM_JSON: (6, 0), IMAGE_DIGESTS: (8, 0), PLAYGO_CHUNK: (9, 0),
    }
    if entry_id in fixed:
        return fixed[entry_id]
    if entry_id in (PLAYGO_HASH_TABLE, PLAYGO_FICM):
        return 11, entry_id
    if 0x1000 <= entry_id <= 0x1FFF:
        return 10, entry_id
    return 7, entry_id


def _keys_entry(content_id: str, passcode: str) -> bytes:
    """Serialize the container's entry-key record.

    Args:
        content_id: ASCII package content identifier.
        passcode: ASCII passcode for the package.

    Returns:
        Encoded entry-key payload.
    """
    padded = content_id.encode("ascii")[:48].ljust(48, b"\x00")
    output = bytearray(sha3(padded))
    derived = [derive_pfs_key(content_id, passcode, index) for index in range(7)]
    for key in derived:
        digest = sha3(key)
        output += bytes(a ^ b for a, b in zip(digest, key))
    for index, key in enumerate(derived):
        modulus = key_data.PASSCODE_MODULI[index * 384:(index + 1) * 384]
        message = passcode.encode("ascii") if index == 0 else key
        output += pkcs1_encrypt(modulus, message)
    return bytes(output)


def _image_key_entry(ekpfs: bytes) -> bytes:
    """Encode the image key as a fixed-size container entry.

    Args:
        ekpfs: Raw PFS image key.

    Returns:
        The padded image-key payload.
    """
    output = bytearray(0x800)
    at = 0
    while at < len(output):
        wrap = pkcs1_encrypt(key_data.MOUNT_IMAGE_MODULUS, ekpfs)
        take = min(len(wrap), len(output) - at)
        output[at:at + take] = wrap[:take]
        at += len(wrap)
    return bytes(output)


def _general_digests(head: bytes, descriptor: bytes, game_digest: bytes,
                     entry_digest) -> bytes:
    """Assemble the summary digests recorded in the container.

    Args:
        head: Main container header bytes.
        descriptor: Image descriptor bytes.
        game_digest: SHA3-256 digest of the outer superblock.
        entry_digest (Callable): Lookup from entry ID to raw digest, or None if
            absent.

    Returns:
        The general-digests payload.
    """
    output = bytearray(GENERAL_LEN)
    output[0x00:0x02] = (0xD256).to_bytes(2, "big")
    output[0x02:0x04] = (0x0102).to_bytes(2, "big")
    output[0x1C:0x20] = GENERAL_DIGEST_SET.to_bytes(4, "big")

    def slot(index: int, digest: bytes) -> None:
        """Store a digest in a numbered slot of the output buffer."""
        output[0x20 + index * 32:0x40 + index * 32] = digest

    pre = head[0x40:0x78] + game_digest + bytes(32)
    slot(0, sha3(pre))
    slot(1, game_digest)
    slot(2, sha3(head[0x00:0x40] + descriptor))
    system = b""
    for entry_id in SYSTEM_DIGEST_IDS:
        digest = entry_digest(entry_id)
        if digest is not None:
            system += digest
    if system:
        slot(3, sha3(system))
    param = entry_digest(PARAM_JSON)
    if param is not None:
        slot(5, param)
    chunk = entry_digest(PLAYGO_CHUNK)
    hash_table = entry_digest(PLAYGO_HASH_TABLE)
    ficm = entry_digest(PLAYGO_FICM)
    if chunk is not None and hash_table is not None and ficm is not None:
        slot(6, sha3(chunk + hash_table + ficm))
    slot(11, game_digest)
    return bytes(output)


@dataclass(slots=True)
class Facts:
    """Container geometry and hashes for install metadata.

    Attributes:
        container_size: Total padded container size in bytes.
        mandatory_size: Size of the prefix through the mandatory entries, in
            bytes.
        body_offset: Container-relative byte offset of the body.
        body_size: Length of the body, including trailing padding.
        body_digest: SHA3-256 digest of the padded body.
        package_digest: Digest recorded before the container signature.
        fih_digest: Digest of the finalized-image header.
        content_digest: Content identity digest from the general-digests entry.
        header_digest: Header and image descriptor digest.
        system_digest: Aggregate digest of system entries.
        param_digest: Digest of the param.json entry.
        entries: Named (offset, size, name) entries in physical order.
    """
    container_size: int
    mandatory_size: int
    body_offset: int
    body_size: int
    body_digest: bytes
    package_digest: bytes
    fih_digest: bytes
    content_digest: bytes
    header_digest: bytes
    system_digest: bytes
    param_digest: bytes
    entries: list[tuple[int, int, str]] = field(default_factory=list)


@dataclass(slots=True)
class Container:
    """A serialized content container and its metadata.

    Attributes:
        bytes: Complete serialized content container.
        facts: Layout and digest information for related install metadata.
    """
    bytes: bytes
    facts: Facts


@dataclass(slots=True)
class CntParams:
    """Inputs for writing a content container.

    Attributes:
        content_id: 36-character ASCII content identifier.
        param_json: Packaged title metadata.
        icon_png: PNG icon bytes, or empty if absent.
        icon_dds: DDS icon bytes, or empty if absent.
        extras: Additional named payloads.
        playgo_chunk: Serialized PlayGo chunk descriptor.
        playgo_hash_table: Serialized PlayGo file hash table.
        playgo_ficm: Serialized PlayGo file-to-chunk map.
        imagedigs: Outer image block digests in physical block order.
        game_digest: Digest of the outer superblock.
        fih_block: Serialized finalized-image header.
        outer_size: Outer image length in bytes.
        cnt_offset: Absolute offset of the container in the package.
        seed: Seed value recorded in the container.
        passcode: Passcode for the package's format records.
        content_type: Numeric content type for the title.
        drm_type: Numeric DRM type recorded by the writer.
        content_flags: Bit flags describing the package content.
        inner_size: Logical inner-image size in bytes.
    """
    content_id: str
    param_json: bytes
    icon_png: bytes
    icon_dds: bytes
    extras: list[ExtraEntry]
    playgo_chunk: bytes
    playgo_hash_table: bytes
    playgo_ficm: bytes
    imagedigs: list[bytes]
    game_digest: bytes
    fih_block: bytes
    outer_size: int
    cnt_offset: int
    seed: bytes
    passcode: str
    content_type: int
    drm_type: int
    content_flags: int
    inner_size: int


class _Body:
    """The aligned container payload buffer and its entry index.

    Attributes:
        bytes: Mutable buffer beginning with the reserved header region.
        spans: Container-relative offsets and declared lengths keyed by entry
            ID.
    """
    def __init__(self) -> None:
        """Reserve the header space and initialize the entry span index."""
        self.bytes = bytearray(BODY_AT)
        self.spans: dict[int, tuple[int, int]] = {}

    def add(self, entry_id: int, data: bytes) -> None:
        """Append an entry at the next 16-byte boundary.

        Args:
            entry_id: ID to associate with the new span.
            data: Bytes to append to the container body.
        """
        at = (len(self.bytes) + 15) // 16 * 16
        self.bytes += bytes(at - len(self.bytes))
        start = len(self.bytes)
        self.bytes += data
        self.spans[entry_id] = (start, len(data))

    def add_sized(self, entry_id: int, data: bytes, size: int) -> None:
        """Record an entry whose declared length differs from its stored bytes.

        Args:
            entry_id: ID to associate with the new span.
            data: Stored payload, including any padding.
            size: Declared payload length in bytes.
        """
        self.add(entry_id, data)
        self.spans[entry_id] = (self.spans[entry_id][0], size)

    def span(self, entry_id: int) -> tuple[int, int]:
        """Return an entry's relative byte offset and declared length."""
        return self.spans[entry_id]

    def payload(self, entry_id: int) -> bytes:
        """Read the declared bytes of an entry already stored in the body."""
        at, size = self.span(entry_id)
        return bytes(self.bytes[at:at + size])


def write(p: CntParams) -> Container:
    """Serialize the content container for a package.

    Args:
        p: Title metadata, payloads, image geometry, and digests.

    Returns:
        Padded container bytes and facts for the install manifest.

    Raises:
        ValueError: The content identifier is invalid or an entry ID is
            duplicated.
    """
    if len(p.content_id) != 36 or not p.content_id.isascii():
        raise ValueError("content id must be 36 ASCII characters")
    entries = list(ENTRIES)
    for extra in p.extras:
        if any(entry[0] == extra.id for entry in entries):
            raise ValueError(f"container entry {extra.id:#06x} given twice")
        flags = 0x80000000 if extra.key_index is not None else 0x08000000
        entries.append((extra.id, flags, extra.name))
    entries.sort(key=lambda entry: entry[0])
    count = len(entries)
    digest_table_len = count * 32
    ekpfs = derive_pfs_key(p.content_id, p.passcode, 1)

    names = bytearray(b"\x00")
    name_offsets = [0] * count
    for index, (_, _, name) in enumerate(entries):
        if not name:
            continue
        name_offsets[index] = len(names)
        names += name.encode("utf-8") + b"\x00"

    imagedigs = b"".join(bytes(reversed(digest)) for digest in p.imagedigs)
    keys_payload = _keys_entry(p.content_id, p.passcode)
    image_key_payload = _image_key_entry(ekpfs)
    general_placeholder = bytes(GENERAL_LEN)
    table_placeholder = bytes(digest_table_len)

    def payload_of(entry_id: int) -> bytes:
        """Look up a fixed or optional entry's bytes, defaulting to empty."""
        fixed = {
            ENTRY_KEYS: keys_payload, IMAGE_KEY: image_key_payload,
            GENERAL_DIGESTS: general_placeholder, METAS: table_placeholder,
            DIGESTS: table_placeholder, ENTRY_NAMES: bytes(names),
            PARAM_JSON: p.param_json, IMAGE_DIGESTS: imagedigs,
            PLAYGO_CHUNK: p.playgo_chunk, ICON0_PNG: p.icon_png,
            ICON0_DDS: p.icon_dds, PLAYGO_HASH_TABLE: p.playgo_hash_table,
            PLAYGO_FICM: p.playgo_ficm,
        }
        if entry_id in fixed:
            return fixed[entry_id]
        for extra in p.extras:
            if extra.id == entry_id:
                return extra.data
        return b""

    key_of = {extra.id: extra.key_index for extra in p.extras}
    order = sorted((entry[0] for entry in entries), key=_body_rank)
    body = _Body()
    for entry_id in order:
        data = payload_of(entry_id)
        if key_of.get(entry_id) is not None:
            padded = data + bytes(-len(data) % 16)
            body.add_sized(entry_id, padded, len(data))
        else:
            body.add(entry_id, data)
    body_end = len(body.bytes)
    padded_end = (body_end + c.BLOCK - 1) // c.BLOCK * c.BLOCK

    table = bytearray(digest_table_len)
    for index, (entry_id, flags1, _) in enumerate(entries):
        at, size = body.span(entry_id)
        row = table[index * 32:(index + 1) * 32]
        row[0x00:0x04] = entry_id.to_bytes(4, "big")
        row[0x04:0x08] = name_offsets[index].to_bytes(4, "big")
        row[0x08:0x0C] = flags1.to_bytes(4, "big")
        row[0x0C:0x10] = ((key_of.get(entry_id) or 0) << 12).to_bytes(4, "big")
        row[0x10:0x14] = at.to_bytes(4, "big")
        row[0x14:0x18] = size.to_bytes(4, "big")
        table[index * 32:(index + 1) * 32] = row

    for index, (entry_id, _, _) in enumerate(entries):
        key_index = key_of.get(entry_id)
        if key_index is None:
            continue
        row = bytes(table[index * 32:(index + 1) * 32])
        entry_key = derive_pfs_key(p.content_id, p.passcode, key_index)
        at, size = body.span(entry_id)
        end = (at + size + 15) // 16 * 16
        body.bytes[at:end] = encrypt_entry(row, entry_key, bytes(body.bytes[at:end]))
    metas_at = body.span(METAS)[0]
    body.bytes[metas_at:metas_at + digest_table_len] = table

    digests = bytearray(digest_table_len)
    for index, (entry_id, _, _) in enumerate(entries):
        if entry_id in (DIGESTS, GENERAL_DIGESTS):
            continue
        key_index = key_of.get(entry_id)
        if key_index is not None:
            at, size = body.span(entry_id)
            end = (at + size + 15) // 16 * 16
            digest = sha3(bytes(body.bytes[at:end]))
        else:
            digest = sha3(body.payload(entry_id))
        digests[index * 32:(index + 1) * 32] = digest

    head = bytearray(0x80)
    head[0:4] = b"\x7fCNT"
    head[0x04:0x08] = (0x20001).to_bytes(4, "big")
    head[0x08:0x0C] = (0x80000000).to_bytes(4, "big")
    head[0x0C:0x10] = (0xC).to_bytes(4, "big")
    head[0x10:0x14] = count.to_bytes(4, "big")
    head[0x14:0x16] = SC_ENTRY_COUNT.to_bytes(2, "big")
    head[0x16:0x18] = count.to_bytes(2, "big")
    metas_span = body.span(METAS)
    names_at = body.span(ENTRY_NAMES)[0]
    head[0x18:0x1C] = metas_span[0].to_bytes(4, "big")
    rollup_size = names_at - BODY_AT
    head[0x1C:0x20] = rollup_size.to_bytes(4, "big")
    head[0x20:0x28] = BODY_AT.to_bytes(8, "big")
    head[0x28:0x30] = (padded_end - BODY_AT).to_bytes(8, "big")
    head[0x30:0x38] = body.span(IMAGE_DIGESTS)[0].to_bytes(8, "big")
    head[0x40:0x64] = p.content_id.encode("ascii")
    head[0x70:0x74] = p.drm_type.to_bytes(4, "big")
    head[0x74:0x78] = p.content_type.to_bytes(4, "big")
    head[0x78:0x7C] = p.content_flags.to_bytes(4, "big")

    descriptor = bytearray(0x80)
    descriptor[0x00:0x04] = (1).to_bytes(4, "big")
    descriptor[0x04:0x08] = (1).to_bytes(4, "big")
    descriptor[0x08:0x0C] = (0xA0000000).to_bytes(4, "big")
    descriptor[0x0E:0x10] = (0x030C).to_bytes(2, "big")
    descriptor[0x10:0x18] = (0x10000).to_bytes(8, "big")
    descriptor[0x18:0x20] = p.outer_size.to_bytes(8, "big")
    si_offset = p.cnt_offset + padded_end
    descriptor[0x28:0x30] = si_offset.to_bytes(8, "big")
    descriptor[0x30:0x38] = si_offset.to_bytes(8, "big")
    descriptor[0x38:0x3C] = (0x10000).to_bytes(4, "big")

    def entry_digest(entry_id: int):
        """Look up a computed entry digest, or return None if absent."""
        for index, (current, _, _) in enumerate(entries):
            if current == entry_id:
                return bytes(digests[index * 32:(index + 1) * 32])
        return None

    body.bytes[0:0x80] = head
    body.bytes[0x400:0x480] = descriptor
    body.bytes[0x440:0x460] = p.game_digest
    body.bytes[0x460:0x480] = sha3(p.fih_block)
    general = _general_digests(bytes(body.bytes[0:0x80]),
                               bytes(body.bytes[0x400:0x480]),
                               p.game_digest, entry_digest)
    general_at = body.span(GENERAL_DIGESTS)[0]
    body.bytes[general_at:general_at + len(general)] = general
    general_index = next(index for index, entry in enumerate(entries)
                         if entry[0] == GENERAL_DIGESTS)
    digests[general_index * 32:(general_index + 1) * 32] = sha3(general)
    digest_at = body.span(DIGESTS)[0]
    body.bytes[digest_at:digest_at + len(digests)] = digests

    imagedigs_span = body.span(IMAGE_DIGESTS)
    image_key_span = body.span(IMAGE_KEY)
    image_key_digest = sha3(body.payload(IMAGE_KEY))
    imagedigs_digest = sha3(body.payload(IMAGE_DIGESTS))
    named = []
    for entry_id, _, name in entries:
        if name:
            at, size = body.span(entry_id)
            named.append((at, size, name))
    named.sort()
    sc_spans = [body.span(ENTRY_KEYS), body.span(IMAGE_KEY), body.span(GENERAL_DIGESTS),
                (metas_span[0], SC_ENTRY_COUNT * ENTRY_ROW)]
    container = bytearray(body.bytes)
    container += bytes(padded_end - len(container))
    container[0x7C:0x80] = padded_end.to_bytes(4, "big")
    container[0x80:0x84] = (0x20240508).to_bytes(4, "big")
    container[0x84:0x88] = (0x090FBFC1).to_bytes(4, "big")
    container[0x200:0x224] = head[0x40:0x64]
    container[0x4A0:0x4B0] = p.seed
    container[0x4B0:0x4B8] = p.cnt_offset.to_bytes(8, "big")
    container[0x4B8:0x4C0] = padded_end.to_bytes(8, "big")
    container[0x510:0x514] = image_key_span[0].to_bytes(4, "big")
    container[0x514:0x518] = image_key_span[1].to_bytes(4, "big")
    container[0x518:0x51C] = imagedigs_span[0].to_bytes(4, "big")
    container[0x51C:0x520] = imagedigs_span[1].to_bytes(4, "big")
    container[0x520:0x540] = image_key_digest
    container[0x540:0x560] = imagedigs_digest

    rollup = sha3(bytes(container[BODY_AT:BODY_AT + rollup_size]))
    container[0x100:0x120] = rollup
    sc2 = b"".join(bytes(container[at:at + size]) for at, size in sc_spans)
    container[0x120:0x140] = sha3(sc2)
    container[0x140:0x160] = sha3(bytes(digests))
    body_digest = sha3(bytes(container[BODY_AT:padded_end]))
    container[0x160:0x180] = body_digest
    package_digest = sha3(bytes(container[:PACKAGE_DIGEST_AT]))
    container[PACKAGE_DIGEST_AT:SIGNATURE_AT] = package_digest
    signature = pkcs1_encrypt(key_data.METADATA_MODULUS,
                              sha3(bytes(container[:SIGNATURE_AT])))
    container[SIGNATURE_AT:SIGNATURE_AT + len(signature)] = signature

    def slot(index: int) -> bytes:
        """Read one digest from the completed general-digests entry."""
        return general[0x20 + index * 32:0x40 + index * 32]

    facts = Facts(
        container_size=padded_end,
        mandatory_size=imagedigs_span[0],
        body_offset=BODY_AT,
        body_size=padded_end - BODY_AT,
        body_digest=body_digest,
        package_digest=package_digest,
        fih_digest=sha3(p.fih_block),
        content_digest=slot(0),
        header_digest=slot(2),
        system_digest=slot(3),
        param_digest=slot(5),
        entries=named,
    )
    return Container(bytes(container), facts)
