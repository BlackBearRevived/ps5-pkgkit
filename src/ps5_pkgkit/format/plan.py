"""Pure layout plan for a package's inner image.

Every offset is fixed here before a byte is read. The template mirrors measured
debug packages: the image is data-first, files are packed in afid order, and the
metadata region (superblock, inode table, flat-path tables, afid table and
directory blocks) sits on a 256 KiB aligned base above the data.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from . import constants as c
from .dirents import dirents_bytes
from .flt import (
    FLAG_EMPTY,
    hash_path,
    pack_apr_entry,
    pack_inode_entry,
    write as write_table,
)


@dataclass(slots=True)
class PlannedFile:
    """A file and its assigned positions in the inner image.

    Attributes:
        path: Slash-separated path within the inner image.
        size: Payload length in bytes.
        inode: Assigned inode number.
        afid: Assigned application file ID.
        logical_offset: Payload offset in the logical mount.
        on_disk_offset: Payload offset in the stored inner layout.
        parent_inode: Inode number of the containing directory.
        dirent_offset: Byte offset of the entry in the parent directory.
        sce_sys: Whether the file belongs to the system metadata tree.
        generated: Whether the builder provides the payload.
        module: Whether the payload is an executable module.
    """
    path: str
    size: int
    inode: int = 0
    afid: int = 0
    logical_offset: int = 0
    on_disk_offset: int = 0
    parent_inode: int = 0
    dirent_offset: int = -1
    sce_sys: bool = False
    generated: bool = False
    module: bool = False

    @property
    def mode(self) -> int:
        """The inode mode for a system or regular payload file."""
        return c.MODE_FILE_SCE_SYS if self.sce_sys else c.MODE_FILE

    @property
    def inode_flags(self) -> int:
        """The inode flags for the file's type and location."""
        kind = c.FLAGS_MODULE if self.module else c.FLAGS_BLOB
        return c.FLAGS_DATA | kind | (c.FLAGS_SCE_SYS if self.sce_sys else 0)


@dataclass(slots=True)
class PlannedDir:
    """A directory in the planned inner image.

    Attributes:
        path: Slash-separated path, empty for uroot.
        inode: Assigned inode number.
        parent_inode: Inode number of the parent directory.
        nlink: Directory link count.
        dirents: Entries as (name, inode, kind) triples in directory order.
        dirent_offset: Byte offset in the parent directory, or -1 if not
            assigned.
    """
    path: str
    inode: int
    parent_inode: int
    nlink: int
    dirents: list[tuple[str, int, int]]
    dirent_offset: int = -1

    @property
    def sce_sys(self) -> bool:
        """Whether this directory is sce_sys or one of its descendants."""
        return self.path == "sce_sys" or self.path.startswith("sce_sys/")


@dataclass(slots=True)
class MetadataLayout:
    """Locations of the inner metadata tables and directory streams.

    A span is a pair of logical byte offset and length.

    Attributes:
        inode_table: Span of the inode table.
        super_root: Span of the super-root directory entries.
        flt: Span of the inode flat-path table.
        flt_apr: Span of the application file flat-path table.
        afid: Span of the application file ID to inode table.
        dirs: Directory spans in plan directory order.
        blocks: Total metadata length in blocks.
    """
    inode_table: tuple[int, int] = (0, 0)
    super_root: tuple[int, int] = (0, 0)
    flt: tuple[int, int] = (0, 0)
    flt_apr: tuple[int, int] = (0, 0)
    afid: tuple[int, int] = (0, 0)
    dirs: list[tuple[int, int]] = field(default_factory=list)
    blocks: int = 0


@dataclass(slots=True)
class Plan:
    """Hold file placements, lookup tables, and inner image geometry.

    Attributes:
        dirs: Planned directories in inode order.
        files: Planned files in inode order.
        afid_order: Indices into files, sorted by application file ID.
        flt_inode: Path hash and payload pairs for the inode flat-path table.
        flt_apr: Path hash and payload pairs for the APR flat-path table.
        afid_to_ino: Inode number for each application file ID.
        first_file_inode: Inode number assigned to the first file.
        data_end: Stored byte offset after the file data and alignment padding.
        meta_base: Logical byte offset at which metadata starts.
        ndblock: Total mount length in blocks.
        metadata_blocks: Metadata length in blocks.
        metadata: Spans for the metadata structures.
        content_inodes: Number of content files and non-root directories.
        app_file_count: Number of application payload files.
    """
    dirs: list[PlannedDir]
    files: list[PlannedFile]
    afid_order: list[int]
    flt_inode: list[tuple[int, int]]
    flt_apr: list[tuple[int, int]]
    afid_to_ino: list[int]
    first_file_inode: int
    data_end: int
    meta_base: int
    ndblock: int
    metadata_blocks: int
    metadata: MetadataLayout
    content_inodes: int
    app_file_count: int

    def has_eboot(self) -> bool:
        """Check whether the plan contains a root eboot.bin."""
        return any(f.path == "eboot.bin" for f in self.files)

    def inner_files(self) -> list[tuple[str, int, int]]:
        """Return (path, logical offset, size) triples in AFID order."""
        return [
            (self.files[index].path, self.files[index].logical_offset, self.files[index].size)
            for index in self.afid_order
        ]

    def mount_files(self) -> list[tuple[str, int, int]]:
        """Return (path, mount offset, size) triples in inode order."""
        base = c.BLOCK
        return [(f.path, base + f.on_disk_offset, f.size) for f in self.files]

    def placements(self) -> list[tuple[int, int, int]]:
        """Return file placements in AFID order.

        Returns:
            Triples of logical byte offset, stored byte offset, and length.
        """
        return [
            (self.files[index].logical_offset, self.files[index].on_disk_offset,
             self.files[index].size)
            for index in self.afid_order
        ]

    def mark_modules(self, is_module: Callable[[str], bool]) -> None:
        """Update the plan's module flags using a path predicate.

        Args:
            is_module: Callable that accepts one file path and returns whether
                its contents identify a module. It is called only for
                non-generated files at least four bytes long.
        """
        for planned in self.files:
            planned.module = (
                not planned.generated and planned.size >= 4 and bool(is_module(planned.path))
            )


def is_module_header(head: bytes) -> bool:
    """Check for a PS4 or PS5 SELF or plain ELF header.

    Args:
        head: Leading file bytes to test against the recognized signatures.

    Returns:
        True if the first four bytes identify a supported module.
    """
    return len(head) >= 4 and head[:4] in (
        c.SELF_PS5, c.SELF_PS4, c.SIGNED_SELF, c.RAW_ELF,
    )


def super_root_dirents() -> list[tuple[str, int, int]]:
    """Return entries for the flat-path tables, AFID table, and uroot."""
    return [
        ("inode_flat_path_table", c.INODE_FLT_INODE, c.DIRENT_FILE),
        ("apr_flat_path_table", c.APR_FLT_INODE, c.DIRENT_FILE),
        ("afid_to_ino_table", c.AFID_TABLE_INODE, c.DIRENT_FILE),
        ("uroot", c.FIRST_DIR_INODE, c.DIRENT_DIR),
    ]


@dataclass(slots=True)
class _DirNode:
    """A directory's tree links and inode fields during planning.

    Attributes:
        path: Slash-separated path relative to uroot.
        name: Final path component.
        parent: Index of the parent node, or None at the root.
        subdirs: Child directory indices.
        files: File indices belonging directly to this directory.
        inode: Assigned inode number.
        dirent_offset: Byte offset in the parent directory.
        nlink: Directory link count.
    """
    path: str
    name: str
    parent: int | None
    subdirs: list[int] = field(default_factory=list)
    files: list[int] = field(default_factory=list)
    inode: int = 0
    dirent_offset: int = -1
    nlink: int = 1


def _ensure_dir(dirs: list[_DirNode], index: dict[str, int], path: str) -> int:
    """Find a directory index, creating the directory and ancestors as needed.

    Args:
        dirs: Mutable directory tree.
        index: Mutable map from relative paths to directory indices.
        path: Slash-separated directory path, with an empty root path.

    Returns:
        Index of the directory in dirs.
    """
    found = index.get(path)
    if found is not None:
        return found
    if "/" in path:
        parent_path, name = path.rsplit("/", 1)
    else:
        parent_path, name = "", path
    parent = _ensure_dir(dirs, index, parent_path)
    position = len(dirs)
    dirs.append(_DirNode(path, name, parent))
    dirs[parent].subdirs.append(position)
    index[path] = position
    return position


def _pre_order(dirs: list[_DirNode], start: int, output: list[int]) -> None:
    """Append directory indices in parent-before-children order."""
    output.append(start)
    for child in dirs[start].subdirs:
        _pre_order(dirs, child, output)


def _post_order(dirs: list[_DirNode], start: int, output: list[int]) -> None:
    """Append directory indices in children-before-parent order."""
    for child in dirs[start].subdirs:
        _post_order(dirs, child, output)
    output.append(start)


def _collect_files_pre(dirs: list[_DirNode], start: int, output: list[int]) -> None:
    """Append file indices while visiting parents before their children."""
    output.extend(dirs[start].files)
    for child in dirs[start].subdirs:
        _collect_files_pre(dirs, child, output)


def _is_under(dirs: list[_DirNode], node: int, ancestor: int | None) -> bool:
    """Check whether a directory equals or descends from an ancestor."""
    if ancestor is None:
        return False
    while True:
        if node == ancestor:
            return True
        parent = dirs[node].parent
        if parent is None:
            return False
        node = parent


def _file_name(path: str) -> str:
    """Return the final component of a slash-separated path."""
    return path.rsplit("/", 1)[-1]


def _parent_path(path: str) -> str:
    """Return the parent path, using an empty string for the root."""
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _check_case_collisions(paths: Iterable[str]) -> None:
    """Reject case-insensitive collisions in paths and their ancestors.

    Args:
        paths: Slash-separated file or directory paths to check.

    Raises:
        ValueError: Two distinct spellings share the same uppercase path.
    """
    seen: dict[str, str] = {}
    for path in paths:
        end = len(path)
        while True:
            prefix = path[:end]
            folded = prefix.upper()
            other = seen.setdefault(folded, prefix)
            if other != prefix:
                raise ValueError(
                    f"{other!r} and {prefix!r} differ only by letter case, "
                    "which the image cannot tell apart"
                )
            cut = path.rfind("/", 0, end)
            if cut < 0:
                break
            end = cut


def build_tree(
    files: Sequence[tuple[str, int]],
    empty_dirs: Sequence[str] = (),
    *,
    spread: bool = False,
) -> Plan:
    """Plan the inner image from file sizes and directory paths.

    Args:
        files: Pairs of slash-separated relative file path and payload size in
            bytes.
        empty_dirs: Empty directories to preserve in the layout.
        spread: Whether to space file starts and reserve extra room before
            metadata for the compressed layout.

    Returns:
        Assigned inodes, file placements, lookup tables, and metadata geometry.

    Raises:
        ValueError: No files were supplied or distinct paths have the same
            uppercase spelling.
    """
    if not files:
        raise ValueError("the source tree has no files")
    planned: list[PlannedFile] = [
        PlannedFile(path, size, sce_sys=path.startswith("sce_sys/"))
        for path, size in files
    ]
    if not any(item.path == c.KEYSTONE for item in planned):
        planned.append(
            PlannedFile(c.KEYSTONE, c.KEYSTONE_LEN, sce_sys=True, generated=True)
        )
    planned.sort(key=lambda item: item.path)

    _check_case_collisions(
        [item.path for item in planned] + [path.strip("/") for path in empty_dirs]
    )

    dirs: list[_DirNode] = [_DirNode("", "uroot", None)]
    index: dict[str, int] = {"": 0}
    for position, item in enumerate(planned):
        parent_path = _parent_path(item.path)
        di = 0 if parent_path == "" else _ensure_dir(dirs, index, parent_path)
        dirs[di].files.append(position)
    for path in empty_dirs:
        path = path.strip("/")
        if path:
            _ensure_dir(dirs, index, path)

    dir_names = [node.name for node in dirs]
    for node in dirs:
        node.subdirs.sort(key=lambda child: dir_names[child])
    names = [item.path for item in planned]
    for node in dirs:
        node.files.sort(key=lambda fi: names[fi])

    dirs_pre: list[int] = []
    _pre_order(dirs, 0, dirs_pre)
    dirs_post: list[int] = []
    _post_order(dirs, 0, dirs_post)

    next_inode = c.FIRST_DIR_INODE
    for di in dirs_pre:
        dirs[di].inode = next_inode
        next_inode += 1
    file_order: list[int] = []
    for di in dirs_post:
        for fi in dirs[di].files:
            planned[fi].inode = next_inode
            next_inode += 1
            file_order.append(fi)
    first_file_inode = c.FIRST_DIR_INODE + len(dirs)

    sce_sys_dir = next((di for di in dirs_pre if dirs[di].path == "sce_sys"), None)
    afid_order: list[int] = []
    if sce_sys_dir is not None:
        subtree: list[int] = []
        _collect_files_pre(dirs, sce_sys_dir, subtree)
        afid_order.extend(subtree)
    for di in dirs_pre:
        if di == sce_sys_dir or _is_under(dirs, di, sce_sys_dir):
            continue
        afid_order.extend(dirs[di].files)
    keystone_at = next(
        (position for position, fi in enumerate(afid_order)
         if planned[fi].path == c.KEYSTONE),
        None,
    )
    if keystone_at is not None:
        afid_order.insert(0, afid_order.pop(keystone_at))
    for afid, fi in enumerate(afid_order):
        planned[fi].afid = afid

    cursor = 0
    on_disk = 0
    starts_ublock = 0
    starts_count = 0
    last_start: int | None = None
    for fi in afid_order:
        item = planned[fi]
        if spread and last_start is not None and cursor // 16 == last_start // 16:
            cursor = (last_start // 16 + 1) * 16
        last_start = cursor
        if starts_ublock != cursor // c.UBLOCK:
            starts_ublock, starts_count = cursor // c.UBLOCK, 0
        if item.size > 0:
            starts_count += 1
        item.logical_offset = cursor
        item.on_disk_offset = on_disk
        item.parent_inode = dirs[index[_parent_path(item.path)]].inode
        cursor += item.size
        on_disk = c.align_up(on_disk + item.size, c.FILE_ALIGN)
        if (spread and item.size > 0 and starts_count >= c.MAX_STARTS_PER_UBLOCK
                and cursor // c.UBLOCK == starts_ublock):
            following = c.align_up(cursor, c.UBLOCK)
            if following <= on_disk:
                cursor = following
    data_end = on_disk

    planned_dirs: list[PlannedDir] = []
    for di in dirs_pre:
        node = dirs[di]
        is_root = node.parent is None
        parent_inode = dirs[node.parent].inode if node.parent is not None else -1
        dirents: list[tuple[str, int, int]] = [
            (".", node.inode, c.DIRENT_DOT),
            ("..", node.inode if is_root else parent_inode, c.DIRENT_DOTDOT),
        ]
        for child in node.subdirs:
            dirents.append((dirs[child].name, dirs[child].inode, c.DIRENT_DIR))
        for fi in node.files:
            dirents.append((_file_name(planned[fi].path), planned[fi].inode, c.DIRENT_FILE))

        from .dirents import dirent_extents

        extents = dirent_extents(name for name, _, _ in dirents)
        subdir_ordinal = 0
        file_ordinal = 0
        for (_, _, kind), (at, _) in zip(dirents, extents):
            if kind == c.DIRENT_DIR:
                dirs[node.subdirs[subdir_ordinal]].dirent_offset = at
                subdir_ordinal += 1
            elif kind == c.DIRENT_FILE:
                planned[node.files[file_ordinal]].dirent_offset = at
                file_ordinal += 1
        node.nlink = 2 + len(node.subdirs) + (1 if is_root else 0)
        planned_dirs.append(
            PlannedDir(node.path, node.inode, parent_inode, node.nlink, dirents,
                       node.dirent_offset)
        )

    position = [0] * len(planned)
    for new, old in enumerate(file_order):
        position[old] = new
    files_in_order = [planned[old] for old in file_order]
    afid_in_order = [position[old] for old in afid_order]

    flt_inode: list[tuple[int, int]] = []
    for directory in planned_dirs[1:]:
        flt_inode.append(
            (hash_path(directory.path),
             pack_inode_entry(directory.inode, True, directory.sce_sys, 0))
        )
    flt_apr: list[tuple[int, int]] = []
    for item in files_in_order:
        apr = not item.sce_sys
        empty = FLAG_EMPTY if item.size == 0 else 0
        flt_inode.append(
            (hash_path(item.path),
             pack_inode_entry(item.inode, False, not apr, item.afid) | empty)
        )
        if apr:
            flt_apr.append((hash_path(item.path), pack_apr_entry(item.size, item.afid)))

    afid_to_ino: list[int] = [0]
    afid_to_ino.extend(files_in_order[fi].inode for fi in afid_in_order)
    afid_to_ino.extend([-1, -1])
    afid_to_ino[0] = len(afid_to_ino) - 1

    if spread:
        logical_end = max(
            (item.logical_offset + item.size for item in files_in_order), default=0
        )
        meta_base = (
            (logical_end + c.COMPRESSED_META_GAP) // c.META_ALIGN * c.META_ALIGN
        )
    else:
        meta_base = c.align_up(data_end + c.BLOCK, c.META_ALIGN)

    super_root = super_root_dirents()
    inode_bytes = c.inode_table_len(4 + len(planned_dirs) + len(files_in_order))
    flt_bytes = len(write_table(flt_inode))
    flt_apr_bytes = len(write_table(flt_apr))
    afid_bytes = len(afid_to_ino) * 4

    at = meta_base + c.BLOCK
    metadata = MetadataLayout(inode_table=(at, inode_bytes), dirs=[])
    at += c.align_up(inode_bytes, c.BLOCK)

    def place(byte_count: int) -> tuple[int, int]:
        """Reserve a block-aligned metadata span and advance the cursor."""
        nonlocal at
        span = (at, byte_count)
        at += c.align_up(byte_count, c.BLOCK)
        return span

    metadata.super_root = place(len(dirents_bytes(super_root)))
    metadata.flt = place(flt_bytes)
    metadata.flt_apr = place(flt_apr_bytes)
    metadata.afid = place(afid_bytes)
    metadata.dirs = [place(len(dirents_bytes(directory.dirents))) for directory in planned_dirs]
    metadata_blocks = (at - meta_base) // c.BLOCK + 1
    metadata.blocks = metadata_blocks

    return Plan(
        dirs=planned_dirs,
        files=files_in_order,
        afid_order=afid_in_order,
        flt_inode=flt_inode,
        flt_apr=flt_apr,
        afid_to_ino=afid_to_ino,
        first_file_inode=first_file_inode,
        data_end=data_end,
        meta_base=meta_base,
        ndblock=meta_base // c.BLOCK + metadata_blocks,
        metadata_blocks=metadata_blocks,
        metadata=metadata,
        content_inodes=len(files_in_order) + len(dirs) - 1,
        app_file_count=sum(
            1 for item in files_in_order
            if not item.sce_sys and _file_name(item.path) != c.PFS_VERSION_DAT
        ),
    )
