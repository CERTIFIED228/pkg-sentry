"""Read package archives in memory, without trusting anything inside them.

Nothing is ever written to disk. The archive can still try to hurt the
scanner, so every member is checked: no links, no paths that climb out of
the package, size limits per file and in total, and a ratio check for zip
bombs. Anything skipped is reported rather than silently dropped.
"""

import io
import lzma
import posixpath
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field


class ArchiveError(Exception):
    pass


@dataclass(frozen=True)
class Limits:
    max_files: int = 20_000
    max_file_bytes: int = 25_000_000
    max_total_bytes: int = 300_000_000
    # Declared sizes of everything, read or not. Skipping a member of a
    # compressed tar still means decompressing it, so this caps the work.
    max_declared_bytes: int = 2_000_000_000
    max_ratio: int = 200


@dataclass(frozen=True)
class File:
    path: str
    data: bytes

    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


@dataclass
class Unpacked:
    files: list[File] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    # Things a real package has no reason to contain (path traversal, links out).
    suspicious: list[tuple[str, str]] = field(default_factory=list)

    def strip_top_dir(self) -> "Unpacked":
        """Drop a folder that every path starts with (package/, name-1.0/)."""
        tops = {f.path.split("/", 1)[0] for f in self.files}
        if len(tops) != 1 or not all("/" in f.path for f in self.files):
            return self
        cut = len(tops.pop()) + 1
        self.files = [File(f.path[cut:], f.data) for f in self.files]
        return self


DEFAULT_LIMITS = Limits()


BROKEN = (tarfile.TarError, EOFError, OSError, ValueError, zlib.error, lzma.LZMAError)


def unpack(
    data: bytes, limits: Limits = DEFAULT_LIMITS, password: bytes | None = None,
    npm: bool = False,
) -> Unpacked:
    """npm=True reads a tarball the way npm installs it (see npm_path)."""
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return _unpack_zip(data, limits, password)
    try:
        # Streaming mode, so tarfile doesn't keep every entry in memory.
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r|*")
    except BROKEN as e:
        raise ArchiveError(f"not a zip or tar archive ({e})") from None
    with archive:
        return _unpack_tar(archive, limits, npm_path if npm else clean_path)


def npm_path(name: str) -> str | None:
    """Where npm puts an entry. Like node-tar with strip: 1, it drops the first
    part of every path whatever it's called (not just a shared "package/"),
    then any leading "/": "anything/index.js" lands as index.js and
    "/abs/x.js" as abs/x.js. Later entries overwrite earlier ones."""
    rest = "/".join(name.replace("\\", "/").split("/")[1:]).lstrip("/")
    if len(rest) > 1 and rest[1] == ":":
        rest = rest[2:].lstrip("/")
    if not rest.strip("/."):
        return ""
    return clean_path(rest)


def clean_path(name: str) -> str | None:
    """A safe relative path, or None if the name tries to leave the package."""
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts or not parts:
        return None
    return posixpath.join(*parts)


class _Budget:
    def __init__(self, limits: Limits, result: Unpacked):
        self.limits, self.result = limits, result
        self.count = self.total = self.declared = 0

    def count_entry(self) -> None:
        # Folders and links count too: millions of empty entries are a DoS.
        self.count += 1
        if self.count > self.limits.max_files:
            raise _Stop(f"more than {self.limits.max_files:,} entries")

    def allow(self, name: str, size: int) -> bool:
        limits, result = self.limits, self.result
        self.declared += size
        if self.declared > limits.max_declared_bytes:
            raise _Stop(f"more than {limits.max_declared_bytes:,} bytes unpacked")
        if size > limits.max_file_bytes:
            result.skipped.append((name, f"{size:,} bytes, too big to scan"))
            return False
        if self.total + size > limits.max_total_bytes:
            raise _Stop(f"more than {limits.max_total_bytes:,} bytes to scan")
        self.total += size
        return True


class _Stop(Exception):
    pass


def _unpack_tar(archive: tarfile.TarFile, limits: Limits, place) -> Unpacked:
    result = Unpacked()
    budget = _Budget(limits, result)
    files: dict[str, File] = {}
    try:
        for member in archive:
            archive.members.clear()
            budget.count_entry()
            path = place(member.name)
            if path == "":
                continue
            if path is None:
                result.suspicious.append((member.name, "path points outside the package"))
                continue
            if member.issym() or member.islnk():
                kind = "symlink" if member.issym() else "hard link"
                target = member.linkname
                # Symlinks are relative to their folder, hard links to the archive root.
                base = posixpath.dirname(path) if member.issym() else ""
                if clean_path(posixpath.normpath(posixpath.join(base, target))) is None:
                    result.suspicious.append((path, f"{kind} to {target}"))
                else:
                    result.skipped.append((path, kind))
                continue
            if not member.isfile() or not budget.allow(path, member.size):
                continue
            handle = archive.extractfile(member)
            files[path] = File(path, handle.read(member.size) if handle else b"")
    except _Stop as e:
        result.skipped.append(("*", f"stopped reading: {e}"))
    except BROKEN as e:
        result.skipped.append(("*", f"archive is damaged: {e}"))
    result.files = list(files.values())
    return result


def _unpack_zip(data: bytes, limits: Limits, password: bytes | None) -> Unpacked:
    result = Unpacked()
    budget = _Budget(limits, result)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError) as e:
        raise ArchiveError(f"damaged zip ({e})") from None
    with archive:
        try:
            for info in archive.infolist():
                budget.count_entry()
                if info.is_dir():
                    continue
                path = clean_path(info.filename)
                if path is None:
                    result.suspicious.append((info.filename, "path points outside the package"))
                    continue
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > limits.max_ratio and info.file_size > 1_000_000:
                    result.suspicious.append((path, f"compressed {ratio:.0f}:1, a zip bomb"))
                    continue
                if not budget.allow(path, info.file_size):
                    continue
                try:
                    with archive.open(info, pwd=password) as handle:
                        # The header's size can lie, so cap the read too.
                        body = handle.read(limits.max_file_bytes + 1)
                except (RuntimeError, zipfile.BadZipFile, NotImplementedError, *BROKEN) as e:
                    result.skipped.append((path, f"can't be read: {e}"))
                    continue
                if len(body) > limits.max_file_bytes:
                    result.suspicious.append((path, "bigger than its header says"))
                    continue
                result.files.append(File(path, body))
        except _Stop as e:
            result.skipped.append(("*", f"stopped reading: {e}"))
    return result
