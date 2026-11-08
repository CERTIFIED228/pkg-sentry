import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from pkg_sentry.archive import ArchiveError, File, Limits, Unpacked, clean_path, npm_path, unpack

DATA = Path(__file__).parent / "data"


def make_tar(members, mode="w:gz"):
    """members: list of (name, bytes) or (name, ("sym"|"lnk", target))."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, body in members:
            info = tarfile.TarInfo(name)
            if isinstance(body, tuple):
                info.type = tarfile.SYMTYPE if body[0] == "sym" else tarfile.LNKTYPE
                info.linkname = body[1]
                tar.addfile(info)
            else:
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members:
            zf.writestr(name, body)
    return buf.getvalue()


def paths(result):
    return sorted(f.path for f in result.files)


@pytest.mark.parametrize("mode", ["w:gz", "w:bz2", "w:xz", "w"])
def test_reads_every_tar_flavour(mode):
    data = make_tar([("package/index.js", b"x"), ("package/package.json", b"{}")], mode)
    assert paths(unpack(data)) == ["package/index.js", "package/package.json"]


def test_reads_zip_and_wheel():
    data = make_zip([("pkg/__init__.py", b"print(1)"), ("pkg-1.0.dist-info/METADATA", b"")])
    result = unpack(data)
    assert paths(result) == ["pkg-1.0.dist-info/METADATA", "pkg/__init__.py"]
    assert {f.path: f.text() for f in result.files}["pkg/__init__.py"] == "print(1)"


def test_not_an_archive():
    with pytest.raises(ArchiveError):
        unpack(b"just some text")


@pytest.mark.parametrize(
    "name", ["../../.bashrc", "/etc/cron.d/evil", "a/../../b", "C:/Windows/evil.exe", "..\\x"]
)
def test_path_traversal_is_reported_not_read(name):
    for data in (make_tar([(name, b"bad"), ("ok.py", b"")]), make_zip([(name, b"bad")])):
        result = unpack(data)
        assert name not in paths(result)
        reported = [s[0].replace("\\", "/") for s in result.suspicious]
        assert reported == [name.replace("\\", "/")]


def test_links_are_never_followed():
    data = make_tar([
        ("package/a.js", b"1"),
        ("package/inside", ("sym", "a.js")),
        ("package/up", ("sym", "../../../home/user/.ssh/id_rsa")),
        ("package/abs", ("sym", "/etc/passwd")),
        ("package/hard", ("lnk", "/etc/shadow")),
        ("package/hard-ok", ("lnk", "package/a.js")),
    ])
    result = unpack(data)
    assert paths(result) == ["package/a.js"]
    assert sorted(s[0] for s in result.suspicious) == ["package/abs", "package/hard", "package/up"]
    assert sorted(s[0] for s in result.skipped) == ["package/hard-ok", "package/inside"]


def test_big_files_are_skipped_and_reported():
    data = make_tar([("big.bin", b"x" * 2000), ("small.py", b"pass")])
    result = unpack(data, Limits(max_file_bytes=1000))
    assert paths(result) == ["small.py"]
    assert result.skipped == [("big.bin", "2,000 bytes, too big to scan")]


def test_stops_after_too_many_files():
    data = make_tar([(f"f{i}.py", b"") for i in range(10)])
    result = unpack(data, Limits(max_files=3))
    assert len(result.files) == 3
    assert "more than 3 entries" in result.skipped[-1][1]


def test_stops_when_total_is_too_big():
    data = make_zip([(f"f{i}", b"x" * 400) for i in range(5)])
    result = unpack(data, Limits(max_total_bytes=1000))
    assert len(result.files) == 2
    assert "stopped reading" in result.skipped[-1][1]


def test_zip_bomb_is_not_decompressed():
    data = make_zip([("bomb.txt", b"\0" * 5_000_000), ("ok.py", b"pass")])
    result = unpack(data)
    assert paths(result) == ["ok.py"]
    assert "zip bomb" in result.suspicious[0][1]


def test_encrypted_zip_needs_the_password():
    # Made with `zip -P infected`, the format malware datasets are shared in.
    blob = (DATA / "encrypted.zip").read_bytes()
    locked = unpack(blob)
    assert locked.files == []
    assert "can't be read" in locked.skipped[0][1]
    assert unpack(blob, password=b"infected").files == [File("me.py", b"hello")]


def test_damaged_tar_keeps_what_was_read():
    data = make_tar([("a.py", b"1" * 600), ("b.py", b"2" * 600)], mode="w")
    result = unpack(data[:1500])
    assert "a.py" in paths(result)


def test_strip_top_dir():
    result = Unpacked([File("package/index.js", b""), File("package/lib/a.js", b"")])
    assert paths(result.strip_top_dir()) == ["index.js", "lib/a.js"]
    mixed = Unpacked([File("a/x", b""), File("b/y", b"")])
    assert paths(mixed.strip_top_dir()) == ["a/x", "b/y"]
    flat = Unpacked([File("setup.py", b"")])
    assert paths(flat.strip_top_dir()) == ["setup.py"]


@pytest.mark.parametrize(
    "name, expected",
    [("a/b.py", "a/b.py"), ("./a//b.py", "a/b.py"), ("a\\b.py", "a/b.py"), ("../x", None),
     ("/x", None), ("", None), (".", None)],
)
def test_clean_path(name, expected):
    assert clean_path(name) == expected


def test_npm_layout_drops_the_first_folder_of_every_entry():
    data = make_tar([("aaa/package.json", b'{"name": "decoy"}'),
                     ("package/package.json", b'{"name": "real"}'),
                     ("zzz/lib/index.js", b"x"),
                     ("/abs/evil.js", b"y"),
                     ("toplevel.js", b"z")])
    result = unpack(data, npm=True)
    files = {f.path: f.data for f in result.files}
    # npm keeps the last package.json, installs what it finds under any folder,
    # and for "/abs/evil.js" the empty part before the "/" is what gets dropped
    assert files == {"package.json": b'{"name": "real"}', "lib/index.js": b"x",
                     "abs/evil.js": b"y"}


@pytest.mark.parametrize(
    "name, expected",
    [("package/index.js", "index.js"), ("./x/index.js", "x/index.js"), ("index.js", ""),
     ("a//b/c.js", "b/c.js"), ("package/../x", None),
     # only "/" separates folders, the way npm reads it on Linux and macOS
     ("package\\lib\\a.js", ""), ("z\\tests/index.js", "index.js")],
)
def test_npm_paths(name, expected):
    assert npm_path(name) == expected


def test_npm_layout_still_reports_climbing_out():
    result = unpack(make_tar([("package/../../x.js", b"x")]), npm=True)
    assert result.files == [] and result.suspicious


def test_folders_and_links_count_towards_the_entry_limit():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for i in range(50):
            info = tarfile.TarInfo(f"d{i}")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
    result = unpack(buf.getvalue(), Limits(max_files=10))
    assert "more than 10 entries" in result.skipped[-1][1]


def test_corrupt_zip_member_is_reported_not_raised():
    data = bytearray(make_zip([("a.py", b"print(1)" * 500), ("b.py", b"ok")]))
    start = data.index(b"a.py") + 10
    data[start:start + 40] = b"\xff" * 40
    result = unpack(bytes(data))
    assert any("can't be read" in why for _, why in result.skipped)


def test_backslashes_in_npm_paths_are_suspicious():
    # On Linux, npm reads "z\tests/index.js" as a folder called "z\tests".
    data = make_tar([("package/package.json", b"{}"), ("z\\tests/index.js", b"x")])
    result = unpack(data, npm=True)
    assert {f.path for f in result.files} == {"package.json", "index.js"}
    assert result.suspicious == [("z\\tests/index.js", "has a backslash in its path")]


def raw_tar(members, end=True):
    """An uncompressed tar, optionally without its end-of-archive blocks."""
    data = make_tar(members, mode="w")
    if end:
        return data
    data = data.rstrip(b"\0")
    return data + b"\0" * (-len(data) % 512)


def test_every_gzip_member_is_read():
    first = raw_tar([("x-1.0/setup.py", b"benign")], end=False)
    second = raw_tar([("x-1.0/setup.py", b"evil")])
    data = gzip.compress(first) + gzip.compress(second)
    files = {f.path: f.data for f in unpack(data).strip_top_dir().files}
    assert files == {"setup.py": b"evil"}


@pytest.mark.parametrize("gap", [b"\0" * 512, b"garbage".ljust(512, b"\0")])
def test_entries_hidden_after_where_python_stops_reading(gap):
    first = raw_tar([("package/index.js", b"benign")], end=False)
    second = raw_tar([("package/index.js", b"evil")])
    result = unpack(gzip.compress(first + gap + second), npm=True)
    assert ("*", "there's more data after where the archive seems to end") in result.skipped


def test_a_normal_tarball_has_nothing_after_its_end():
    assert unpack(make_tar([("package/index.js", b"x")]), npm=True).skipped == []
    assert unpack(raw_tar([("package/index.js", b"x")]), npm=True).skipped == []


def test_data_after_the_gzip_stream():
    result = unpack(make_tar([("package/index.js", b"x")]) + b"trailing junk", npm=True)
    assert ("*", "there's data after the compressed archive") in result.skipped


def test_zero_padding_after_the_gzip_stream_is_fine():
    data = make_tar([("package/index.js", b"x")]) + b"\0" * 4096
    result = unpack(data, npm=True)
    assert result.skipped == [] and [f.path for f in result.files] == ["index.js"]


def test_reading_past_the_end_stays_at_the_end():
    from pkg_sentry.archive import _Gunzip

    stream = _Gunzip(gzip.compress(b"hello") + b"\0" * 100, 1_000_000)
    assert stream.read(1000) == b"hello"
    assert [stream.read(1000) for _ in range(5)] == [b""] * 5
    assert not stream.trailing
