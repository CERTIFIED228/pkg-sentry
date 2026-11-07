import json
from datetime import datetime, timezone

import pytest

from pkg_sentry import http
from pkg_sentry.registry import Artifact, Registry, VersionNotFound
from pkg_sentry.spec import PackageSpec


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def pypi_file(name, kind, when, size=1000):
    return {"filename": name, "packagetype": kind, "url": f"https://files.example/{name}",
            "size": size, "upload_time_iso_8601": when}


def pypi_doc():
    return {
        "info": {
            "name": "Example-Pkg", "version": "2.0", "summary": "does things",
            "home_page": "", "author": "", "author_email": "dev@example.com",
            "project_urls": {"Homepage": "https://example.com", "Source": "https://github.com/x/y"},
            "yanked": False,
        },
        "releases": {
            "1.0": [pypi_file("example_pkg-1.0.tar.gz", "sdist", "2021-03-01T10:00:00.000Z")],
            "1.5": [],  # every file deleted
            "2.0": [
                pypi_file("example_pkg-2.0-cp312-cp312-win_amd64.whl", "bdist_wheel",
                          "2024-05-02T10:00:00Z", 9000),
                pypi_file("example_pkg-2.0-py3-none-any.whl", "bdist_wheel",
                          "2024-05-02T10:01:00Z"),
                pypi_file("example_pkg-2.0.tar.gz", "sdist", "2024-05-01T09:00:00Z"),
            ],
        },
        "urls": [],
    }


def npm_doc():
    return {
        "name": "left-pad",
        "dist-tags": {"latest": "1.3.0"},
        "time": {"created": "2014-03-14T09:09:20Z", "modified": "2024-04-16T05:01:57Z",
                 "1.0.0": "2014-03-14T09:09:20Z", "1.3.0": "2018-04-09T01:00:00Z"},
        "repository": {"type": "git", "url": "git+https://github.com/stevemao/left-pad.git"},
        "versions": {
            "1.0.0": {"dist": {"tarball": "https://r.example/left-pad-1.0.0.tgz"}},
            "1.3.0": {
                "description": "String left pad",
                "author": {"name": "azer"},
                "scripts": {"test": "node test", "postinstall": "node setup.js", "install": ""},
                "dist": {"tarball": "https://r.example/left-pad/-/left-pad-1.3.0.tgz",
                         "unpackedSize": 9752,
                         "attestations": {"provenance": {"predicateType": "slsa"}}},
                "deprecated": "use String.prototype.padStart()",
            },
        },
    }


@pytest.fixture
def registry(server):
    server["/pypi/example-pkg/json"] = (200, json.dumps(pypi_doc()).encode(), {})
    server["/left-pad"] = (200, json.dumps(npm_doc()).encode(), {})
    return Registry(pypi_url=server.url, npm_url=server.url)


def test_pypi_latest(registry):
    info = registry.info(PackageSpec("pypi", "example-pkg"))
    assert (info.name, info.version, info.summary) == ("Example-Pkg", "2.0", "does things")
    assert info.repository == "https://github.com/x/y"
    assert info.homepage == "https://example.com"
    assert info.author == "dev@example.com"
    assert info.created == utc(2021, 3, 1, 10)
    assert info.released == utc(2024, 5, 1, 9)  # earliest file of the release
    assert info.previous_release == utc(2021, 3, 1, 10)
    assert info.release_count == 2  # the empty 1.5 doesn't count


def test_pypi_reads_the_sdist_and_the_pure_wheel(registry):
    info = registry.info(PackageSpec("pypi", "example-pkg"))
    assert [a.filename for a in info.artifacts] == [
        "example_pkg-2.0.tar.gz", "example_pkg-2.0-py3-none-any.whl"]


def test_pypi_specific_version(registry):
    info = registry.info(PackageSpec("pypi", "example-pkg", "1.0"))
    assert info.version == "1.0"
    assert info.previous_release is None
    assert [a.filename for a in info.artifacts] == ["example_pkg-1.0.tar.gz"]


def test_pypi_missing_version(registry):
    with pytest.raises(VersionNotFound):
        registry.info(PackageSpec("pypi", "example-pkg", "9.9"))


def test_pypi_repo_falls_back_to_a_github_homepage(server):
    doc = pypi_doc()
    doc["info"]["project_urls"] = None
    doc["info"]["home_page"] = "https://github.com/x/y"
    server["/pypi/example-pkg/json"] = (200, json.dumps(doc).encode(), {})
    info = Registry(pypi_url=server.url).info(PackageSpec("pypi", "example-pkg"))
    assert info.repository == "https://github.com/x/y"


def test_only_platform_wheels_picks_the_smallest(server):
    doc = pypi_doc()
    doc["releases"]["2.0"] = [
        pypi_file("p-2.0-cp312-win_amd64.whl", "bdist_wheel", "2024-05-02T10:00:00Z", 900),
        pypi_file("p-2.0-cp312-manylinux.whl", "bdist_wheel", "2024-05-02T10:00:00Z", 500),
    ]
    server["/pypi/example-pkg/json"] = (200, json.dumps(doc).encode(), {})
    info = Registry(pypi_url=server.url).info(PackageSpec("pypi", "example-pkg"))
    assert [a.filename for a in info.artifacts] == ["p-2.0-cp312-manylinux.whl"]


def test_unknown_package(server):
    with pytest.raises(http.NotFound):
        Registry(pypi_url=server.url).info(PackageSpec("pypi", "nope"))


def test_npm_latest(registry):
    info = registry.info(PackageSpec("npm", "left-pad"))
    assert info.version == "1.3.0"
    assert info.summary == "String left pad"
    assert info.repository == "git+https://github.com/stevemao/left-pad.git"
    assert info.author == "azer"
    assert info.install_scripts == {"postinstall": "node setup.js"}
    assert info.artifacts[0].filename == "left-pad-1.3.0.tgz"
    assert info.artifacts[0].size == 9752
    assert info.created == utc(2014, 3, 14, 9, 9, 20)
    assert info.previous_release == utc(2014, 3, 14, 9, 9, 20)
    assert info.release_count == 2
    assert info.deprecated.startswith("use String")
    assert info.provenance
    assert not info.removed_as_malware


def test_npm_scoped_names_are_encoded(server):
    doc = npm_doc()
    doc["name"] = "@scope/pkg"
    server["/@scope%2Fpkg"] = (200, json.dumps(doc).encode(), {})
    info = Registry(npm_url=server.url).info(PackageSpec("npm", "@scope/pkg"))
    assert info.name == "@scope/pkg"


def test_npm_missing_version(registry):
    with pytest.raises(VersionNotFound):
        registry.info(PackageSpec("npm", "left-pad", "7.0.0"))


@pytest.mark.parametrize("version", ["0.0.1-security", "0.0.2-security"])
def test_npm_security_placeholder_means_removed_as_malware(server, version):
    doc = {
        "name": "crossenv",
        "dist-tags": {"latest": version},
        "time": {version: "2017-08-02T00:00:00Z"},
        "versions": {version: {"description": "security holding package",
                               "dist": {"tarball": "https://r.example/c.tgz"}}},
    }
    server["/crossenv"] = (200, json.dumps(doc).encode(), {})
    info = Registry(npm_url=server.url).info(PackageSpec("npm", "crossenv"))
    assert info.removed_as_malware


def test_download(server):
    server["/files/x.tgz"] = (200, b"archive bytes", {})
    assert Registry().download(Artifact("x.tgz", server.url + "/files/x.tgz")) == b"archive bytes"
