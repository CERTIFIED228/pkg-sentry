import json
import sys

import pytest

from pkg_sentry.projects import ProjectError, read_project
from pkg_sentry.spec import PackageSpec


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
    return path


def test_requirements(tmp_path):
    path = write(tmp_path, "requirements.txt", """
# web stuff
requests==2.31.0
Django>=4.2,<5
urllib3[socks] == 2.2.1  # pinned
numpy; python_version >= "3.10"
-r other.txt
--index-url https://example.com/simple
git+https://github.com/x/y.git#egg=y
./local-package
mypkg @ https://example.com/mypkg.whl
""")
    specs, notes = read_project(path)
    assert specs == [
        PackageSpec("pypi", "requests", "2.31.0"),
        PackageSpec("pypi", "Django"),
        PackageSpec("pypi", "urllib3", "2.2.1"),
        PackageSpec("pypi", "numpy"),
    ]
    assert len(notes) == 5
    assert "skipped option '-r'" in notes[0]


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib")
def test_pyproject(tmp_path):
    path = write(tmp_path, "pyproject.toml", """
[project]
name = "app"
dependencies = ["requests==2.31.0", "click>=8"]
[project.optional-dependencies]
dev = ["pytest", "requests==2.31.0"]
[dependency-groups]
lint = ["ruff", {include-group = "x"}]
""")
    specs, _ = read_project(path)
    assert specs == [PackageSpec("pypi", "requests", "2.31.0"), PackageSpec("pypi", "click"),
                     PackageSpec("pypi", "pytest"), PackageSpec("pypi", "ruff")]


def test_package_json(tmp_path):
    path = write(tmp_path, "package.json", {
        "dependencies": {"express": "4.19.2", "lodash": "^4.17.21", "@babel/core": "~7.24.0",
                         "local": "file:../local", "fork": "github:me/fork",
                         "alias": "npm:left-pad@1.3.0"},
        "devDependencies": {"jest": "29.7.0"},
    })
    specs, notes = read_project(path)
    assert specs == [
        PackageSpec("npm", "express", "4.19.2"),
        PackageSpec("npm", "lodash"),
        PackageSpec("npm", "@babel/core"),
        PackageSpec("npm", "left-pad", "1.3.0"),
        PackageSpec("npm", "jest", "29.7.0"),
    ]
    assert any("local" in n for n in notes) and any("fork" in n for n in notes)
    assert any("package-lock.json" in n for n in notes)


def test_package_lock_v3(tmp_path):
    path = write(tmp_path, "package-lock.json", {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/express": {"version": "4.19.2",
                                     "resolved": "https://registry.npmjs.org/express/-/x.tgz"},
            "node_modules/express/node_modules/debug": {"version": "2.6.9"},
            "node_modules/@scope/pkg": {"version": "1.0.0"},
            "node_modules/linked": {"link": True},
            "node_modules/private": {"version": "1.0.0",
                                     "resolved": "https://npm.corp.example/private.tgz"},
        },
    })
    specs, notes = read_project(path)
    assert specs == [PackageSpec("npm", "express", "4.19.2"), PackageSpec("npm", "debug", "2.6.9"),
                     PackageSpec("npm", "@scope/pkg", "1.0.0")]
    assert notes == ["private: skipped, comes from npm.corp.example"]


def test_package_lock_v1(tmp_path):
    path = write(tmp_path, "package-lock.json", {
        "lockfileVersion": 1,
        "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
                         "c": {"version": "file:../c"}},
    })
    specs, _ = read_project(path)
    assert specs == [PackageSpec("npm", "a", "1.0.0"), PackageSpec("npm", "b", "2.0.0")]


@pytest.mark.parametrize("name, text", [("package.json", "{nope"), ("package.json", "[]"),
                                         ("Pipfile", "x")])
def test_bad_files(tmp_path, name, text):
    with pytest.raises(ProjectError):
        read_project(write(tmp_path, name, text))


def test_missing_file(tmp_path):
    with pytest.raises(ProjectError):
        read_project(tmp_path / "requirements.txt")
