"""Package metadata and downloads from PyPI and the npm registry."""

import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote

from packaging.tags import sys_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from . import http
from .spec import PackageSpec

PYPI_URL = "https://pypi.org"
NPM_URL = "https://registry.npmjs.org"
# npm replaces confirmed malware with "0.0.1-security", "0.0.2-security"...
NPM_PLACEHOLDER = re.compile(r"^0\.0\.\d+-security$")
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
REPO_KEYS = ("source", "source code", "repository", "code", "github", "gitlab")


class VersionNotFound(LookupError):
    pass


@dataclass(frozen=True)
class Artifact:
    filename: str
    url: str
    size: int | None = None


@dataclass
class PackageInfo:
    ecosystem: str
    name: str
    version: str
    summary: str = ""
    homepage: str | None = None
    repository: str | None = None
    created: datetime | None = None
    released: datetime | None = None
    previous_release: datetime | None = None
    # npm only: every script, because install hooks can call the others.
    scripts: dict[str, str] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)
    deprecated: str | None = None
    # npm swaps confirmed malware for an empty "security holding package".
    removed_as_malware: bool = False

    @property
    def install_scripts(self) -> dict[str, str]:
        return {k: self.scripts[k] for k in NPM_INSTALL_HOOKS if self.scripts.get(k)}


class Registry:
    def __init__(self, pypi_url: str = PYPI_URL, npm_url: str = NPM_URL, timeout: float = 20):
        self.pypi_url, self.npm_url, self.timeout = pypi_url, npm_url, timeout

    def info(self, spec: PackageSpec) -> PackageInfo:
        if spec.ecosystem == "npm":
            return self._npm(spec)
        return self._pypi(spec)

    def download(self, artifact: Artifact, max_bytes: int = 50_000_000) -> bytes:
        return http.get(artifact.url, max_bytes=max_bytes, timeout=self.timeout * 3)

    def _pypi(self, spec: PackageSpec) -> PackageInfo:
        doc = _dict(http.get_json(f"{self.pypi_url}/pypi/{quote(spec.name)}/json",
                                  timeout=self.timeout))
        meta = _dict(doc.get("info"))
        name = _str(meta.get("name")) or spec.name
        version = spec.version or _str(meta.get("version"))
        if not version:
            raise http.FetchError(f"PyPI's answer for {spec.name} has no version in it")
        releases = {v: _files(files) for v, files in _dict(doc.get("releases")).items()}
        releases = {v: files for v, files in releases.items() if files}
        if version not in releases:
            if spec.version:
                raise VersionNotFound(f"{name} has no release {version} on PyPI")
            releases[version] = _files(doc.get("urls"))

        uploaded = {}
        for v, files in releases.items():
            times = [t for f in files if (t := _time(f.get("upload_time_iso_8601")))]
            if times:
                uploaded[v] = min(times)
        urls = {k.lower(): v for k, v in _dict(meta.get("project_urls")).items()
                if isinstance(k, str) and _str(v)}
        homepage = _str(meta.get("home_page")) or urls.get("homepage")
        repository = next((urls[k] for k in REPO_KEYS if k in urls), None)
        if not repository and _looks_like_repo(homepage):
            repository = homepage

        return PackageInfo(
            ecosystem="pypi",
            name=name,
            version=version,
            summary=_str(meta.get("summary")),
            homepage=homepage,
            repository=repository,
            created=min(uploaded.values(), default=None),
            released=uploaded.get(version),
            previous_release=_before(uploaded, version),
            artifacts=_pick_pypi_files(releases[version]),
            deprecated=_yanked(releases[version]),
        )

    def _npm(self, spec: PackageSpec) -> PackageInfo:
        url = f"{self.npm_url}/{quote(spec.name, safe='@')}"
        doc = _dict(http.get_json(url, timeout=self.timeout, max_bytes=150_000_000))
        versions = _dict(doc.get("versions"))
        version = spec.version or _str(_dict(doc.get("dist-tags")).get("latest"))
        if version not in versions:
            raise VersionNotFound(f"{spec.name} has no version {version} on npm")
        meta = versions[version]
        if not isinstance(meta, dict):
            raise http.FetchError(f"npm's manifest for {spec.name}@{version} is broken")
        times = {v: t for v, raw in _dict(doc.get("time")).items()
                 if v in versions and (t := _time(raw))}
        scripts = {k: v for k, v in _dict(meta.get("scripts")).items()
                   if isinstance(k, str) and isinstance(v, str)}
        repository = meta.get("repository") or doc.get("repository")
        if isinstance(repository, dict):
            repository = repository.get("url")
        repository = _str(repository)
        dist = _dict(meta.get("dist"))
        tarball = _str(dist.get("tarball"))

        return PackageInfo(
            ecosystem="npm",
            name=_str(doc.get("name")) or spec.name,
            version=version,
            summary=_str(meta.get("description")) or _str(doc.get("description")),
            homepage=_str(meta.get("homepage")) or _str(doc.get("homepage")) or None,
            repository=repository or None,
            created=min(times.values(), default=None),
            released=times.get(version),
            previous_release=_before(times, version),
            scripts=scripts,
            # No size: unpackedSize is the size after unpacking, not the download.
            artifacts=[Artifact(tarball.rsplit("/", 1)[-1], tarball)] if tarball else [],
            deprecated=_str(meta.get("deprecated")) or None,
            removed_as_malware=bool(NPM_PLACEHOLDER.match(version))
            or "npm/security-holder" in repository,
        )


def _yanked(files: list[dict]) -> str | None:
    # The top-level "yanked" is about the latest release; each file says
    # whether it was yanked itself.
    gone = [f for f in files if f.get("yanked")]
    if not gone or len(gone) < len(files):
        return None
    return _str(gone[0].get("yanked_reason")) or "yanked"


def _time(text) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else None


# Registries are trusted to be up, not to be well-formed: anyone can publish
# odd metadata, so every field is checked for the type it should be.
def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _str(value) -> str:
    return value if isinstance(value, str) else ""


def _files(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [f for f in value if isinstance(f, dict) and _str(f.get("filename"))
            and _str(f.get("url"))]


def _before(uploaded: dict[str, datetime], version: str) -> datetime | None:
    mine = uploaded.get(version)
    if mine is None:
        return None
    return max((t for v, t in uploaded.items() if t < mine), default=None)


def _looks_like_repo(url: str | None) -> bool:
    return bool(url) and any(h in url for h in ("github.com/", "gitlab.com/", "bitbucket.org/"))


def _pick_pypi_files(files: list[dict], tags=None) -> list[Artifact]:
    """The sdist (its setup.py runs on install) and the wheel pip would pick
    on this machine. pip prefers wheels, and a wheel doesn't have to match
    the sdist, so both are worth reading."""
    def artifact(f):
        size = f.get("size")
        return Artifact(f["filename"], f["url"], size if isinstance(size, int) else None)

    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    wheels = [f for f in files if f["filename"].endswith(".whl")]
    picked = [artifact(sdists[0])] if sdists else []
    if wheels:
        picked.append(artifact(_best_wheel(wheels, tags)))
    if not picked and files:
        picked.append(artifact(files[0]))
    return picked


def _best_wheel(wheels: list[dict], tags=None) -> dict:
    # pip ranks wheels by how well their tags fit this machine, so a
    # Windows-only wheel beats a pure-Python one on Windows.
    rank = {tag: i for i, tag in enumerate(tags if tags is not None else sys_tags())}
    best, best_rank = None, len(rank)
    for wheel in wheels:
        try:
            wheel_tags = parse_wheel_filename(wheel["filename"])[3]
        except InvalidWheelFilename:
            continue
        score = min((rank[t] for t in wheel_tags if t in rank), default=len(rank))
        if score < best_rank:
            best, best_rank = wheel, score
    # Nothing fits this machine: read the smallest one as a sample.
    return best or min(wheels, key=lambda w: w.get("size") if isinstance(w.get("size"), int)
                       else 0)
