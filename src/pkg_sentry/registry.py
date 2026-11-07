"""Package metadata and downloads from PyPI and the npm registry."""

import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote

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
    author: str | None = None
    created: datetime | None = None
    released: datetime | None = None
    previous_release: datetime | None = None
    release_count: int = 0
    install_scripts: dict[str, str] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)
    deprecated: str | None = None
    provenance: bool = False
    # npm swaps confirmed malware for an empty "security holding package".
    removed_as_malware: bool = False


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
        doc = http.get_json(f"{self.pypi_url}/pypi/{quote(spec.name)}/json", timeout=self.timeout)
        meta = doc["info"]
        version = spec.version or meta["version"]
        releases = {v: files for v, files in doc.get("releases", {}).items() if files}
        if version not in releases:
            if spec.version:
                raise VersionNotFound(f"{meta['name']} has no release {version} on PyPI")
            releases[version] = doc.get("urls", [])

        uploaded = {v: min(_time(f["upload_time_iso_8601"]) for f in files)
                    for v, files in releases.items() if files}
        urls = {k.lower(): v for k, v in (meta.get("project_urls") or {}).items() if v}
        homepage = meta.get("home_page") or urls.get("homepage")
        repository = next((urls[k] for k in REPO_KEYS if k in urls), None)
        if not repository and _looks_like_repo(homepage):
            repository = homepage

        return PackageInfo(
            ecosystem="pypi",
            name=meta["name"],
            version=version,
            summary=meta.get("summary") or "",
            homepage=homepage,
            repository=repository,
            author=meta.get("author") or meta.get("author_email"),
            created=min(uploaded.values(), default=None),
            released=uploaded.get(version),
            previous_release=_before(uploaded, version),
            release_count=len(releases),
            artifacts=_pick_pypi_files(releases[version]),
            deprecated=(meta.get("yanked_reason") or "yanked") if meta.get("yanked") else None,
        )

    def _npm(self, spec: PackageSpec) -> PackageInfo:
        url = f"{self.npm_url}/{quote(spec.name, safe='@')}"
        doc = http.get_json(url, timeout=self.timeout, max_bytes=150_000_000)
        versions = doc.get("versions") or {}
        version = spec.version or (doc.get("dist-tags") or {}).get("latest")
        if version not in versions:
            raise VersionNotFound(f"{spec.name} has no version {version} on npm")
        meta = versions[version]
        times = {v: _time(t) for v, t in (doc.get("time") or {}).items() if v in versions}
        scripts = meta.get("scripts") or {}
        repository = meta.get("repository") or doc.get("repository")
        if isinstance(repository, dict):
            repository = repository.get("url")
        author = meta.get("author") or doc.get("author")
        if isinstance(author, dict):
            author = author.get("name") or author.get("email")
        dist = meta.get("dist") or {}

        return PackageInfo(
            ecosystem="npm",
            name=doc.get("name", spec.name),
            version=version,
            summary=meta.get("description") or doc.get("description") or "",
            homepage=meta.get("homepage") or doc.get("homepage"),
            repository=repository or None,
            author=author,
            created=min(times.values(), default=None),
            released=times.get(version),
            previous_release=_before(times, version),
            release_count=len(versions),
            install_scripts={k: scripts[k] for k in NPM_INSTALL_HOOKS if scripts.get(k)},
            artifacts=[Artifact(dist["tarball"].rsplit("/", 1)[-1], dist["tarball"],
                                dist.get("unpackedSize"))] if dist.get("tarball") else [],
            deprecated=meta.get("deprecated") or None,
            provenance=bool((dist.get("attestations") or {}).get("provenance")),
            removed_as_malware=bool(NPM_PLACEHOLDER.match(version))
            or "npm/security-holder" in (repository or ""),
        )


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _before(uploaded: dict[str, datetime], version: str) -> datetime | None:
    mine = uploaded.get(version)
    if mine is None:
        return None
    return max((t for v, t in uploaded.items() if t < mine), default=None)


def _looks_like_repo(url: str | None) -> bool:
    return bool(url) and any(h in url for h in ("github.com/", "gitlab.com/", "bitbucket.org/"))


def _pick_pypi_files(files: list[dict]) -> list[Artifact]:
    """The sdist (its setup.py runs on install) and the wheel pip would most
    likely pick. pip prefers wheels, and a wheel doesn't have to match the
    sdist, so both are worth reading."""
    def artifact(f):
        return Artifact(f["filename"], f["url"], f.get("size"))

    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    wheels = [f for f in files if f["filename"].endswith(".whl")]
    picked = [artifact(sdists[0])] if sdists else []
    if wheels:
        pure = [w for w in wheels if w["filename"].endswith("-none-any.whl")]
        best = pure[0] if pure else min(wheels, key=lambda w: w.get("size") or 0)
        picked.append(artifact(best))
    if not picked and files:
        picked.append(artifact(files[0]))
    return picked
