"""Read the dependencies of a project: requirements.txt, pyproject.toml,
package.json and package-lock.json."""

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .spec import PackageSpec

REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
EXACT_PIN = re.compile(r"^===?\s*([A-Za-z0-9.!+_-]+)\s*$")
NPM_EXACT = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")
# Options pip allows after a requirement on the same line.
LINE_OPTIONS = re.compile(r"\s--?[a-z][\w-]*(?:[= ]\S+)?")
INCLUDE = re.compile(r"^(?:-r|--requirement)[= ]?\s*(\S+)$")
EXTRA_INDEX = re.compile(r"^(?:-i|--index-url|--extra-index-url)\b")
MAX_INCLUDES = 20


class ProjectError(ValueError):
    pass


def read_project(path: Path) -> tuple[list[PackageSpec], list[str]]:
    """Packages to check, and notes about lines that were skipped."""
    name = path.name.lower()
    try:
        text = path.read_text(encoding="utf-8-sig")  # Notepad adds a BOM
    except (OSError, UnicodeDecodeError) as e:
        raise ProjectError(f"can't read {path}: {e}") from None
    if name == "package-lock.json" or name == "npm-shrinkwrap.json":
        return _package_lock(text)
    if name == "package.json":
        return _package_json(text)
    if name == "pyproject.toml":
        return _pyproject(text)
    if name.endswith(".txt") or name.endswith(".in"):
        return _requirements(text, path)
    raise ProjectError(f"don't know how to read {path.name}. Use requirements.txt, "
                       "pyproject.toml, package.json or package-lock.json")


def _requirements(text: str, path: Path | None = None,
                  seen: set | None = None) -> tuple[list[PackageSpec], list[str]]:
    specs, notes = [], []
    seen = seen if seen is not None else {path.resolve()} if path else set()
    for number, line in _logical_lines(text):
        if not line or line.startswith("#"):
            continue
        if include := INCLUDE.match(line):
            found, more = _include(path, include.group(1), seen)
            specs += found
            notes += more
            continue
        if EXTRA_INDEX.match(line):
            notes.append(f"line {number}: uses another package index. If it's a private one, "
                         "anyone can publish its package names on PyPI (dependency confusion)")
            continue
        if line.startswith("-"):
            notes.append(f"line {number}: skipped option '{line.split()[0]}'")
            continue
        line = LINE_OPTIONS.sub("", f" {line}").strip()  # --hash=sha256:... and friends
        if "://" in line or line.startswith((".", "/")) or " @ " in line:
            notes.append(f"line {number}: skipped '{line}', not from PyPI")
            continue
        spec = _python_requirement(line)
        if spec:
            specs.append(spec)
        else:
            notes.append(f"line {number}: couldn't read '{line}'")
    return specs, notes


def _logical_lines(text: str):
    """Lines with comments removed and backslash continuations joined."""
    start, parts = None, []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw if raw.lstrip().startswith("#") else re.split(r"\s#", raw, maxsplit=1)[0]
        start = start or number
        if line.rstrip().endswith("\\") and not line.lstrip().startswith("#"):
            parts.append(line.rstrip()[:-1])
            continue
        parts.append(line)
        yield start, " ".join(p.strip() for p in parts).strip()
        start, parts = None, []
    if parts:
        yield start, " ".join(p.strip() for p in parts).strip()


def _include(path: Path | None, name: str, seen: set) -> tuple[list[PackageSpec], list[str]]:
    target = (path.parent / name if path else Path(name)).resolve()
    if target in seen:
        return [], []
    if len(seen) > MAX_INCLUDES:
        return [], [f"skipped {name}, too many nested -r files"]
    seen.add(target)
    try:
        text = target.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        return [], [f"couldn't read {name}: {e.strerror if isinstance(e, OSError) else e}"]
    specs, notes = _requirements(text, target, seen)
    return specs, [f"{name}: {n}" for n in notes]


def _pyproject(text: str) -> tuple[list[PackageSpec], list[str]]:
    try:
        import tomllib
    except ImportError:  # Python 3.10
        raise ProjectError("reading pyproject.toml needs Python 3.11+, "
                           "use a requirements file instead") from None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ProjectError(f"pyproject.toml isn't valid TOML: {e}") from None
    project = _dict(data.get("project"))
    lines = list(_list(project.get("dependencies")))
    for extra in _dict(project.get("optional-dependencies")).values():
        lines += _list(extra)
    for group in _dict(data.get("dependency-groups")).values():
        lines += _list(group)
    specs = [s for s in (_python_requirement(x) for x in lines if isinstance(x, str)) if s]
    specs += _poetry(_dict(_dict(data.get("tool")).get("poetry")))
    return _unique(specs), []


def _poetry(poetry: dict) -> list[PackageSpec]:
    """[tool.poetry.dependencies]: a bare version like "2.31.0" means exactly that one."""
    tables = [_dict(poetry.get("dependencies")), _dict(poetry.get("dev-dependencies"))]
    tables += [_dict(_dict(g).get("dependencies")) for g in _dict(poetry.get("group")).values()]
    specs = []
    for table in tables:
        for name, wanted in table.items():
            if name.lower() == "python":
                continue
            if isinstance(wanted, dict):
                if any(k in wanted for k in ("git", "path", "url")):
                    continue
                wanted = wanted.get("version", "")
            pin = EXACT_PIN.match(f"=={wanted}" if re.match(r"^\d", str(wanted)) else str(wanted))
            specs.append(PackageSpec("pypi", name, pin.group(1) if pin else None))
    return specs


def _python_requirement(line: str) -> PackageSpec | None:
    line = line.split(";", 1)[0].strip()  # environment markers
    m = REQUIREMENT.match(line)
    if not m:
        return None
    name, rest = m.group(1), m.group(2).strip()
    pin = EXACT_PIN.match(rest)
    return PackageSpec("pypi", name, pin.group(1) if pin else None)


def _package_json(text: str) -> tuple[list[PackageSpec], list[str]]:
    data = _json(text, "package.json")
    specs, notes = [], []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, wanted in _dict(data.get(section)).items():
            if not isinstance(wanted, str):
                continue
            if wanted.startswith("npm:"):  # "alias": "npm:real-name@1.0.0" or "npm:@scope/x@1"
                real = wanted[4:]
                at = real.rfind("@")
                name, wanted = (real[:at], real[at + 1:]) if at > 0 else (real, "")
            if wanted.startswith(("file:", "link:", "git", "http", "workspace:")) or "/" in wanted:
                notes.append(f"{name}: skipped '{wanted}', not from the npm registry")
                continue
            exact = NPM_EXACT.match(wanted.strip())
            specs.append(PackageSpec("npm", name, exact.group(1) if exact else None))
    if any(s.version is None for s in specs):
        notes.append("version ranges were checked at their latest release. Check "
                     "package-lock.json to see exactly what gets installed")
    return _unique(specs), notes


def _package_lock(text: str) -> tuple[list[PackageSpec], list[str]]:
    data = _json(text, "package-lock.json")
    specs, notes = [], []
    if "packages" in data:  # lockfile v2 and v3
        for path, entry in _dict(data["packages"]).items():
            if not isinstance(entry, dict) or not path or entry.get("link") \
                    or "node_modules/" not in path:
                continue
            name = _text(entry.get("name")) or path.rsplit("node_modules/", 1)[1]
            resolved = _text(entry.get("resolved"))
            if resolved and urlparse(resolved).hostname != "registry.npmjs.org":
                where = urlparse(resolved).hostname or resolved
                notes.append(f"{name}: skipped, comes from {where}")
                continue
            version = _text(entry.get("version"))
            if version and NPM_EXACT.match(version):
                specs.append(PackageSpec("npm", name, version))
    else:  # v1 nests dependencies
        def walk(deps, depth=0):
            for name, entry in _dict(deps).items():
                if not isinstance(entry, dict) or depth > 100:
                    continue
                version = _text(entry.get("version"))
                if NPM_EXACT.match(version):
                    specs.append(PackageSpec("npm", name, version))
                elif version.startswith("npm:"):
                    real, _, pinned = version[4:].rpartition("@")
                    if real and NPM_EXACT.match(pinned):
                        specs.append(PackageSpec("npm", real, pinned))
                walk(entry.get("dependencies"), depth + 1)
        walk(data.get("dependencies"))
    return _unique(specs), notes


def _json(text: str, what: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ProjectError(f"{what} isn't valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise ProjectError(f"{what} should be a JSON object")
    return data


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _unique(specs: list[PackageSpec]) -> list[PackageSpec]:
    return list(dict.fromkeys(specs))
