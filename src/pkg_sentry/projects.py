"""Read the dependencies of a project: requirements.txt, pyproject.toml,
package.json and package-lock.json."""

import json
import re
from pathlib import Path

from .spec import PackageSpec

REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
EXACT_PIN = re.compile(r"^===?\s*([A-Za-z0-9.!+_-]+)\s*$")
NPM_EXACT = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


class ProjectError(ValueError):
    pass


def read_project(path: Path) -> tuple[list[PackageSpec], list[str]]:
    """Packages to check, and notes about lines that were skipped."""
    name = path.name.lower()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ProjectError(f"can't read {path}: {e}") from None
    if name == "package-lock.json" or name == "npm-shrinkwrap.json":
        return _package_lock(text)
    if name == "package.json":
        return _package_json(text)
    if name == "pyproject.toml":
        return _pyproject(text)
    if name.endswith(".txt") or name.endswith(".in"):
        return _requirements(text)
    raise ProjectError(f"don't know how to read {path.name}. Use requirements.txt, "
                       "pyproject.toml, package.json or package-lock.json")


def _requirements(text: str) -> tuple[list[PackageSpec], list[str]]:
    specs, notes = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            notes.append(f"line {number}: skipped option '{line.split()[0]}'")
            continue
        if "://" in line or line.startswith((".", "/")) or " @ " in line:
            notes.append(f"line {number}: skipped '{line}', not from PyPI")
            continue
        spec = _python_requirement(line)
        if spec:
            specs.append(spec)
        else:
            notes.append(f"line {number}: couldn't read '{line}'")
    return specs, notes


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
    project = data.get("project", {})
    lines = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        lines += extra
    for group in data.get("dependency-groups", {}).values():
        lines += [x for x in group if isinstance(x, str)]
    specs = [s for s in (_python_requirement(line) for line in lines) if s]
    return _unique(specs), []


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
        for name, wanted in (data.get(section) or {}).items():
            if not isinstance(wanted, str):
                continue
            if wanted.startswith(("file:", "link:", "git", "http", "workspace:")) or "/" in wanted:
                notes.append(f"{name}: skipped '{wanted}', not from the npm registry")
                continue
            if wanted.startswith("npm:"):  # "alias": "npm:real-name@1.0.0"
                real = wanted[4:]
                at = real.rfind("@")
                name, wanted = (real[:at], real[at + 1:]) if at > 0 else (real, "")
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
        for path, entry in data["packages"].items():
            if not path or entry.get("link") or "node_modules/" not in path:
                continue
            name = entry.get("name") or path.rsplit("node_modules/", 1)[1]
            resolved = entry.get("resolved", "")
            if resolved and "registry.npmjs.org" not in resolved:
                notes.append(f"{name}: skipped, comes from {resolved.split('/')[2]}")
                continue
            if entry.get("version"):
                specs.append(PackageSpec("npm", name, entry["version"]))
    else:  # v1 nests dependencies
        def walk(deps):
            for name, entry in (deps or {}).items():
                if entry.get("version") and not entry["version"].startswith(("file:", "git")):
                    specs.append(PackageSpec("npm", name, entry["version"]))
                walk(entry.get("dependencies"))
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


def _unique(specs: list[PackageSpec]) -> list[PackageSpec]:
    return list(dict.fromkeys(specs))
