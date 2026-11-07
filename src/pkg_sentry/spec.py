import re
from dataclasses import dataclass

ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}

# PEP 508 names, and npm's rules (lowercase, url-safe, optional @scope/, max 214 chars).
PYPI_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.IGNORECASE)


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class PackageSpec:
    ecosystem: str
    name: str
    version: str | None = None

    @property
    def label(self) -> str:
        version = ""
        if self.version:
            version = ("==" if self.ecosystem == "pypi" else "@") + self.version
        return f"{self.name}{version} ({ECOSYSTEMS[self.ecosystem]})"


def normalise(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def parse_spec(text: str, default: str = "pypi") -> PackageSpec:
    text = text.strip()
    ecosystem = default
    prefix, sep, rest = text.partition(":")
    if sep:
        if prefix.lower() not in ECOSYSTEMS:
            raise SpecError(f"unknown ecosystem '{prefix}', use pypi: or npm:")
        ecosystem, text = prefix.lower(), rest.strip()
    elif text.startswith("@"):
        ecosystem = "npm"

    if ecosystem == "npm":
        return _parse_npm(text)
    return _parse_pypi(text)


def _parse_pypi(text: str) -> PackageSpec:
    name, sep, version = text.partition("==")
    name, version = name.strip(), version.strip()
    if any(op in name for op in "<>!~=@ "):
        raise SpecError("pin an exact version with == or leave the version out")
    if sep and not version:
        raise SpecError("missing version after ==")
    if not PYPI_NAME.match(name):
        raise SpecError(f"'{name}' isn't a valid PyPI package name")
    return PackageSpec("pypi", name, version or None)


def _parse_npm(text: str) -> PackageSpec:
    # The version separator is the last @ that isn't the scope's leading one.
    at = text.rfind("@")
    if at > 0:
        name, version = text[:at], text[at + 1 :]
        if not version:
            raise SpecError("missing version after @")
    else:
        name, version = text, None
    if len(name) > 214 or not NPM_NAME.match(name):
        raise SpecError(f"'{name}' isn't a valid npm package name")
    if name.startswith("@") and "/" not in name:
        raise SpecError(f"'{name}' is only a scope, the package name is missing")
    return PackageSpec("npm", name, version)
