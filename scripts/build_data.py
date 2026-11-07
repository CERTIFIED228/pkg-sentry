"""Rebuild the popular-package lists in src/pkg_sentry/data.

    python scripts/build_data.py

PyPI: hugovk/top-pypi-packages (downloads over the last 30 days).
npm:  the npm-high-impact package by Titus Wormer (most downloaded and most
      depended on). It's published as a JS module, so the names are pulled
      out of its source rather than run.
"""

import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "src" / "pkg_sentry" / "data"
PYPI_TOP = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
NPM_PACKAGE = "https://registry.npmjs.org/npm-high-impact/latest"
LIMIT = 15_000


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "pkg-sentry build_data"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def pypi_names() -> list[str]:
    rows = json.loads(fetch(PYPI_TOP))["rows"]
    rows.sort(key=lambda r: -r["download_count"])
    return [re.sub(r"[-_.]+", "-", r["project"]).lower() for r in rows[:LIMIT]]


def npm_names() -> list[str]:
    tarball = json.loads(fetch(NPM_PACKAGE))["dist"]["tarball"]
    with tarfile.open(fileobj=io.BytesIO(fetch(tarball))) as tar:
        source = tar.extractfile("package/lib/top.js").read().decode()
    names = re.findall(r"^\s*'((?:@[^'/]+/)?[^'/]+)',?$", source, re.MULTILINE)
    seen, ordered = set(), []
    for name in names:
        if name.lower() not in seen:
            seen.add(name.lower())
            ordered.append(name.lower())
    return ordered[:LIMIT]


def write(name: str, names: list[str]) -> None:
    if len(names) < 1000:
        sys.exit(f"only {len(names)} names for {name}, something went wrong")
    (DATA / name).write_text("\n".join(names) + "\n", encoding="utf-8")
    print(f"{name}: {len(names):,} names")


if __name__ == "__main__":
    DATA.mkdir(parents=True, exist_ok=True)
    write("top-pypi.txt", pypi_names())
    write("top-npm.txt", npm_names())
