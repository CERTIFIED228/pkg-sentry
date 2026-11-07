"""Download the most popular PyPI and npm packages for the false-alarm benchmark.

    python scripts/fetch_popular.py out-folder [--count 1000]

Each package gets a folder with the files pkg-sentry would read (PyPI: the
sdist and one wheel, npm: the tarball) and an info.json.
"""

import argparse
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pkg_sentry import http
from pkg_sentry.names import load_popular
from pkg_sentry.registry import Registry
from pkg_sentry.spec import PackageSpec

MAX_BYTES = 50_000_000


def fetch(registry: Registry, out: Path, ecosystem: str, name: str) -> str:
    folder = out / ecosystem / name.replace("/", "__")
    if (folder / "info.json").exists():
        return "already there"
    try:
        info = registry.info(PackageSpec(ecosystem, name))
    except (http.FetchError, LookupError, KeyError, ValueError):
        return "failed"
    folder.mkdir(parents=True, exist_ok=True)
    saved = []
    for artifact in info.artifacts:
        if artifact.size and artifact.size > MAX_BYTES:
            continue
        try:
            (folder / artifact.filename).write_bytes(registry.download(artifact, MAX_BYTES))
            saved.append(artifact.filename)
        except http.FetchError:
            continue
    (folder / "info.json").write_text(json.dumps(
        {"name": info.name, "version": info.version, "files": saved}))
    return "saved"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args()
    registry = Registry()
    jobs = [(eco, name) for eco in ("pypi", "npm")
            for name in sorted(load_popular(eco).ranks, key=load_popular(eco).ranks.get)
            [: args.count]]
    with ThreadPoolExecutor(12) as pool:
        results = pool.map(lambda job: fetch(registry, args.out, *job), jobs)
        print(dict(Counter(results)))


if __name__ == "__main__":
    main()
