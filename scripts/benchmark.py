"""Measure detection on real malware and false alarms on popular packages.

    python scripts/benchmark.py --malware path/to/malicious-software-packages-dataset \\
                                --benign path/to/popular-packages [--split test]

Malware comes from Datadog's malicious-software-packages-dataset. Samples
are encrypted zips (password "infected") and are only ever read into
memory. Nothing is extracted to disk and nothing is run.

The popular-packages folder is made by scripts/fetch_popular.py.

Only the static layers are measured: the code and the name. The
known-malware lookup is left out, since OSV lists most of these samples and
it would make the numbers meaningless.

Rules were tuned on the "dev" half (malware discovered before 2025, and
popular packages with an even name hash). Report the "test" half.
"""

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path

from pkg_sentry.analyse import analyse
from pkg_sentry.archive import ArchiveError, File, Unpacked, unpack
from pkg_sentry.names import load_popular
from pkg_sentry.rules import Finding, judge

CUTOFF = "2025-01-01"
NESTED = (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar.bz2")
LEVELS = ("critical", "high", "medium", "low")


def load_sample(path: Path) -> Unpacked:
    """A dataset zip, with the dataset's own wrapping removed."""
    result = unpack(path.read_bytes(), password=b"infected")
    nested = [f for f in result.files if f.path.endswith(NESTED)]
    for f in nested:
        try:
            inner = unpack(f.data)
        except ArchiveError:
            continue
        result.files += [File(f"{f.path}/{g.path}", g.data) for g in inner.files]
        result.suspicious += inner.suspicious
        result.skipped += inner.skipped
    result.files = [File(_undouble(f.path), f.data) for f in result.files if f not in nested]
    return result.strip_top_dir()


def _undouble(path: str) -> str:
    # Some samples store a/b.py as a/b.py/a/b.py.
    parts = path.split("/")
    for size in range(1, len(parts) // 2 + 1):
        tail = parts[-size:]
        if parts[-2 * size:-size] == tail and "." in tail[-1]:
            return "/".join(parts[:-2 * size] + tail)
    return path


def name_findings(ecosystem: str, name: str) -> list[Finding]:
    squat = load_popular(ecosystem).squats(name)
    if not squat:
        return []
    return [Finding("typosquat", f"looks like {squat.how}")]


def malware(root: Path, split: str):
    for ecosystem in ("pypi", "npm"):
        for path in sorted((root / "samples" / ecosystem).glob("*/*/*/*.zip")):
            found_on = path.name[:10]
            if (found_on < CUTOFF) != (split == "dev"):
                continue
            name = path.parent.parent.name
            yield ecosystem, name, path.parent.parent.parent.name, lambda p=path: [load_sample(p)]


def popular(root: Path, split: str):
    for ecosystem in ("pypi", "npm"):
        for folder in sorted((root / ecosystem).iterdir()):
            info_file = folder / "info.json"
            if not info_file.exists():
                continue
            info = json.loads(info_file.read_text())
            even = hashlib.sha256(info["name"].encode()).digest()[0] % 2 == 0
            if even != (split == "dev"):
                continue

            def load(folder=folder, info=info, ecosystem=ecosystem):
                # Each file on its own, the way `pkg-sentry check` reads them.
                parts = []
                for filename in info["files"]:
                    data = (folder / filename).read_bytes()
                    try:
                        part = (unpack(data, npm=True) if ecosystem == "npm"
                                else unpack(data).strip_top_dir())
                    except ArchiveError:
                        continue
                    parts.append(part)
                return parts

            yield ecosystem, info["name"], "popular", load


def run(packages, label, show):
    levels, rules, slow, empty, rows = Counter(), Counter(), [], 0, []
    start = time.time()
    for ecosystem, name, kind, load in packages:
        began = time.time()
        parts = load()
        if not any(p.files or p.suspicious for p in parts):
            empty += 1
            continue
        findings = [f for p in parts for f in analyse(p, ecosystem)]
        findings += name_findings(ecosystem, name)
        verdict = judge(findings)
        levels[verdict.severity] += 1
        rules.update({f.rule for f in findings})
        rows.append((ecosystem, kind, name, verdict))
        slow.append((time.time() - began, name))
    total = sum(levels.values())
    print(f"\n{label}: {total} packages ({empty} empty samples skipped), "
          f"{time.time() - start:.0f}s")
    at_least = 0
    for level in LEVELS:
        at_least += levels[level]
        share = at_least / max(total, 1)
        print(f"  {level:>8}: {levels[level]:5}   {level} or worse: {share:6.1%}")
    print(f"  {'none':>8}: {levels['none']:5}")
    for eco in ("pypi", "npm"):
        mine = [v for e, _, _, v in rows if e == eco]
        if mine:
            hit = sum(v.at_least("medium") for v in mine)
            print(f"  {eco}: {len(mine)} packages, medium or worse {hit / len(mine):.1%}")
    print("  rules:", ", ".join(f"{r} {n}" for r, n in rules.most_common()))
    print("  slowest:", ", ".join(f"{n} {t:.1f}s" for t, n in sorted(slow)[-3:]))
    for ecosystem, _, name, verdict in rows:
        if show(verdict):
            reasons = "; ".join(f"{f.rule} {f.where}" for f in verdict.findings[:4])
            print(f"    {ecosystem:4} {verdict.severity:8} {verdict.score:3} {name}  {reasons}")
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--malware", type=Path)
    parser.add_argument("--benign", type=Path)
    parser.add_argument("--split", choices=["dev", "test"], default="test")
    parser.add_argument("--show", choices=["none", "missed", "alarms"], default="none")
    args = parser.parse_args(argv)
    if not args.malware and not args.benign:
        parser.error("give --malware, --benign or both")

    if args.malware:
        run(malware(args.malware, args.split), f"Malware ({args.split})",
            lambda v: args.show == "missed" and not v.at_least("medium"))
    if args.benign:
        run(popular(args.benign, args.split), f"Popular packages ({args.split})",
            lambda v: args.show == "alarms" and v.at_least("low"))


if __name__ == "__main__":
    sys.exit(main())
