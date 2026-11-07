import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .analyse import analyse
from .archive import ArchiveError, File, Limits, Unpacked, clean_path, unpack
from .check import Checker, Report
from .known import OSV
from .names import load_popular
from .projects import ProjectError, read_project
from .report import as_json, as_text, summary
from .rules import SEVERITIES, Finding, judge
from .spec import PackageSpec, SpecError, parse_spec

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}


def main(argv: list[str] | None = None) -> int:
    _safe_streams()
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        return args.run(args)
    except KeyboardInterrupt:
        return 130


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkg-sentry",
        description="Check PyPI and npm packages for signs of malware before installing them. "
                    "Nothing is installed or run.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    def common(p):
        p.add_argument("--json", action="store_true", help="print JSON instead of text")
        p.add_argument("--fail-on", choices=SEVERITIES[1:], default="high",
                       help="exit with 1 if anything is at least this bad (default: high)")
        p.add_argument("--no-colour", "--no-color", action="store_true", dest="no_colour")

    def online(p):
        p.add_argument("--offline", action="store_true",
                       help="skip the known-malware lookup on OSV.dev")
        p.add_argument("--no-code", action="store_true",
                       help="don't download and read the code, metadata only")

    check = sub.add_parser("check", help="check one or more packages",
                           description="Check packages, e.g. `requests`, `requests==2.31.0`, "
                                       "`npm:lodash@4.17.21` or `@babel/core`.")
    check.add_argument("packages", nargs="+", metavar="PACKAGE")
    check.add_argument("--npm", action="store_true", help="treat names without a prefix as npm")
    common(check)
    online(check)
    check.set_defaults(run=run_check)

    scan = sub.add_parser("scan", help="check every dependency of a project",
                          description="Check requirements.txt, pyproject.toml, package.json "
                                      "or package-lock.json.")
    scan.add_argument("file", type=Path)
    scan.add_argument("--all", action="store_true", help="also list packages with no problems")
    scan.add_argument("--workers", type=int, default=8, help=argparse.SUPPRESS)
    common(scan)
    online(scan)
    scan.set_defaults(run=run_scan)

    inspect = sub.add_parser("inspect", help="check a package you've already downloaded",
                             description="Read a downloaded archive (.tar.gz, .whl, .tgz, "
                                         ".zip) or an unpacked folder. Nothing is fetched.")
    inspect.add_argument("path", type=Path)
    inspect.add_argument("--npm", action="store_true", help="it's an npm package")
    inspect.add_argument("--pypi", action="store_true", help="it's a PyPI package")
    common(inspect)
    inspect.set_defaults(run=run_inspect)
    return parser


def run_check(args) -> int:
    try:
        specs = [parse_spec(p, default="npm" if args.npm else "pypi") for p in args.packages]
    except SpecError as e:
        _error(str(e))
        return 2
    checker = _checker(args)
    reports = [checker.check(spec) for spec in specs]
    return _finish(reports, args, show_clean=True)


def run_scan(args) -> int:
    try:
        specs, notes = read_project(args.file)
    except ProjectError as e:
        _error(str(e))
        return 2
    if not specs:
        _error(f"no packages found in {args.file}")
        return 2
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    checker = _checker(args)
    print(f"checking {len(specs)} package(s) from {args.file}...", file=sys.stderr)
    with ThreadPoolExecutor(max(1, args.workers)) as pool:
        reports = list(pool.map(checker.check, specs))
    return _finish(reports, args, show_clean=args.all)


def run_inspect(args) -> int:
    path = args.path
    try:
        unpacked = _read_folder(path) if path.is_dir() else unpack(path.read_bytes())
    except (OSError, ArchiveError) as e:
        _error(f"can't read {path}: {e}")
        return 2
    unpacked.strip_top_dir()
    ecosystem = "npm" if args.npm else "pypi" if args.pypi else None
    findings = analyse(unpacked, ecosystem)
    ecosystem = ecosystem or ("npm" if any(f.path == "package.json" for f in unpacked.files)
                              else "pypi")
    name = _guess_name(path)
    if name and (squat := load_popular(ecosystem).squats(name)):
        findings.append(Finding("typosquat", f"the name looks like {squat.how}"))
    notes = [f"skipped {p} ({why})" for p, why in unpacked.skipped[:5]]
    report = Report(PackageSpec(ecosystem, path.name), judge(findings, notes))
    return _finish([report], args, show_clean=True)


def _checker(args) -> Checker:
    return Checker(osv=None if args.offline else OSV(), read_code=not args.no_code)


def _finish(reports: list[Report], args, show_clean: bool) -> int:
    failed = any(r.error for r in reports)
    flagged = [r for r in reports if not r.error and r.verdict.at_least(args.fail_on)]
    if args.json:
        print(as_json(reports))
    else:
        colour = not args.no_colour and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        shown = [r for r in reports if show_clean or r.error or r.verdict.severity != "none"]
        for r in shown:
            print(as_text(r, colour=colour))
            print()
        if len(reports) > 1:
            print(summary(reports))
    if flagged:
        return 1
    return 2 if failed else 0


def _read_folder(root: Path) -> Unpacked:
    limits, result, total = Limits(), Unpacked(), 0
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        rel = clean_path(path.relative_to(root).as_posix())
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            result.skipped.append((rel, f"{size:,} bytes, too big to scan"))
            continue
        total += size
        if total > limits.max_total_bytes or len(result.files) >= limits.max_files:
            result.skipped.append(("*", "stopped reading, the folder is too big"))
            break
        result.files.append(File(rel, path.read_bytes()))
    return result


def _guess_name(path: Path) -> str | None:
    """requests-2.31.0.tar.gz -> requests, left-pad-1.3.0.tgz -> left-pad."""
    name = path.name
    for ext in (".tar.gz", ".tgz", ".whl", ".zip", ".tar.bz2"):
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    parts = []
    for part in name.split("-"):
        if part[:1].isdigit():  # the version starts here
            break
        parts.append(part)
    return "-".join(parts) or None


def _error(message: str) -> None:
    print(f"pkg-sentry: {message}", file=sys.stderr)


def _safe_streams() -> None:
    # Windows consoles can't print everything a package might contain.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")


if __name__ == "__main__":
    sys.exit(main())
