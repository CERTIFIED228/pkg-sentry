"""Run the code checks over an unpacked package.

The main job here is deciding *when* each file's code runs, because code
that runs by itself during `pip install`/`npm install` is far more
dangerous than the same code in a function nobody calls:

- setup.py, and local modules it imports, run during install
- __init__.py runs on import (module-level code only)
- .pth files run every time Python starts
- npm install hooks and the files they start run during install
"""

import posixpath
import re

from .archive import Unpacked
from .jsscan import scan_js, scan_package_json
from .pyscan import local_imports, scan_python
from .rules import Finding, snippet
from .textrules import binary_kind, check_text

TEXT_EXTENSIONS = {".py", ".js", ".cjs", ".mjs", ".ts", ".json", ".txt", ".md", ".rst", ".cfg",
                   ".toml", ".yml", ".yaml", ".css", ".html", ".png", ".jpg", ".jpeg", ".gif",
                   ".svg", ".ico", ".woff", ".ttf", ".pyi", ".map"}
DROPPED_PROGRAMS = {".exe", ".scr", ".msi"}
SCRIPTS = {".sh", ".bash", ".bat", ".cmd", ".ps1", ".vbs"}
JS = {".js", ".cjs", ".mjs"}
DEV_DIRS = {"example", "examples", "docs", "doc", "scripts", "benchmarks", "benchmark", "bench",
            "tools", "samples", "demo", "demos", "ci", ".github", ".circleci", "fixtures",
            "__fixtures__", "__tests__", "__mocks__", "e2e", "dev", "winbuild", ".evergreen"}
# Files in the other ecosystem's language don't run on install or import:
# JavaScript in a PyPI package is a web asset, Python in an npm package a helper.
OWN_CODE = {"pypi": {".py", ".pth"}, "npm": {".js", ".cjs", ".mjs"}}
FOREIGN_CODE = {".py", ".js", ".cjs", ".mjs"}
DEV_FILES = re.compile(r"^(?:test_.*\.py|conftest\.py|.*_tests?\.py|.*\.(?:test|spec)\.[cm]?js"
                       r"|make\.bat|gulpfile\.js|gruntfile\.js|karma\.conf\.js)$", re.IGNORECASE)
# Code in tests, docs and build tooling doesn't run when someone installs or
# uses the package, so only signs that are never innocent count there.
STRONG = {"exfil-endpoint", "disguised-binary", "pth-file", "archive-escape"}
PTH_CODE = re.compile(r"^\s*import\s", re.MULTILINE)
PTH_DANGER = re.compile(r"b64decode|base64|zlib|marshal|subprocess|os\.system|popen|urllib|urlopen"
                        r"|socket|requests|http\.client|codecs\.decode|fromhex")
SENDS_DATA = {"exfil-endpoint", "raw-ip-url", "network-at-install", "env-dump", "recon",
              "download-exec", "fetch-and-run"}


def analyse(unpacked: Unpacked, ecosystem: str | None = None) -> list[Finding]:
    files = {f.path: f for f in unpacked.files}
    ecosystem = ecosystem or _guess_ecosystem(files)
    findings = [Finding("archive-escape", f"has a file that {why}", path)
                for path, why in unpacked.suspicious]

    install_files = set()
    if ecosystem == "npm":
        root = _root_package_json(files)
        if root:
            found, run_files = scan_package_json(root, files[root].text())
            findings += found
            base = posixpath.dirname(root)
            install_files = {posixpath.join(base, f) for f in run_files}
    packages = {posixpath.dirname(p) for p in files if posixpath.basename(p) == "__init__.py"}
    # Local modules that setup.py imports run during install too.
    setup_dirs: dict[str, set[str]] = {}
    for path, f in files.items():
        if posixpath.basename(path) == "setup.py":
            setup_dirs[posixpath.dirname(path)] = local_imports(f.text())

    for path, f in files.items():
        ext = posixpath.splitext(path)[1].lower()
        foreign = ext in FOREIGN_CODE and ext not in OWN_CODE.get(ecosystem, FOREIGN_CODE)
        dev = (is_dev_file(path) or foreign) and path not in install_files
        found = _check_file(path, f, setup_dirs, install_files, packages, dev)
        if dev:
            found = [x for x in found if x.rule in STRONG]
        findings += found

    findings += _combine(findings)
    return _without_duplicates(findings)


def _check_file(path, f, setup_dirs, install_files, packages, dev) -> list[Finding]:
    name = posixpath.basename(path)
    ext = posixpath.splitext(name)[1].lower()
    kind = binary_kind(f.data[:72])
    if kind and ext in TEXT_EXTENSIONS:
        return [Finding("disguised-binary", f"is {kind} pretending to be a {ext} file",
                        path, critical=True)]
    found = []
    if ext in DROPPED_PROGRAMS:
        found.append(Finding("binary-payload", f"ships {name}", path))
    if ext == ".py":
        role = "runtime" if dev else _python_role(path, setup_dirs, packages)
        found += scan_python(path, f.text(), role)
    elif ext == ".pth":
        found += _check_pth(path, f.text())
    elif ext in JS:
        found += scan_js(path, f.text(), install_time=path in install_files)
    elif ext in SCRIPTS:
        found += check_text(f.text(), path)
    return found


def is_dev_file(path: str) -> bool:
    folders = [p.lower() for p in path.split("/")[:-1]]
    if any(p in DEV_DIRS or p.startswith("test") or p.endswith("tests") for p in folders):
        return True
    return bool(DEV_FILES.match(posixpath.basename(path)))


def _python_role(path: str, setup_dirs: dict[str, set[str]], packages: set[str]) -> str:
    folder, name = posixpath.split(path)
    stem = name[:-3]
    if name == "setup.py" or stem in setup_dirs.get(folder, ()):
        return "setup"
    # Module-level code runs when the module is imported. That needs a name
    # Python can import (not run-bench.py) inside a package, or at the top.
    importable = folder in packages or folder in ("", "src") or folder in setup_dirs
    return "import" if stem.isidentifier() and importable else "runtime"


def _check_pth(path: str, text: str) -> list[Finding]:
    # site.py runs any line in a .pth file that starts with "import".
    lines = [line for line in text.splitlines() if PTH_CODE.match(line)]
    risky = [line for line in lines if PTH_DANGER.search(line)]
    if not risky:
        return []
    line_no = text.splitlines().index(risky[0]) + 1
    return [Finding("pth-file", "has a .pth file that runs code every time Python starts",
                    path, line_no, snippet(risky[0]), critical=True)]


def _combine(findings: list[Finding]) -> list[Finding]:
    """Reading secrets is only theft if the same file can also send them out.
    One kind of credential is normal for a tool (an AWS library reads ~/.aws);
    several kinds, or browser and wallet data, is what stealers collect."""
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.path or "", []).append(f)
    extra = []
    for path, found in by_file.items():
        rules = {f.rule for f in found}
        looted = [f for f in found if f.rule == "secrets"]
        kinds = {f.message for f in found if f.rule == "credentials"}
        if rules & SENDS_DATA and (looted or len(kinds) >= 2):
            first = looted[0] if looted else next(f for f in found if f.rule == "credentials")
            extra.append(Finding("steals-secrets", "reads credentials and can send them out",
                                 path, first.line, first.snippet,
                                 critical="exfil-endpoint" in rules))
    return extra


def _without_duplicates(findings: list[Finding]) -> list[Finding]:
    seen, unique = set(), []
    for f in findings:
        key = (f.rule, f.path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _root_package_json(files) -> str | None:
    candidates = [p for p in files if posixpath.basename(p) == "package.json"
                  and "node_modules/" not in p]
    return min(candidates, key=lambda p: p.count("/"), default=None)


def _guess_ecosystem(files) -> str:
    if _root_package_json(files):
        return "npm"
    return "pypi"
