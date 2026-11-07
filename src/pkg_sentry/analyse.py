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
DROPPED_PROGRAMS = {".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".msi", ".com", ".jar"}
SCRIPTS = {".sh", ".bash", ".bat", ".cmd", ".ps1", ".vbs"}
JS = {".js", ".cjs", ".mjs"}
NOT_IMPORTED = {"test", "tests", "testing", "example", "examples", "docs", "doc", "scripts",
                "benchmarks", "tools", "samples", "demo"}
PTH_CODE = re.compile(r"^\s*import\s", re.MULTILINE)
PTH_DANGER = re.compile(r"exec|eval|b64decode|subprocess|urllib|socket|requests|__import__|compile")
SENDS_DATA = {"exfil-endpoint", "raw-ip-url", "network-at-install", "env-dump", "recon",
              "download-exec"}


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
    # Local modules that setup.py imports run during install too.
    setup_dirs: dict[str, set[str]] = {}
    for path, f in files.items():
        if posixpath.basename(path) == "setup.py":
            setup_dirs[posixpath.dirname(path)] = local_imports(f.text())

    for path, f in files.items():
        name = posixpath.basename(path)
        ext = posixpath.splitext(name)[1].lower()

        kind = binary_kind(f.data[:72])
        if kind and ext in TEXT_EXTENSIONS:
            findings.append(Finding("disguised-binary", f"is {kind} pretending to be a {ext} file",
                                    path, critical=True))
            continue
        if ext in DROPPED_PROGRAMS:
            findings.append(Finding("binary-payload", f"ships {name}", path))

        if ext == ".py":
            findings += scan_python(path, f.text(), _python_role(path, setup_dirs))
        elif ext == ".pth":
            findings += _check_pth(path, f.text())
        elif ext in JS:
            findings += scan_js(path, f.text(), install_time=path in install_files)
        elif ext in SCRIPTS:
            findings += check_text(f.text(), path)

    findings += _combine(findings)
    return _without_duplicates(findings)


def _python_role(path: str, setup_dirs: dict[str, set[str]]) -> str:
    folder, name = posixpath.split(path)
    if name == "setup.py":
        return "setup"
    if name[:-3] in setup_dirs.get(folder, ()):
        return "setup"
    # Module-level code in any module runs when it's imported. Tests, examples
    # and docs aren't imported by users, so they don't count.
    parts = set(path.lower().split("/")[:-1])
    if parts & NOT_IMPORTED or name.startswith(("test_", "conftest")):
        return "runtime"
    return "import"


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
    rules = {f.rule for f in findings}
    extra = []
    if "secrets" in rules and rules & SENDS_DATA:
        secret = next(f for f in findings if f.rule == "secrets")
        extra.append(Finding("steals-secrets", "reads credentials and has a way to send them out",
                             secret.path, secret.line, secret.snippet,
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
