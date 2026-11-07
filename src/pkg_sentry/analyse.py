"""Run the code checks over an unpacked package.

The main job here is deciding *when* each file's code runs, because code
that runs by itself during `pip install`/`npm install` is far more
dangerous than the same code in a function nobody calls:

- setup.py runs during install, and so does everything it imports, runs or
  reads as code (followed from file to file), and an in-tree build backend
- module-level code in a package runs on import
- .pth files run every time Python starts
- npm install hooks run during install, and so does every file they load
"""

import ast
import posixpath
import re

from .archive import Unpacked
from .jsscan import local_requires, scan_gyp, scan_js, scan_package_json
from .pyscan import file_references, imports_of, scan_python, used_imports
from .rules import Finding, snippet
from .textrules import PER_RULE, binary_kind, check_text

TEXT_EXTENSIONS = {".py", ".js", ".cjs", ".mjs", ".ts", ".json", ".txt", ".md", ".rst", ".cfg",
                   ".toml", ".yml", ".yaml", ".css", ".html", ".png", ".jpg", ".jpeg", ".gif",
                   ".svg", ".ico", ".woff", ".ttf", ".pyi", ".map"}
DROPPED_PROGRAMS = {".exe", ".scr", ".msi"}
SCRIPTS = {".sh", ".bash", ".bat", ".cmd", ".ps1", ".vbs"}
JS = {".js", ".cjs", ".mjs"}
CODE = {".py", ".pyw", ".pth", ".pyc", ".sh", ".bat", ".cmd", ".ps1", ".gyp", ".json"} | JS
DEV_DIRS = {"test", "tests", "testing", "example", "examples", "docs", "doc", "scripts",
            "benchmarks", "benchmark", "bench", "tools", "samples", "demo", "demos", "ci",
            ".github", ".circleci", "fixtures", "__fixtures__", "__tests__", "__mocks__", "e2e",
            "dev", "winbuild", ".evergreen"}
DEV_FILES = re.compile(r"^(?:test_.*\.py|conftest\.py|.*_tests?\.py|.*\.(?:test|spec)\.[cm]?js"
                       r"|make\.bat|gulpfile\.js|gruntfile\.js|karma\.conf\.js)$", re.IGNORECASE)
# Code in tests, docs and build tooling doesn't run when someone installs or
# uses the package, so only signs that are never innocent count there.
STRONG = {"exfil-endpoint", "disguised-binary", "pth-file", "archive-escape"}
# Files in the other ecosystem's language don't run on install or import:
# JavaScript in a PyPI package is a web asset, Python in an npm package a helper.
OWN_CODE = {"pypi": {".py", ".pth"}, "npm": {".js", ".cjs", ".mjs"}}
FOREIGN_CODE = {".py", ".js", ".cjs", ".mjs"}
PTH_DANGER = re.compile(
    r"b64decode|base64|zlib|marshal|subprocess|os\.system|popen|os\.spawn|os\.exec|execl|execv"
    r"|urllib|urlopen|socket|requests|http\.client|codecs\.decode|fromhex|chr\(|getattr\(\s*os"
    r"|open\("
)
PTH_PLAIN_IMPORT = re.compile(r"^\s*import\s+[\w.]+\s*$")
PTH_MODULES = {"sys", "types", "os", "importlib"}
PTH_IMPORTS = {"importlib", "importlib.util", "importlib.machinery", "_distutils_hack"}
PTH_CALLS = {"os.path.join", "os.path.dirname", "os.path.exists", "sys._getframe",
             "sys.modules.setdefault", "importlib.util.module_from_spec",
             "importlib.machinery.PathFinder.find_spec", "types.ModuleType", "os.environ.get",
             "m.__dict__.setdefault", "mp.append"}
SENDS_DATA = {"exfil-endpoint", "raw-ip-url", "network-at-install", "env-dump", "recon",
              "download-exec", "fetch-and-run"}
FOLLOW_LIMIT = 300


def analyse(unpacked: Unpacked, ecosystem: str | None = None) -> list[Finding]:
    files = {f.path: f for f in unpacked.files}
    ecosystem = ecosystem or guess_ecosystem(files)
    findings = [Finding("archive-escape", f"has a file that {why}", path)
                for path, why in unpacked.suspicious[:PER_RULE]]
    findings += _unread(unpacked)

    packages = {posixpath.dirname(p) for p in files if posixpath.basename(p) == "__init__.py"}
    install_files: set[str] = set()
    setup_files: dict[str, str] = {}
    if ecosystem == "npm":
        root = root_package_json(files)
        if root:
            found, run_files = scan_package_json(root, files[root].text())
            findings += found
            base = posixpath.dirname(root)
            install_files = _follow_requires(
                {posixpath.normpath(posixpath.join(base, f)) for f in run_files}, files)
    else:
        setup_files = _setup_files(files)

    for path, f in files.items():
        ext = posixpath.splitext(path)[1].lower()
        install = path in install_files or path in setup_files
        foreign = ext in FOREIGN_CODE and ext not in OWN_CODE.get(ecosystem, FOREIGN_CODE)
        dev = not install and (foreign or is_dev_file(path, packages))
        found = _check_file(path, f, ecosystem, setup_files, install_files, packages, dev)
        if dev:
            found = [x for x in found if x.rule in STRONG]
        findings += found

    findings += _combine(findings)
    return _without_duplicates(findings)


def _check_file(path, f, ecosystem, setup_files, install_files, packages, dev) -> list[Finding]:
    name = posixpath.basename(path)
    ext = posixpath.splitext(name)[1].lower()
    kind = binary_kind(f.data[:72])
    if kind and ext in TEXT_EXTENSIONS:
        return [Finding("disguised-binary", f"is {kind} pretending to be a {ext} file",
                        path, critical=True)]
    found = []
    if ext in DROPPED_PROGRAMS:
        found.append(Finding("binary-payload", f"ships {name}", path))
    if path in setup_files and ext not in (".py", ".pyc") and ext not in JS:
        # Something setup.py reads as code or runs, whatever its extension.
        found += scan_python(path, f.data, "setup")
        found += check_text(f.text(), path, install_time=True)
    elif ext == ".py":
        role = "runtime" if dev else _python_role(path, setup_files, packages)
        found += scan_python(path, f.data, role)
    elif ext == ".pyc":
        loaded = path in setup_files
        found.append(Finding("compiled-python",
                             "setup.py loads compiled Python that can't be read" if loaded
                             else "ships compiled Python (.pyc) that can't be read",
                             path, points=45 if loaded else None))
    elif ext == ".pth":
        found += _check_pth(path, f.text())
    elif ext in JS:
        found += scan_js(path, f.text(), install_time=path in install_files or path in setup_files)
    elif ext in SCRIPTS:
        found += check_text(f.text(), path, install_time=path in install_files)
    elif name == "binding.gyp" and ecosystem == "npm":
        found += scan_gyp(path, f.text())
    return found


def guess_ecosystem(files) -> str:
    return "npm" if "package.json" in files and not looks_like_python(files) else "pypi"


def looks_like_python(files) -> bool:
    return any(p in ("setup.py", "PKG-INFO", "pyproject.toml") for p in files) or any(
        p.split("/", 1)[0].endswith(".dist-info") for p in files)


def root_package_json(files) -> str | None:
    if "package.json" in files:
        return "package.json"
    candidates = [p for p in files if posixpath.basename(p) == "package.json"
                  and "node_modules/" not in p]
    return min(candidates, key=lambda p: (p.count("/"), p), default=None)


def is_dev_file(path: str, packages=frozenset()) -> bool:
    folders = path.split("/")[:-1]
    for i, folder in enumerate(folders):
        lower = folder.lower()
        named_dev = lower in DEV_DIRS or lower.endswith("tests")
        # A top-level package called tools/ or testinfra/ is the library itself.
        here = "/".join(folders[: i + 1])
        top_package = here in packages and (i == 0 or folders[:i] == ["src"])
        if named_dev and not top_package:
            return True
    return bool(DEV_FILES.match(posixpath.basename(path)))


def _python_role(path: str, setup_files: dict[str, str], packages: set[str]) -> str:
    folder, name = posixpath.split(path)
    if path in setup_files:
        return setup_files[path]
    # Module-level code runs when the module is imported. That needs a name
    # Python can import (not run-bench.py) inside a package, or at the top.
    importable = folder in packages or folder in ("", "src")
    return "import" if name[:-3].isidentifier() and importable else "runtime"


def _setup_files(files) -> dict[str, str]:
    """What runs during `pip install`, and how much of it: "setup" means all
    of a file's code counts, "import" means only its top level runs.

    - setup.py, an in-tree build backend, and files they run or exec are
      "setup", and everything they call into is followed.
    - A module whose functions get called (or that's handed to setup() as a
      cmdclass) is "setup" too, but only its top level is followed further.
      Following every call of every called function would pull in the whole
      build toolchain (mypy's setup.py calls mypyc, which calls all of mypy).
    - A module that's only imported is "import"."""
    start = [p for p in files if posixpath.basename(p) == "setup.py"] + _build_backend(files)
    roots = {posixpath.dirname(p) for p in start} | {""}
    rank: dict[str, int] = {}  # 0 imported, 1 called into, 2 run whole
    queue = [(p, 2) for p in start]
    while queue and len(rank) < FOLLOW_LIMIT:
        path, level_ = queue.pop()
        if rank.get(path, -1) >= level_:
            continue
        rank[path] = level_
        if not path.endswith(".py"):
            continue  # only follow imports and paths out of Python
        data, base = files[path].data, posixpath.dirname(path)
        everywhere = level_ == 2
        here = roots | {base}
        for level, dotted in imports_of(data):
            queue += [(m, 0) for m in _module_files(dotted, level, base, here, files)]
        for level, dotted in used_imports(data, everywhere):
            queue += [(m, 1) for m in _module_files(dotted, level, base, here, files,
                                                    deepest=True)]
        for ref in file_references(data, everywhere):
            for candidate in (posixpath.normpath(posixpath.join(base, ref)), ref):
                if candidate in files:
                    queue.append((candidate, 2))
    return {path: "setup" if r else "import" for path, r in rank.items()}


def _module_files(dotted: str, level: int, base: str, roots: set[str], files,
                  deepest: bool = False) -> list[str]:
    """The files `import dotted` runs: every package's __init__.py on the way
    down, then the module itself. With deepest, only the module the name
    ends up in (`helpers.go` is a function in helpers/__init__.py)."""
    if level:
        anchor = base
        for _ in range(level - 1):
            anchor = posixpath.dirname(anchor)
        roots = {anchor}
    parts = [p for p in dotted.split(".") if p]
    found = []
    for root in roots:
        here = []
        for i in range(len(parts) + 1):
            if not i and not level:
                continue
            stem = posixpath.join(root, *parts[:i]) if i else root
            matches = [c.lstrip("/") for c in (f"{stem}.py", f"{stem}.pyc", f"{stem}/__init__.py")
                       if c.lstrip("/") in files and (i or c.endswith("__init__.py"))]
            if matches:
                here.append(matches)
        if here:
            found += here[-1] if deepest else [m for group in here for m in group]
    return found


def _build_backend(files) -> list[str]:
    """In-tree build backends and cmdclass modules named in pyproject.toml."""
    root = next((p for p in files if posixpath.basename(p) == "pyproject.toml"
                 and p.count("/") <= 1), None)
    if not root:
        return []
    text = files[root].text()
    base = posixpath.dirname(root)
    dirs = set()
    for group in re.findall(r"backend-path\s*=\s*\[([^\]]{0,500})\]", text):
        dirs |= {posixpath.normpath(posixpath.join(base, d)).lstrip("./")
                 for d in re.findall(r"['\"]([^'\"]{1,200})['\"]", group)}
    # Without backend-path the backend comes from PyPI, not from this package.
    modules = re.findall(r"build-backend\s*=\s*['\"]([\w.]+)", text) if dirs else []
    dirs.add(base)
    cmdclass = re.search(r"\[tool\.setuptools\.cmdclass\]([^\[]{0,2000})", text)
    if cmdclass:
        modules += [m.rsplit(".", 1)[0] for m in re.findall(r"=\s*['\"]([\w.]+)['\"]",
                                                              cmdclass.group(1))]
    found = []
    for module in modules:
        found += _module_files(module, 0, base, dirs, files)
    return found


def _follow_requires(start: set[str], files) -> set[str]:
    """npm install files and everything they require, followed through."""
    seen: set[str] = set()
    queue = [p for p in start if p in files]
    while queue and len(seen) < FOLLOW_LIMIT:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        base = posixpath.dirname(path)
        for spec in local_requires(files[path].text()):
            target = posixpath.normpath(posixpath.join(base, spec)).lstrip("/")
            for candidate in (target, f"{target}.js", f"{target}.cjs", f"{target}.mjs",
                              f"{target}/index.js"):
                if candidate in files:
                    queue.append(candidate)
    return seen


def _check_pth(path: str, text: str) -> list[Finding]:
    # site.py runs any line in a .pth file that starts with "import".
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.lstrip().startswith("import") or PTH_PLAIN_IMPORT.match(line):
            continue
        if _known_pth(line):
            continue
        if PTH_DANGER.search(line):
            found.append(Finding("pth-file", "has a .pth file that runs code every time Python "
                                 "starts", path, number, snippet(line), critical=True))
        else:
            found.append(Finding("pth-code", "has a .pth file that runs a line of code every time "
                                 "Python starts", path, number, snippet(line)))
    return found + check_text(text, path, install_time=True)


def _known_pth(line: str) -> bool:
    """The two kinds of .pth line that honest packages ship: setuptools'
    namespace-package loader and its distutils shim. Only calls from those
    templates are allowed, so tacking anything else on still gets noticed."""
    try:
        tree = ast.parse(line.strip())
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if _dotted(func) == "__import__":
                arg = node.args[0] if len(node.args) == 1 and not node.keywords else None
                if not (isinstance(arg, ast.Constant) and arg.value in PTH_IMPORTS):
                    return False
            elif not (_dotted(func) in PTH_CALLS or isinstance(func, ast.Attribute)
                      and func.attr == "add_shim" and _shim_import(func.value)):
                return False
        elif isinstance(node, ast.Import):
            if any(alias.name not in PTH_MODULES or alias.asname for alias in node.names):
                return False
        elif isinstance(node, (ast.ImportFrom, ast.Lambda, ast.FunctionDef, ast.ClassDef)):
            return False
    return True


def _dotted(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return ".".join([node.id, *reversed(parts)])
    return None


def _shim_import(node) -> bool:
    return (isinstance(node, ast.Call) and _dotted(node.func) == "__import__"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "_distutils_hack")


def _unread(unpacked: Unpacked) -> list[Finding]:
    """Code that couldn't be read can't be called clean."""
    found = []
    for path, why in unpacked.skipped:
        name = posixpath.basename(path)
        ext = posixpath.splitext(path)[1].lower()
        if path != "*" and ext not in CODE and name not in ("setup.py", "package.json"):
            continue
        if why in ("symlink", "hard link"):
            continue
        key = name in ("setup.py", "package.json") or ext == ".pth"
        where = "part of the package" if path == "*" else path
        found.append(Finding("unread-code", f"couldn't read {where} ({why}), so it could be "
                             "hiding anything", None if path == "*" else path,
                             points=60 if key else None))
    return found


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
