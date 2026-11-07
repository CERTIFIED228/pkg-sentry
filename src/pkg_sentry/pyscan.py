"""Static checks for Python files.

The file is parsed with `ast`, never imported or run. Import aliases are
followed (`import base64 as b`, `__import__("base64")`, `_s = os.system`)
so renaming things doesn't hide a call, and the tree is walked with an
explicit stack, so code nested thousands of levels deep can't crash the scan.
Files that don't parse (Python 2, or broken on purpose) still get the text
checks.
"""

import ast
import codecs
import io
import re
import tokenize
import warnings

from .rules import Finding, snippet
from .textrules import check_text, line_finder

EXEC = {"exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile"}
DECODE_PREFIXES = ("base64.", "zlib.decompress", "gzip.decompress", "bz2.decompress",
                   "lzma.decompress", "marshal.loads", "codecs.decode", "binascii.",
                   "pickle.loads", "bytes.fromhex")
DECODE_METHODS = {"decrypt", "fromhex", "b64decode", "decompress", "unhexlify"}
SHELL = {"os.system", "os.popen", "os.startfile", "pty.spawn", "commands.getoutput",
         "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec"}
SHELL_PREFIXES = ("subprocess.", "os.exec", "os.spawn", "os.posix_spawn")
NETWORK_PREFIXES = ("urllib.request.urlopen", "urllib.request.urlretrieve",
                    "urllib.request.Request", "urllib2.urlopen", "urllib.urlopen",
                    "urllib.urlretrieve", "requests.",
                    "httpx.", "http.client.HTTP", "socket.socket", "socket.create_connection",
                    "aiohttp.ClientSession", "smtplib.SMTP", "ftplib.FTP", "dns.resolver.",
                    "socket.gethostbyname", "socket.getaddrinfo", "wget.download",
                    "pycurl.Curl", "websocket.", "telebot.", "discord_webhook.")
RECON = {"socket.gethostname", "getpass.getuser", "os.getlogin", "platform.node", "platform.uname",
         "os.uname", "uuid.getnode"}
LOOKUPS = {"socket.gethostbyname", "socket.getaddrinfo", "socket.gethostbyname_ex",
           "dns.resolver.resolve", "dns.resolver.query"}
DUMPERS = {"dict", "str", "repr", "json.dumps", "urllib.parse.urlencode", "list"}
# Commands people run from setup.py while building, not to attack anyone.
BUILD_TOOLS = {"git", "cmake", "make", "gcc", "cc", "g++", "clang", "pkg-config", "cython",
               "nvcc", "xcrun", "hipcc", "ninja", "meson", "cargo", "rustc", "swig", "uname",
               "nproc", "which", "where", "lsb_release", "sw_vers", "python", "python3", "brew",
               "twine", "pip", "pip3", "tox", "coverage", "patchelf", "install_name_tool",
               "otool", "ldd", "autoreconf", "autogen.sh", "configure", "rm", "cp", "mv", "mkdir",
               "npm", "yarn", "node", "protoc", "f2py", "sphinx-build", "ps", "hg", "svn"}
SHELLS = {"sh", "bash", "/bin/sh", "/bin/bash"}
RUNNABLE = re.compile(r"\.(?:exe|bat|cmd|ps1|vbs|scr|msi|sh)\b", re.IGNORECASE)
OBFUSCATOR = re.compile(
    r"\bfrom\s+pyarmor_runtime\w*\s+import|__pyarmor__\s*\(|Obfuscated (?:with|by) "
)
# Names obfuscators generate: IlIlIlIl, OO0O0O0O, _0x1f2a, __________1
SCRAMBLED_NAME = re.compile(r"^(?:[Il]{6,}|[O0]{6,}|_0x[0-9a-f]{3,}|_{4,}\d*)$")
EXEC_WORDS = re.compile(r"\b(?:exec|eval|compile)\b")
SHELL_WORDS = re.compile(r"\b(?:system|popen|subprocess|Popen|call|run|spawn\w*|startfile)\b")
RECON_WORDS = re.compile(r"\b(?:gethostname|getuser|getlogin|node|uname|getnode)\b")
BLOB = re.compile(r"^[A-Za-z0-9+/=\s]{2000,}$|^[0-9a-fA-F\s]{2000,}$")
# Source encodings real projects use. Anything else in a coding line (utf-7,
# unicode_escape...) lets code read as harmless text but run as something else.
NORMAL_ENCODINGS = {"utf-8", "utf-8-sig", "ascii", "latin-1", "iso8859-1", "iso8859-15",
                    "iso8859-2", "cp1250", "cp1251", "cp1252", "koi8-r", "euc_jp", "shift_jis",
                    "cp932", "gbk", "gb2312", "gb18030", "big5", "euc_kr", "cp949", "mac-roman"}


def decode_source(data: bytes | str) -> tuple[str, str]:
    """Text of a Python file as Python itself would read it, and its encoding."""
    if isinstance(data, str):
        return data, "utf-8"
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        encoding = codecs.lookup(encoding).name
    except (SyntaxError, LookupError):
        encoding = "utf-8"
    try:
        return data.decode(encoding, errors="replace"), encoding
    except (LookupError, UnicodeError):
        return data.decode("utf-8", errors="replace"), "utf-8"


def parse(source: str) -> ast.Module | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def scan_python(path: str, data: bytes | str, role: str = "runtime") -> list[Finding]:
    """role: "setup" (everything runs at install), "import" (module-level
    code runs when imported) or "runtime"."""
    source, encoding = decode_source(data)
    found = []
    if encoding not in NORMAL_ENCODINGS:
        found.append(Finding("obfuscated", f"declares the unusual source encoding {encoding}, "
                             "which hides code from anything reading it as plain text", path, 1,
                             snippet(source.split("\n", 2)[0]), critical=role == "setup"))
    tree = parse(source)
    if tree is None:
        return found + _scan_unparsable(path, source, role)
    visitor = _Visitor(path, source, role)
    visitor.tree = tree
    try:
        visitor.prepare(tree)
        visitor.walk(tree)
    except RecursionError:
        if role != "runtime":
            found.append(Finding("obfuscated", "is nested too deeply to analyse", path, None,
                                 None, points=25))
        return found + _scan_unparsable(path, source, role)
    return found + visitor.finish()


def imports_of(data: bytes | str) -> set[tuple[int, str]]:
    """(level, dotted name) for every import: `from . import x` is (1, "x")."""
    tree = parse(decode_source(data)[0])
    if tree is None:
        return set()
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {(0, a.name) for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            found.add((node.level, base))
            found |= {(node.level, f"{base}.{a.name}".strip(".")) for a in node.names}
    return found


# Calls that run a file rather than read it: exec(open(x).read()),
# runpy.run_path(x), subprocess.call(["sh", x]).
RUNS_FILES = {"exec", "eval", "compile", "execfile", "run_path", "system", "popen", "Popen",
              "call", "check_call", "check_output", "run", "spec_from_file_location",
              "SourceFileLoader", "load_source", "startfile", "getoutput"}
PATH_LIKE = re.compile(r"\.?/?[\w.-]+(?:/[\w.-]+)*\.\w{1,5}")


def file_references(data: bytes | str, everywhere: bool = True) -> set[str]:
    """Relative paths (scripts/build.sh) that code which runs hands to exec,
    runpy or a subprocess. Reading a README or a version file doesn't count."""
    tree = parse(decode_source(data)[0])
    if tree is None:
        return set()
    assigned: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned.setdefault(target.id, []).append(node.value)
    found = set()
    for node in running_nodes(tree, everywhere):
        if not isinstance(node, ast.Call):
            continue
        parts = _dotted_parts(node.func)
        if not parts or not (parts[-1] in RUNS_FILES or parts[-1].startswith(("exec", "spawn"))):
            continue
        sources = [node]
        # cmd = ["sh", "install.sh"]; subprocess.call(cmd)
        sources += [v for n in ast.walk(node) if isinstance(n, ast.Name)
                    for v in assigned.get(n.id, [])[:5]]
        found |= {n.value.strip().removeprefix("./") for source in sources
                  for n in ast.walk(source)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and 0 < len(n.value) < 200 and PATH_LIKE.fullmatch(n.value.strip())}
    return found


def used_imports(data: bytes | str, everywhere: bool = True) -> set[tuple[int, str]]:
    """Modules whose code this file actually runs: an imported name that's
    called, subclassed or handed to setup() as a cmdclass. Importing a module
    only runs its top level; calling into it runs the function too.
    `from helpers import go; go()` gives (0, "helpers.go")."""
    tree = parse(decode_source(data)[0])
    if tree is None:
        return set()
    bound: dict[str, tuple[int, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    bound[a.asname] = (0, a.name)
                else:
                    top = a.name.split(".")[0]
                    bound[top] = (0, top)
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name != "*":
                    bound[a.asname or a.name] = (node.level,
                                                 f"{node.module or ''}.{a.name}".strip("."))
    used = set()
    for node in running_nodes(tree, everywhere):
        targets = []
        if isinstance(node, ast.Call):
            targets.append(node.func)
            # cmdclass={"install": helpers.PostInstall} runs during pip install
            targets += [v for k in node.keywords if k.arg == "cmdclass"
                        and isinstance(k.value, ast.Dict) for v in k.value.values]
        elif isinstance(node, ast.ClassDef):
            targets += node.bases
        for target in targets:
            parts = _dotted_parts(target)
            if parts and parts[0] in bound:
                level, module = bound[parts[0]]
                used.add((level, ".".join([module, *parts[1:-1]]).strip(".")))
                if len(parts) > 1:
                    used.add((level, ".".join([module, *parts[1:]]).strip(".")))
    return used


# setup.py commands that pip runs while installing. A cmdclass entry under
# any other name (`python setup.py import_cldr`) only runs when asked for.
INSTALL_COMMANDS = {"install", "build", "build_py", "build_ext", "build_clib", "build_scripts",
                    "egg_info", "develop", "bdist_wheel", "bdist_egg", "bdist", "sdist",
                    "install_lib", "install_scripts", "install_data", "install_headers",
                    "install_egg_info", "editable_wheel", "dist_info", "build_src"}


def running_nodes(tree: ast.Module, everywhere: bool = True):
    """Every node, or with everywhere=False only what runs when the module is
    imported: the top level and the local functions it calls, but not other
    function bodies or `if __name__ == "__main__"` blocks. Either way, setup()
    commands pip never runs are left out."""
    if everywhere:
        idle = _idle_commands(tree)
        stack = [tree]
        while stack:
            node = stack.pop()
            if isinstance(node, ast.ClassDef) and node.name in idle:
                continue
            yield node
            stack.extend(ast.iter_child_nodes(node))
        return
    functions = {n.name: n for n in tree.body
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    entered: set[str] = set()
    stack = list(reversed(tree.body))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.If) and _is_main_guard(node.test):
            stack.extend(reversed(node.orelse))
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in functions and node.func.id not in entered:
            entered.add(node.func.id)
            stack.extend(reversed(functions[node.func.id].body))
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _idle_commands(tree: ast.Module) -> set[str]:
    """Classes only used as setup() commands that pip doesn't run."""
    used, idle = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=False):
                if isinstance(value, ast.Name) and isinstance(key, ast.Constant):
                    (used if key.value in INSTALL_COMMANDS else idle).add(value.id)
    return idle - used


def _dotted_parts(node) -> list[str] | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return [node.id, *reversed(parts)]
    return None


class _Visitor:
    def __init__(self, path, source, role):
        self.path, self.source, self.role = path, source, role
        self.aliases: dict[str, str] = {}
        self.decoded_names: set[str] = set()
        self.network_names: set[str] = set()
        self.recon_names: set[str] = set()
        self.decode_funcs: set[str] = set()
        self.called_at_import: set[str] = set()
        self.depth = 0
        self.findings: list[Finding] = []
        self.calls: list[tuple[str, ast.Call, bool]] = []
        self.env_dumps: list[ast.AST] = []
        self.scrambled: set[str] = set()
        self.tree: ast.Module | None = None
        # Decoded/downloaded variables only matter if something execs them.
        self.track_values = bool(EXEC_WORDS.search(source) or SHELL_WORDS.search(source))
        self.track_recon = bool(RECON_WORDS.search(source))

    @property
    def install_time(self) -> bool:
        return self.role == "setup" or (self.role == "import" and self.depth == 0)

    def prepare(self, tree: ast.Module) -> None:
        """First pass: imports, functions that return decoded data, and which
        local functions the module calls from its top level."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._note_import(node)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                returns = [node.body] if isinstance(node, ast.Lambda) else [
                    n.value for n in ast.walk(node) if isinstance(n, ast.Return) and n.value]
                if any(self._contains(r, self._is_decode) for r in returns):
                    if isinstance(node, ast.Lambda):
                        continue
                    self.decode_funcs.add(node.name)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
                if self._contains(node.value.body, self._is_decode):
                    self.decode_funcs.update(t.id for t in node.targets if isinstance(t, ast.Name))
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, ast.If) and _is_main_guard(stmt.test):
                continue
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.called_at_import.add(node.func.id)

    def walk(self, tree: ast.Module) -> None:
        # (node, depth) pairs on an explicit stack instead of recursion.
        stack = [(tree, 0)]
        while stack:
            node, depth = stack.pop()
            self.depth = depth
            self._handle(node)
            stack.extend(reversed(list(self._children(node, depth))))

    def _children(self, node, depth):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # A function the module itself calls at the top level runs on import too.
            runs_now = depth == 0 and node.name in self.called_at_import
            for child in ast.iter_child_nodes(node):
                yield child, depth if runs_now else depth + 1
        elif isinstance(node, ast.Lambda):
            for child in ast.iter_child_nodes(node):
                yield child, depth + 1
        elif isinstance(node, ast.If) and _is_main_guard(node.test):
            # `if __name__ == "__main__":` only runs when the file is run directly.
            yield node.test, depth
            for child in node.body:
                yield child, depth + 1
            for child in node.orelse:
                yield child, depth
        else:
            for child in ast.iter_child_nodes(node):
                yield child, depth

    def _handle(self, node) -> None:
        if isinstance(node, ast.Call):
            self._visit_call(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
            self._visit_assign(node)
        elif isinstance(node, ast.Name):
            if SCRAMBLED_NAME.match(node.id):
                self.scrambled.add(node.id)
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str) and len(node.value) >= 2000 and BLOB.match(node.value):
                self.add("obfuscated", "carries a large encoded blob", node, points=10)

    def _note_import(self, node) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                self.aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif node.module and not node.level:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def _visit_assign(self, node) -> None:
        value = node.value
        if value is None:
            return
        raw_targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        # x = ..., a, b = ... and self.x = ... (as "self.x", not marking `self` itself)
        targets = [n for t in raw_targets for n in _assigned_names(t)]
        if not targets or isinstance(value, ast.Constant):
            return
        if isinstance(value, (ast.Name, ast.Attribute)):
            # _ssystem = os.system, then _ssystem("...")
            name = self.name_of(value)
            if name and _dangerous(name):
                self.aliases.update({t: name for t in targets})
            if isinstance(value, ast.Name) and value.id in self.decoded_names:
                self.decoded_names.update(targets)
            return
        if self.track_recon and self._contains(value, self._is_recon):
            self.recon_names.update(targets)
        if self.track_values and self._contains(value, self._is_decode):
            self.decoded_names.update(targets)
        if self.track_values and self._contains(value, self._is_network):
            self.network_names.update(targets)
        name = self.name_of(value) if isinstance(value, ast.Call) else None
        if name and name.startswith(("importlib.import_module", "__import__")):
            module = _const_arg(value)
            if module:
                self.aliases.update({t: module for t in targets})

    def _visit_call(self, node) -> None:
        name = self.name_of(node.func)
        if name:
            self.calls.append((name, node, self.install_time))
            self._check_call(name, node)
        if name in ("__import__", "importlib.import_module") and node.args:
            if not _const(node.args[0]) and any(
                isinstance(n, ast.Call) and self.name_of(n.func) == "chr"
                for n in ast.walk(node.args[0])
            ):
                self.add("obfuscated", "hides which module it imports", node)
        if name == "setup" or (name or "").endswith(".setup"):
            self._check_setup(node)

    # -- names ---------------------------------------------------------------

    def name_of(self, node) -> str | None:
        """Dotted name of a call target, with import aliases resolved."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        elif isinstance(node, ast.Call):
            inner = self.name_of(node.func)
            if inner in ("__import__", "importlib.import_module") and _const_arg(node):
                parts.append(_const_arg(node))
            elif inner == "getattr" and len(node.args) >= 2:
                attr, base = _const(node.args[1]), self.name_of(node.args[0])
                if attr and base:
                    parts.append(f"{base}.{attr}" if base != "builtins" else attr)
                else:
                    return None
            else:
                return None
        else:
            return None
        return ".".join(reversed(parts))

    def _is_decode(self, node) -> bool:
        if isinstance(node, (ast.Name, ast.Attribute)):
            return _name_key(node) in self.decoded_names
        if isinstance(node, ast.Subscript) and _reversed_slice(node.slice):
            # "...)1(tnirp"[::-1]. Only a literal: shape[::-1] is everywhere in numpy code.
            return isinstance(node.value, ast.Constant) and isinstance(node.value.value,
                                                                      (str, bytes))
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Name) and func.id in self.decode_funcs:
            return True
        name = self.name_of(func) or ""
        if name.startswith(DECODE_PREFIXES):
            return True
        if isinstance(func, ast.Attribute) and func.attr in DECODE_METHODS:
            return True
        # ''.join(chr(x) for x in [...]) and bytes([...]).decode()
        if isinstance(func, ast.Attribute) and func.attr == "join":
            return any(isinstance(n, ast.Call) and self.name_of(n.func) == "chr"
                       for n in ast.walk(node))
        if isinstance(func, ast.Attribute) and func.attr == "decode":
            return self._contains(func.value, lambda n: isinstance(n, ast.Call) and
                                  self.name_of(n.func) in ("bytes", "bytearray"))
        return False

    def _is_network(self, node) -> bool:
        if isinstance(node, (ast.Name, ast.Attribute)):
            return _name_key(node) in self.network_names
        if not isinstance(node, ast.Call):
            return False
        name = self.name_of(node.func) or ""
        return name.startswith(NETWORK_PREFIXES)

    def _is_recon(self, node) -> bool:
        if isinstance(node, (ast.Name, ast.Attribute)):
            return _name_key(node) in self.recon_names
        return isinstance(node, ast.Call) and self.name_of(node.func) in RECON

    def _contains(self, node, test) -> bool:
        return any(test(n) for n in ast.walk(node))

    # -- rules ---------------------------------------------------------------

    def add(self, rule, message, node, critical=False, points=None):
        line = getattr(node, "lineno", None)
        text = ast.get_source_segment(self.source, node) if hasattr(node, "end_lineno") else None
        self.findings.append(Finding(rule, message, self.path, line,
                                     snippet(text or ""), critical, points))

    def _check_call(self, name, node):
        args = list(node.args) + [k.value for k in node.keywords]
        when = "during install" if self.role == "setup" else "on import"

        if name in EXEC and args:
            payload = args[0]
            if self._contains(payload, self._is_network):
                self.add("download-exec", "downloads code and runs it", node,
                         critical=self.install_time)
            elif self._contains(payload, self._is_decode):
                self.add("exec-decoded", "decodes hidden code and runs it", node,
                         critical=self.install_time)
            elif self.install_time and not _const(payload) and not _reads_a_file(payload):
                self.add("exec-dynamic", f"runs code built at runtime {when}", node)

        if (name in SHELL or name.startswith(SHELL_PREFIXES)) and self.track_values and any(
                self._contains(a, self._is_decode) for a in args):
            self.add("exec-decoded", "decodes a hidden command and runs it", node,
                     critical=self.install_time)

        if name in SHELL or name.startswith(SHELL_PREFIXES):
            if self.install_time and not _build_tool(args):
                # A command spelled out in the code is clearer evidence than
                # one assembled from variables (often a compiler invocation).
                spelled_out = bool(args) and _const_command(args[0])
                self.add("shell-at-install", f"runs commands {when}", node,
                         points=None if spelled_out else 15)
            else:
                self.add("shell", "runs shell commands", node)
            strings = [_const(n) or "" for a in args for n in ast.walk(a)]
            if name == "os.startfile" or any(RUNNABLE.search(text) for text in strings):
                self.calls.append(("runs-a-program", node, self.install_time))

        if name.startswith(NETWORK_PREFIXES) and self.install_time:
            self.add("network-at-install", f"connects to the internet {when}", node)
        if name.startswith(NETWORK_PREFIXES) and self.track_recon and any(
                self._contains(a, self._is_recon) for a in args) and not (
                name in LOOKUPS and not any(_mixes_text(a) for a in args)):
            # gethostbyname(gethostname()) just finds this machine's own IP. Sending the
            # name inside a DNS query (f"{user}.attacker.com") is the beacon.
            self.add("recon", "sends this computer's name or user name to a server", node,
                     points=25)

        if name in DUMPERS and any(self.name_of(a) == "os.environ" for a in node.args):
            self.env_dumps.append(node)
        elif name.startswith(NETWORK_PREFIXES) and any(
                self.name_of(a) == "os.environ" for a in args):
            self.env_dumps.append(node)

    def _check_setup(self, node):
        for kw in node.keywords:
            if kw.arg != "cmdclass" or not isinstance(kw.value, ast.Dict):
                continue
            for key in kw.value.keys:
                command = _const(key)
                if command in ("install", "develop", "egg_info"):
                    self.add("install-hook", f"replaces the '{command}' command with its own code",
                             key)

    def finish(self) -> list[Finding]:
        names = [name for name, _, _ in self.calls]
        has_network = any(n.startswith(NETWORK_PREFIXES) and n not in LOOKUPS for n in names)

        if has_network:
            for name, node, install_time in self.calls:
                if name == "runs-a-program":
                    self.add("download-exec", "downloads a program and starts it", node,
                             critical=install_time, points=None if install_time else 25)
            if self.env_dumps:
                self.add("env-dump", "collects all environment variables and sends them out",
                         self.env_dumps[0])
            for name, node, _ in self.calls:
                if name in RECON:
                    self.add("recon", "collects details about the machine and sends them",
                             node)
                    break

        m = OBFUSCATOR.search(self.source)
        if m:
            self.findings.append(Finding("obfuscated", "deliberately scrambled code",
                                         self.path, line_finder(self.source)(m.start()),
                                         snippet(m.group(0))))
        elif len(self.scrambled) >= 5:
            names = ", ".join(sorted(self.scrambled)[:3])
            self.findings.append(Finding("obfuscated", f"deliberately scrambled names ({names}...)",
                                         self.path))

        self.findings += self._text_checks()
        return self.findings

    def _text_checks(self) -> list[Finding]:
        found = check_text(self.source, self.path, install_time=self.role == "setup")
        if self.role != "import" or not found or self.tree is None:
            return found
        # A module's top level runs on import (during install, if setup.py
        # imports it), so hits there count as install time. The text checks
        # work line by line, so they're run again and matched up by line.
        top = _top_level_lines(self.tree)
        strong = check_text(self.source, self.path, install_time=True)
        return ([f for f in found if f.line not in top]
                + [f for f in strong if f.line in top])


def _name_key(node) -> str | None:
    """"x" for x, "self.x" for self.x: how assigned values are remembered."""
    parts = _dotted_parts(node)
    return ".".join(parts) if parts else None


def _assigned_names(target):
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Attribute):
        parts = _dotted_parts(target)
        if parts:
            yield ".".join(parts)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _assigned_names(element)
    elif isinstance(target, ast.Starred):
        yield from _assigned_names(target.value)


def _top_level_lines(tree: ast.Module) -> set[int]:
    """Lines that run when the module is imported: not inside a function or
    an `if __name__ == "__main__"` block."""
    lines = set()
    stack = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.If) and _is_main_guard(node.test):
            stack.extend(node.orelse)
            continue
        inner = [child for name in ("body", "orelse", "finalbody", "handlers", "cases")
                 for child in getattr(node, name, None) or []]
        if not hasattr(node, "lineno"):
            stack.extend(inner)
        elif inner:
            # if/try/with/class: the header line, then each statement inside
            first = min((c.lineno for c in inner if hasattr(c, "lineno")), default=node.lineno)
            lines.update(range(node.lineno, max(node.lineno, first - 1) + 1))
            stack.extend(inner)
        else:
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


def _is_main_guard(test) -> bool:
    """Exactly `__name__ == "__main__"` (either way round), possibly with `and`.
    `!=` or `or` would run on import, so they don't count."""
    if isinstance(test, ast.BoolOp):
        return isinstance(test.op, ast.And) and any(_is_main_guard(v) for v in test.values)
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = [test.left, test.comparators[0]]
    has_name = any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides)
    return has_name and any(_const(s) == "__main__" for s in sides)


def _reversed_slice(node) -> bool:
    if not isinstance(node, ast.Slice) or node.step is None:
        return False
    step = node.step
    if isinstance(step, ast.UnaryOp) and isinstance(step.op, ast.USub):
        step = step.operand
        return isinstance(step, ast.Constant) and step.value == 1
    return isinstance(step, ast.Constant) and step.value == -1


def _const(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _build_tool(args) -> bool:
    if not args:
        return False
    first = args[0]
    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
        first = first.elts[0]
    command = _const(first)
    if command is None:
        return isinstance(first, ast.Attribute) and first.attr == "executable"  # sys.executable
    words = command.split()
    if isinstance(args[0], (ast.List, ast.Tuple)):
        words = [_const(e) or "" for e in args[0].elts]
    if not words:
        return False
    program = words[0]
    # Running the package's own build script: ./build.sh, sh autogen.sh (not sh -c "...")
    script = words[1] if program in SHELLS and len(words) > 1 else program
    if script.endswith(".sh") and not script.startswith(("/", "http")):
        return True
    return program.rsplit("/", 1)[-1] in BUILD_TOOLS


def _mixes_text(node) -> bool:
    return isinstance(node, (ast.JoinedStr, ast.BinOp)) or (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("format", "join"))


def _dangerous(name: str) -> bool:
    return (name in EXEC or name in SHELL or name.startswith(SHELL_PREFIXES)
            or name.startswith(NETWORK_PREFIXES) or name.startswith(DECODE_PREFIXES))


def _const_command(node) -> bool:
    if isinstance(node, (ast.List, ast.Tuple)):
        return bool(node.elts) and all(_const(e) is not None for e in node.elts)
    return _const(node) is not None


def _const_arg(call: ast.Call) -> str | None:
    return _const(call.args[0]) if call.args else None


def _reads_a_file(node) -> bool:
    """exec(open("pkg/version.py").read()) is a normal way to get a version.
    The file it reads is scanned in its own right (see analyse.py)."""
    return any(isinstance(n, ast.Call) and (
        (isinstance(n.func, ast.Name) and n.func.id == "open")
        or (isinstance(n.func, ast.Attribute) and n.func.attr in ("read", "read_text")))
        for n in ast.walk(node))


def _scan_unparsable(path, source, role) -> list[Finding]:
    found = check_text(source, path, install_time=role == "setup")
    hidden = r"\b(?:exec|eval)\s*\([^\n]{0,300}?(?:b64decode|decompress|fromhex|decrypt)"
    if re.search(hidden, source):
        found.append(Finding("exec-decoded", "decodes hidden code and runs it", path,
                             critical=role == "setup"))
    return found
