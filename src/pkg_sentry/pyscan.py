"""Static checks for Python files.

The file is parsed with `ast`, never imported or run. Import aliases are
followed (`import base64 as b`, `__import__("base64")`) so renaming a module
doesn't hide a call. Files that don't parse (Python 2, or broken on purpose)
still get the text checks.
"""

import ast
import re
import warnings

from .rules import Finding, snippet
from .textrules import check_text

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
DUMPERS = {"dict", "str", "repr", "json.dumps", "urllib.parse.urlencode", "list"}
# Commands people run from setup.py while building, not to attack anyone.
BUILD_TOOLS = {"git", "cmake", "make", "gcc", "cc", "g++", "clang", "pkg-config", "cython",
               "nvcc", "xcrun", "hipcc", "ninja", "meson", "cargo", "rustc", "swig", "uname",
               "nproc", "which", "where", "lsb_release", "sw_vers", "python", "python3"}
RUNNABLE = re.compile(r"\.(?:exe|bat|cmd|ps1|vbs|scr|msi|sh)\b", re.IGNORECASE)
OBFUSCATOR = re.compile(r"__pyarmor__|pyarmor_runtime|PyObfuscator|BlankOBF|pyobfuscate")
# Names obfuscators generate: IlIlIlIl, OO0O0O0O, _0x1f2a, __________1
SCRAMBLED_NAME = re.compile(r"^(?:[Il]{6,}|[O0]{6,}|_0x[0-9a-f]{3,}|_{4,}\d*)$")
SCRAMBLED_WORD = re.compile(r"\b(?:[Il]{6,}|O[O0]{5,}|_0x[0-9a-f]{3,})\b")
# Cheap first pass: a file with none of these can't trigger any AST rule, so
# the parse is skipped. Most files in a big library land here.
WORTH_PARSING = re.compile(
    r"\b(?:exec|eval|compile|subprocess|system|popen|startfile|spawn|socket|urllib|urlopen|requests"
    r"|httpx|http\.client|aiohttp|smtplib|ftplib|websocket|pycurl|wget|telebot|discord_webhook"
    r"|__import__|import_module|environ|getuser|gethostname|getlogin|getnode|uname|setup|pty"
    r"|chr|dns)\b"
)
EXEC_WORDS = re.compile(r"\b(?:exec|eval|compile)\b")
BLOB = re.compile(r"^[A-Za-z0-9+/=\s]{2000,}$|^[0-9a-fA-F\s]{2000,}$")


def scan_python(path: str, source: str, role: str = "runtime") -> list[Finding]:
    """role: "setup" (everything runs at install), "import" (module-level
    code runs when imported) or "runtime"."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _scan_unparsable(path, source, role)
    visitor = _Visitor(path, source, role)
    try:
        visitor.visit(tree)
    except RecursionError:
        # Absurdly deep code. Don't let it crash the scan (that alone would be
        # a way to hide a payload); fall back to the text checks.
        return _scan_unparsable(path, source, role)
    return visitor.finish()


def local_imports(source: str) -> set[str]:
    """Top-level module names a setup.py imports (from main import run -> "main")."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    return names


class _Visitor(ast.NodeVisitor):
    def __init__(self, path, source, role):
        self.path, self.source, self.role = path, source, role
        self.aliases: dict[str, str] = {}
        self.decoded_names: set[str] = set()
        self.network_names: set[str] = set()
        self.depth = 0
        self.findings: list[Finding] = []
        self.calls: list[tuple[str, ast.Call, bool]] = []
        self.env_dumps: list[ast.AST] = []
        self.scrambled: set[str] = set()
        # Decoded/downloaded variables only matter if something execs them.
        self.track_values = bool(EXEC_WORDS.search(source))

    # -- bookkeeping ---------------------------------------------------------

    @property
    def install_time(self) -> bool:
        return self.role == "setup" or (self.role == "import" and self.depth == 0)

    def visit_FunctionDef(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_AsyncFunctionDef = visit_Lambda = visit_FunctionDef

    def visit_ClassDef(self, node):
        # Class bodies run at import, so they don't count as nesting.
        self.generic_visit(node)

    def visit_If(self, node):
        # `if __name__ == "__main__":` only runs when the file is run directly.
        test = node.test
        is_main = (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                   and test.left.id == "__name__"
                   and any(_const(c) == "__main__" for c in test.comparators))
        if not is_main:
            return self.generic_visit(node)
        self.visit(test)
        self.depth += 1
        for child in node.body:
            self.visit(child)
        self.depth -= 1
        for child in node.orelse:
            self.visit(child)

    def visit_Name(self, node):
        if SCRAMBLED_NAME.match(node.id):
            self.scrambled.add(node.id)

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def visit_Assign(self, node):
        self.generic_visit(node)
        value = node.value
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not targets or isinstance(value, (ast.Constant, ast.Name, ast.Attribute)):
            return
        if self.track_values and self._contains(value, self._is_decode):
            self.decoded_names.update(targets)
        if self.track_values and self._contains(value, self._is_network):
            self.network_names.update(targets)
        name = self.name_of(value) if isinstance(value, ast.Call) else None
        if name and name.startswith(("importlib.import_module", "__import__")):
            module = _const_arg(value)
            if module:
                self.aliases.update({t: module for t in targets})

    def visit_Call(self, node):
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
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) >= 2000:
            if BLOB.match(node.value):
                self.add("obfuscated", "carries a large encoded blob", node, points=10)

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
        if isinstance(node, ast.Name):
            return node.id in self.decoded_names
        if not isinstance(node, ast.Call):
            return False
        name = self.name_of(node.func) or ""
        if name.startswith(DECODE_PREFIXES):
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in DECODE_METHODS:
            return True
        # ''.join(chr(x) for x in [...]) and bytes([...]).decode()
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "join":
            return any(isinstance(n, ast.Call) and self.name_of(n.func) == "chr"
                       for n in ast.walk(node))
        if isinstance(func, ast.Attribute) and func.attr == "decode":
            return self._contains(func.value, lambda n: isinstance(n, ast.Call) and
                                  self.name_of(n.func) in ("bytes", "bytearray"))
        return False

    def _is_network(self, node) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.network_names
        if not isinstance(node, ast.Call):
            return False
        name = self.name_of(node.func) or ""
        return name.startswith(NETWORK_PREFIXES)

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

        if name in SHELL or name.startswith(SHELL_PREFIXES):
            if self.install_time and not _build_tool(args):
                self.add("shell-at-install", f"runs commands {when}", node)
            else:
                self.add("shell", "runs shell commands", node)
            strings = [_const(n) or "" for a in args for n in ast.walk(a)]
            if name == "os.startfile" or any(RUNNABLE.search(text) for text in strings):
                self.calls.append(("runs-a-program", node, self.install_time))

        if name.startswith(NETWORK_PREFIXES) and self.install_time:
            self.add("network-at-install", f"connects to the internet {when}", node)

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
        has_network = any(n.startswith(NETWORK_PREFIXES) for n in names)

        if has_network:
            for name, node, install_time in self.calls:
                if name == "runs-a-program":
                    self.add("download-exec", "downloads a program and starts it", node,
                             critical=install_time)
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
                                         self.path, self.source.count("\n", 0, m.start()) + 1,
                                         snippet(m.group(0))))
        elif len(self.scrambled) >= 5:
            names = ", ".join(sorted(self.scrambled)[:3])
            self.findings.append(Finding("obfuscated", f"deliberately scrambled names ({names}...)",
                                         self.path))

        self.findings += check_text(self.source, self.path, install_time=self.role == "setup")
        return self.findings


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
    program = command.split()[0] if command.split() else ""
    return program.rsplit("/", 1)[-1] in BUILD_TOOLS


def _const_arg(call: ast.Call) -> str | None:
    return _const(call.args[0]) if call.args else None


def _reads_a_file(node) -> bool:
    """exec(open("pkg/version.py").read()) is a normal way to get a version."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("read", "read_text", "read_bytes"):
            return True
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"
               for n in ast.walk(node))


def _text_only(path, source, role) -> list[Finding]:
    found = check_text(source, path, install_time=role == "setup")
    m = OBFUSCATOR.search(source)
    scrambled = set(SCRAMBLED_WORD.findall(source))
    if m:
        found.append(Finding("obfuscated", "deliberately scrambled code", path,
                             source.count("\n", 0, m.start()) + 1, snippet(m.group(0))))
    elif len(scrambled) >= 5:
        names = ", ".join(sorted(scrambled)[:3])
        found.append(Finding("obfuscated", f"deliberately scrambled names ({names}...)", path))
    return found


def _scan_unparsable(path, source, role) -> list[Finding]:
    found = check_text(source, path, install_time=role == "setup")
    if re.search(r"\b(?:exec|eval)\s*\([^\n]*(?:b64decode|decompress|fromhex|decrypt)", source):
        found.append(Finding("exec-decoded", "decodes hidden code and runs it", path,
                             critical=role == "setup"))
    return found
