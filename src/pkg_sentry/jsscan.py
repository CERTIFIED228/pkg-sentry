"""Static checks for npm packages: package.json install hooks and JS files.

JavaScript isn't parsed here, it's searched. Comments are blanked out first
(keeping offsets, so line numbers still match) by a small scanner that knows
about strings, template literals and regex literals, so a "/*" inside a string
can't be used to hide the code after it.
"""

import json
import re

from .rules import Finding, snippet
from .textrules import check_text, line_finder

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")
HOOK_SHELL = re.compile(
    r"\b(?:curl|wget|nc|ncat|bash\s+-c|sh\s+-c|powershell|pwsh|cmd(?:\.exe)?\s+/c|python3?\s+-c)\b"
    r"|/dev/tcp/",
    re.IGNORECASE,
)
# Install hooks that are part of how a lot of packages build.
HARMLESS_HOOKS = re.compile(
    r"^(?:node-gyp(?:-build)?(?:\s+rebuild)?|prebuild-install|husky(?:\s+install)?|patch-package"
    r"|tsc|ngcc|is-ci|exit 0|echo\b[^|;&`$]*)$"
)
# `npm run build`, `yarn build`, `pnpm run x`: the real command is in scripts.
RUNNER = re.compile(r"^(?:npm\s+(?:run|run-script)|yarn(?:\s+run)?|pnpm(?:\s+run)?)\s+([\w:.@/-]+)")
NODE_FILE_FLAGS = {"-r", "--require", "--import", "--loader", "--experimental-loader"}
NODE_CODE_FLAGS = {"-e", "--eval", "-p", "--print"}
REQUIRE = re.compile(
    r"\brequire\s*\(\s*(['\"`])([^'\"`\n]{1,200})\1\s*\)"
    r"|\bimport\s*\(\s*(['\"`])([^'\"`\n]{1,200})\3\s*\)"
    r"|\bfrom\s+(['\"])([^'\"\n]{1,200})\5"
)


def _module(names: str) -> str:
    return (r"(?:require|import)\s*\(\s*['\"`](?:node:)?(?:" + names + r")['\"`]\s*\)"
            r"|from\s+['\"](?:node:)?(?:" + names + r")['\"]")


CHILD_PROCESS = re.compile(_module("child_process"))
SHELL_CALL = re.compile(r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(")
NETWORK = re.compile(
    _module("https?|net|dgram|dns|tls|axios|node-fetch|request|got|undici")
    + r"|\bfetch\s*\(\s*['\"`]https?:|\bnew\s+WebSocket\s*\(|\bXMLHttpRequest\b"
)
EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"`]|\bvm\.run\w*\s*\(")
DECODE = re.compile(
    r"Buffer\.from\([^)]{0,300}['\"](?:base64|hex)['\"]|\batob\s*\(|String\.fromCharCode\s*\("
    r"|decodeURIComponent\s*\(\s*escape|createDecipheriv\s*\(",
)
# The whole environment serialised. `env: process.env` for a child process is normal.
ENV_DUMP = re.compile(
    r"(?:JSON|querystring|qs)\.stringify\(\s*process\.env\s*\)"
    r"|JSON\.stringify\(\s*\{[^;]{0,500}?:\s*process\.env\s*[,}]"
)
RECON = re.compile(r"\bos\.(?:hostname|userInfo|networkInterfaces|homedir)\s*\(")
RUNNABLE = re.compile(
    r"\.(?:exe|sh|ps1|bat|cmd|vbs|scr)['\"`]|chmod(?:Sync)?\s*\(|detached\s*:\s*true"
)
# Spam and worms republish themselves: rewrite package.json, then npm publish.
SELF_PUBLISH = re.compile(r"['\"`]npm\s+publish\b")
WRITES_PACKAGE_JSON = re.compile(r"writeFileSync\(\s*['\"`][./]*package\.json")
OBFUSCATOR = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
OBFUSCATOR_SIGNS = re.compile(
    r"while\s*\(\s*!!\[\]\s*\)|\['push'\]\(\s*\w+\['shift'\]\(\)\s*\)|\[\]\[\(!\[\]\+\[\]\)"
)
# node-gyp runs `<!(command)` while building a native addon during install.
GYP_COMMAND = re.compile(r"<!@?\(")
GYP_HARMLESS = re.compile(r"^node\s+-[pe]\s+['\"]?require\(['\"][\w@/.-]+['\"]\)[\w.]*['\"]?$")
# Characters after which a "/" starts a regex literal rather than a division.
REGEX_AFTER = set("(,=:[!&|?{};+-*%<>~^") | {""}


def strip_comments(source: str) -> str:
    """Comments replaced by spaces (newlines kept), strings and regexes left alone."""
    out = list(source)
    i, n = 0, len(source)
    last = ""  # last significant character outside comments
    while i < n:
        c = source[i]
        if c in "'\"`":
            i = _skip_string(source, i, c)
            last = c
            continue
        if c == "/" and i + 1 < n:
            nxt = source[i + 1]
            if nxt == "/":
                end = source.find("\n", i)
                end = n if end < 0 else end
                out[i:end] = " " * (end - i)
                i = end
                continue
            if nxt == "*":
                end = source.find("*/", i + 2)
                end = n if end < 0 else end + 2
                out[i:end] = [ch if ch == "\n" else " " for ch in source[i:end]]
                i = end
                continue
            if last in REGEX_AFTER or _after_keyword(source, i):
                i = _skip_regex(source, i)
                last = "/"
                continue
        if not c.isspace():
            last = c
        i += 1
    return "".join(out)


def _skip_string(source: str, i: int, quote: str) -> int:
    i += 1
    while i < len(source):
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == quote or (c == "\n" and quote != "`"):
            return i + 1
        i += 1
    return i


def _skip_regex(source: str, i: int) -> int:
    i += 1
    in_class = False
    while i < len(source):
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "\n":
            return i
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            return i + 1
        i += 1
    return i


def _after_keyword(source: str, i: int) -> bool:
    before = source[max(0, i - 12):i].rstrip()
    return bool(re.search(r"\b(?:return|typeof|case|in|of|delete|void|throw|new)$", before))


def expand_hook(command: str, scripts: dict, depth: int = 0) -> list[str]:
    """The commands a hook really runs, following `npm run x` into scripts."""
    leaves = []
    for part in re.split(r"\s*(?:&&|\|\||;)\s*", command.strip()):
        m = RUNNER.match(part)
        target = scripts.get(m.group(1)) if m else None
        if isinstance(target, str) and depth < 5:
            leaves += expand_hook(target, scripts, depth + 1)
        elif part:
            leaves.append(part)
    return leaves


def node_files(command: str) -> set[str]:
    """Files a `node ...` command (or code inside it) loads."""
    tokens = [t.strip("'\"") for t in re.findall(r"'[^']*'|\"[^\"]*\"|\S+", command)]
    found: set[str] = set()
    if tokens and tokens[0].rsplit("/", 1)[-1] in ("node", "nodejs"):
        rest = iter(tokens[1:])
        for token in rest:
            if token in NODE_FILE_FLAGS:
                found.add(next(rest, ""))
            elif token in NODE_CODE_FLAGS:
                next(rest, "")
            elif token.startswith("-"):
                continue
            else:
                found.add(token)
                break
    found |= {spec for spec in local_requires(command)}
    return {_candidate for f in found if f for _candidate in _with_extensions(f)}


def local_requires(source: str) -> set[str]:
    """Relative module specifiers a file loads: ./x, ../lib/y."""
    found = set()
    for m in REQUIRE.finditer(source):
        spec = m.group(2) or m.group(4) or m.group(6)
        if spec and spec.startswith((".", "/")):
            found.add(spec)
    return found


def _with_extensions(path: str) -> set[str]:
    path = path.removeprefix("./")
    return {path, f"{path}.js", f"{path}.cjs", f"{path}.mjs", f"{path}/index.js"}


def scan_hooks(path: str, scripts: dict, text: str = "") -> tuple[list[Finding], set[str]]:
    """Install hooks from a package.json `scripts` object."""
    findings, run_files = [], set()
    lines = line_finder(text) if text else None
    for hook in INSTALL_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip() or hook == "prepare":
            continue
        leaves = expand_hook(command, scripts)
        if all(HARMLESS_HOOKS.match(leaf) for leaf in leaves):
            continue
        line = None
        if lines and (m := re.search(r'"' + hook + r'"\s*:', text)):
            line = lines(m.start())
        findings.append(Finding("install-script", f"runs '{command}' on install", path, line,
                                snippet(command)))
        for leaf in leaves:
            run_files |= node_files(leaf)
            if HOOK_SHELL.search(leaf):
                findings.append(Finding("shell-at-install",
                                        "the install script runs shell commands",
                                        path, line, snippet(leaf)))
            findings += check_text(leaf, path, lambda _, line=line: line, install_time=True)
    return findings, run_files


def scan_package_json(path: str, text: str) -> tuple[list[Finding], set[str]]:
    """Findings, plus the files the install hooks run (they get install-time weight)."""
    try:
        meta = json.loads(text)
    except ValueError:
        return [], set()
    if not isinstance(meta, dict) or not isinstance(meta.get("scripts"), dict):
        return [], set()
    return scan_hooks(path, meta["scripts"], text)


def scan_gyp(path: str, text: str) -> list[Finding]:
    """node-gyp runs commands in binding.gyp automatically during npm install."""
    findings = []
    lines = line_finder(text)
    for m in GYP_COMMAND.finditer(text):
        command = _balanced(text, m.end()).replace('\\"', '"').strip()
        if GYP_HARMLESS.match(command):
            continue
        line = lines(m.start())
        findings.append(Finding("shell-at-install", f"binding.gyp runs '{command}' during install",
                                path, line, snippet(command)))
        findings += check_text(command, path, lambda _, line=line: line, install_time=True)
    return findings


def _balanced(text: str, start: int, limit: int = 500) -> str:
    """Text up to the bracket that closes the one just before `start`."""
    depth = 1
    for i in range(start, min(len(text), start + limit)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start:i]
        elif text[i] == "\n":
            break
    return text[start:start + limit]


def scan_js(path: str, source: str, install_time: bool = False) -> list[Finding]:
    code = strip_comments(source)
    lines = line_finder(code)
    found: list[Finding] = []
    when = "during install"

    def add(rule, message, match, critical=False, points=None):
        found.append(Finding(rule, message, path, lines(match.start()),
                             snippet(code[match.start():match.start() + 120]), critical, points))

    has_child = CHILD_PROCESS.search(code)
    has_network = NETWORK.search(code)

    if has_child:
        call = SHELL_CALL.search(code, has_child.end()) or has_child
        if install_time:
            add("shell-at-install", f"runs commands {when}", call)
        else:
            add("shell", "runs shell commands", call)
    if has_network and install_time:
        add("network-at-install", f"connects to the internet {when}", has_network)

    for m in EVAL.finditer(code):
        window = code[max(0, m.start() - 400): m.end() + 400]
        if DECODE.search(window):
            add("exec-decoded", "decodes hidden code and runs it", m, critical=install_time)
            break
        if install_time and not re.match(r"eval\s*\(\s*['\"`]", code[m.start():]):
            add("exec-dynamic", f"runs code built at runtime {when}", m)
            break

    if has_network:
        if has_child and (m := RUNNABLE.search(code)):
            # Also how esbuild and friends fetch their binary, so it's behaviour,
            # not evidence like the shell one-liners in textrules.
            add("fetch-and-run", "downloads files and starts programs", m)
        if m := ENV_DUMP.search(code):
            add("env-dump", "collects all environment variables and sends them out", m)
        if m := RECON.search(code):
            add("recon", "collects details about the machine and sends them", m)

    if has_child and (m := SELF_PUBLISH.search(code)) and WRITES_PACKAGE_JSON.search(code):
        add("self-publish", "rewrites package.json and publishes to npm by itself", m)

    hex_names = len(set(OBFUSCATOR.findall(code)))
    if hex_names >= 20 or OBFUSCATOR_SIGNS.search(code):
        m = OBFUSCATOR.search(code) or OBFUSCATOR_SIGNS.search(code)
        add("obfuscated", "deliberately scrambled code (javascript-obfuscator style)", m)

    # The string checks also look at the raw source: if the comment scanner is
    # ever fooled, a webhook or `curl | sh` still can't disappear with it.
    seen = {(f.rule, f.line) for f in found}
    for f in check_text(code, path, lines, install_time) + check_text(
            source, path, line_finder(source), install_time):
        if (f.rule, f.line) not in seen:
            seen.add((f.rule, f.line))
            found.append(f)
    return found
