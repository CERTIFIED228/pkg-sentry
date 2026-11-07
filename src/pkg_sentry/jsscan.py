"""Static checks for npm packages: package.json install hooks and JS files.

JavaScript isn't parsed here, it's searched. Comments are blanked out first
(keeping line numbers) so a README snippet in a comment doesn't count, and
calls are only matched next to the module they come from.
"""

import json
import re

from .rules import Finding, snippet
from .textrules import check_text

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")
HOOK_RUNS_FILE = re.compile(
    r"\bnode\s+(?:-e\s+)?['\"]?([\w./@-]+\.(?:c|m)?js)\b|\bnode\s+([\w./-]+)"
)
HOOK_SHELL = re.compile(
    r"\b(?:curl|wget|nc|ncat|bash\s+-c|sh\s+-c|powershell|pwsh|cmd(?:\.exe)?\s+/c|python3?\s+-c)\b"
    r"|/dev/tcp/|node\s+-e\b",
    re.IGNORECASE,
)
# Install hooks that are part of how a lot of packages build.
HARMLESS_HOOKS = re.compile(
    r"^(?:node-gyp(?:-build)?\s+rebuild|node-gyp-build|prebuild-install(?:\s+\|\|\s+node-gyp\s+rebuild)?"
    r"|husky(?:\s+install)?|patch-package|npm run build|tsc|ngcc|is-ci\s*\|\|\s*husky install)$"
)

CHILD_PROCESS = re.compile(
    r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)|from\s+['\"](?:node:)?child_process['\"]"
)
SHELL_CALL = re.compile(r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(")
NETWORK = re.compile(
    r"require\(\s*['\"](?:node:)?(?:https?|net|dgram|dns|tls|axios|node-fetch|request|got)['\"]\s*\)"
    r"|from\s+['\"](?:node:)?(?:https?|net|dns|axios|node-fetch|got)['\"]"
    r"|\bfetch\s*\(\s*['\"`]https?:|\bnew\s+WebSocket\s*\(|\bXMLHttpRequest\b"
)
EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"`]|\bvm\.run\w*\s*\(")
DECODE = re.compile(
    r"Buffer\.from\([^)]*['\"](?:base64|hex)['\"]|\batob\s*\(|String\.fromCharCode\s*\("
    r"|decodeURIComponent\s*\(\s*escape|createDecipheriv\s*\(",
)
ENV_DUMP = re.compile(
    r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)"
    r"|\.\.\.process\.env\b|:\s*process\.env\s*[,}]|=\s*process\.env\s*;"
)
RECON = re.compile(r"\bos\.(?:hostname|userInfo|networkInterfaces|homedir)\s*\(")
RUNNABLE = re.compile(
    r"\.(?:exe|sh|ps1|bat|cmd|vbs|scr)['\"`]|chmod(?:Sync)?\s*\(|detached\s*:\s*true"
)
OBFUSCATOR = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
OBFUSCATOR_SIGNS = re.compile(
    r"while\s*\(\s*!!\[\]\s*\)|\['push'\]\(\s*\w+\['shift'\]\(\)\s*\)|\[\]\[\(!\[\]\+\[\]\)"
)
COMMENT = re.compile(r"/\*.*?\*/|(?<![:'\"\\])//[^\n]*", re.DOTALL)


def scan_package_json(path: str, text: str) -> tuple[list[Finding], set[str]]:
    """Findings, plus the files the install hooks run (they get install-time weight)."""
    try:
        meta = json.loads(text)
    except ValueError:
        return [], set()
    if not isinstance(meta, dict):
        return [], set()
    scripts = meta.get("scripts") if isinstance(meta.get("scripts"), dict) else {}
    findings, run_files = [], set()
    for hook in INSTALL_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        if hook == "prepare" or HARMLESS_HOOKS.match(command.strip()):
            continue
        line = _line_of(text, f'"{hook}"')
        findings.append(Finding("install-script", f"runs '{command}' on install", path, line,
                                snippet(command)))
        for m in HOOK_RUNS_FILE.finditer(command):
            target = (m.group(1) or m.group(2)).lstrip("./")
            run_files |= {target, f"{target}.js", f"{target}/index.js"}
        if HOOK_SHELL.search(command):
            findings.append(Finding("shell-at-install", "the install script runs shell commands",
                                    path, line, snippet(command)))
        findings += check_text(command, path, lambda _, line=line: line, install_time=True)
    main = meta.get("main")
    if isinstance(main, str):
        run_files.add(f"main:{main.lstrip('./')}")
    return findings, run_files


def scan_js(path: str, source: str, install_time: bool = False) -> list[Finding]:
    code = COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), source)
    found: list[Finding] = []
    when = "during install"

    def add(rule, message, match, critical=False, points=None):
        line = code.count("\n", 0, match.start()) + 1
        found.append(Finding(rule, message, path, line, snippet(code[match.start():
                     match.start() + 120]), critical, points))

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
            add("download-exec", "downloads a program and starts it", m, critical=install_time)
        if m := ENV_DUMP.search(code):
            add("env-dump", "collects all environment variables and sends them out", m)
        if m := RECON.search(code):
            add("recon", "collects details about the machine and sends them", m)

    hex_names = len(set(OBFUSCATOR.findall(code)))
    if hex_names >= 20 or OBFUSCATOR_SIGNS.search(code):
        m = OBFUSCATOR.search(code) or OBFUSCATOR_SIGNS.search(code)
        add("obfuscated", "deliberately scrambled code (javascript-obfuscator style)", m)

    found += check_text(code, path, install_time=install_time)
    return found


def _line_of(text: str, needle: str) -> int | None:
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else None
