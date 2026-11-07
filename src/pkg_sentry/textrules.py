"""Patterns that mean the same thing in any language: where data is sent,
which files are worth stealing, and how malware hides or sticks around."""

import bisect
import ipaddress
import re

from .rules import Finding, snippet

# Services built for receiving data: no account needed, or a bot/webhook
# token is enough. Malware posts stolen data straight to these.
EXFIL = re.compile(
    r"discord(?:app)?\.com/api/webhooks/"
    r"|api\.telegram\.org/bot"
    r"|\bngrok(?:-free)?\.(?:io|app|dev)\b"
    r"|\bpipedream\.net\b|\bwebhook\.site\b|\brequestbin\.\w+|\bhookbin\.com\b|\bbeeceptor\.com\b"
    r"|\binteract\.sh\b|\boast\.(?:pro|live|site|online|fun|me)\b|burpcollaborator\.net"
    r"|\boastify\.com\b|\bdnslog\.cn\b|\bceye\.io\b|\bcanarytokens\.com\b",
    re.IGNORECASE,
)
# Anonymous file and paste hosts. Stealers upload archives here, but download
# tools and docs mention them too, so they count for less.
DROPS = re.compile(
    r"\btransfer\.sh\b|\bfile\.io\b|\bgofile\.io\b|\banonfiles\.com\b"
    r"|pastebin\.com/raw|\bpaste\.ee/r/|\brentry\.co\b",
    re.IGNORECASE,
)

SEP = r"[/\\\\]+"
# Stores no normal library has a reason to open: browsers, chat apps, wallets.
STOLEN_GOODS = re.compile(
    # Chrome/Edge profile files, as file names in a path or a string, not "local state" in prose
    r"(?<=[/\\\\'\"])(?:Login Data|Local State|Web Data)(?=['\"/\\\\]|$)"
    r"|Network" + SEP + r"Cookies\b|User Data" + SEP + r"Default" + SEP + r"Cookies\b"
    r"|\bcookies\.sqlite\b|\bkey4\.db\b|\blogins\.json\b"
    r"|discord(?:canary|ptb)?" + SEP + r"Local Storage|Local Storage" + SEP + r"leveldb"
    r"|Telegram Desktop" + SEP + r"tdata|\bwallet\.dat\b|\bExodus" + SEP + r"exodus\.wallet"
    r"|\bElectrum" + SEP + r"wallets|\bAtomic" + SEP + r"Local Storage"
    r"|nkbihfbeogaeaoehlefnkodbefgpgknn"  # MetaMask's extension id
    # /etc/shadow as a string in code, not a password library's docs about it
    r"|(?<=['\"])/etc/shadow(?=['\"])|login\.keychain-db"
)
# Credentials that plenty of honest tools read (the AWS SDK reads ~/.aws).
CREDENTIALS = re.compile(
    r"\.ssh" + SEP + r"id_(?:rsa|dsa|ecdsa|ed25519)\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b"
    r"|\.aws" + SEP + r"credentials\b|\.azure" + SEP + r"(?:accessTokens|msal_token_cache)"
    r"|\.config" + SEP + r"gcloud\b|\.docker" + SEP + r"config\.json\b|\.kube" + SEP + r"config\b",
    re.IGNORECASE,
)

POWERSHELL = re.compile(r"powershell|pwsh", re.IGNORECASE)
POWERSHELL_HIDING = re.compile(
    r"-w(?:indowstyle)?\s+h(?:idden)?\b|invoke-expression"
    r"|downloadstring|downloadfile|invoke-webrequest|frombase64string|-exec(?:utionpolicy)?\s+bypass",
    re.IGNORECASE,
)
# "iex" is also Elixir's shell, so it only counts right next to the PowerShell call.
POWERSHELL_IEX = re.compile(r"\biex\b", re.IGNORECASE)

PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n|;]{0,400}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|(?:curl|wget)\b[^\n;]{0,400}?(?:-o|-O|>)\s{0,8}[^\s;]{1,300}[;&\s]{1,8}"
    r"(?:chmod\s+\+?[0-7x]+|\./|sh |bash )"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,400}\|\s*iex\b"
    r"|certutil[^\n]{0,200}-urlcache|bitsadmin[^\n]{0,200}/transfer|mshta\s+https?:",
    re.IGNORECASE,
)

DECODE_TO_SHELL = re.compile(
    r"base64\s+(?:-d|--decode|-D)\b[^\n|]{0,200}\|\s*(?:ba|z|da)?sh\b"
    r"|frombase64string\([^\n]{0,2000}?\)\s*\|\s*iex",
    re.IGNORECASE,
)
SELF_UNINSTALL = re.compile(r"\bpip3?\s+(?:-\S+\s+){0,8}uninstall\b", re.IGNORECASE)

PERSISTENCE = re.compile(
    r"Start Menu[/\\\\]+Programs[/\\\\]+Startup|CurrentVersion[/\\\\]+Run(?:Once)?\b"
    r"|schtasks(?:\.exe)?\s+/create|\bcrontab\s+-|Library/LaunchAgents"
    r"|systemctl\s+--user\s+enable|\bat\.exe\b"
    r"|>>\s{0,8}['\"]?(?:~|\$HOME)?/?\.(?:bashrc|zshrc|bash_profile|profile)\b"
    r"|\.(?:bashrc|zshrc|bash_profile)['\"]\)?\s{0,8},\s{0,8}['\"]a",
    re.IGNORECASE,
)

URL_IP = re.compile(r"\b(?:https?|tcp|udp|wss?)://(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)


def public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_global


# Plain substrings each pattern needs. Checking these first is far cheaper
# than running the regexes over every line of a big library.
GATES = {
    "exfil": ("discord", "telegram", "ngrok", "pipedream", "webhook", "requestbin", "hookbin",
              "beeceptor", "interact.sh", "oast", "burpcollaborator", "dnslog", "ceye", "canary",
              "transfer.sh", "file.io", "gofile", "anonfiles", "pastebin", "paste.ee", "rentry"),
    "loot": ("login data", "local state", "web data", "cookies", "key4.db", "local storage",
             "tdata", "wallet", "electrum", "nkbihfbeogaeaoehlefnkodbefgpgknn", "/etc/shadow",
             "keychain"),
    "creds": (".ssh", ".git-credentials", ".npmrc", ".pypirc", ".aws", ".azure", "gcloud",
              ".docker", ".kube"),
    "powershell": ("powershell", "pwsh"),
    "pipe": ("curl", "wget", "iwr", "irm", "invoke-web", "invoke-rest", "certutil", "bitsadmin",
             "mshta"),
    "decode": ("base64", "frombase64string"),
    "uninstall": ("uninstall",),
    "persist": ("startup", "currentversion", "schtasks", "crontab", "launchagents",
                "systemctl", "at.exe", "bashrc", "zshrc", "bash_profile", ".profile"),
    "ip": ("://",),
}


# One rule firing thousands of times in a file says nothing new, and a file
# built to do that would slow the scan down.
PER_RULE = 20


BIG_TEXT = 200_000
WINDOW = 600


def _windows(lower: str, words) -> list[tuple[int, int]]:
    spans = []
    for word in words:
        at = lower.find(word)
        while at >= 0 and len(spans) < 20_000:
            spans.append((max(0, at - WINDOW), at + len(word) + WINDOW))
            at = lower.find(word, at + len(word))
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def _near(pattern, text: str, windows):
    for start, end in windows:
        yield from pattern.finditer(text, start, end)


def line_finder(text: str):
    """offset -> line number, without recounting newlines for every match."""
    starts: list[int] = []

    def line_of(pos: int) -> int:
        if not starts:
            starts.append(0)
            starts.extend(m.end() for m in re.finditer("\n", text))
        return bisect.bisect_right(starts, pos)

    return line_of


def check_text(text: str, path: str, line_of=None, install_time: bool = False) -> list[Finding]:
    """String-level checks. `line_of(offset)` maps a match back to a line."""
    line_of = line_of or line_finder(text)
    lower = text.lower()
    gate = {name: any(word in lower for word in words) for name, words in GATES.items()}
    found = []
    counts: dict[str, int] = {}

    def scan(pattern, gate_name):
        if len(text) < BIG_TEXT:
            return pattern.finditer(text)
        # Megabyte bundles: only look near the words the pattern needs.
        return _near(pattern, text, _windows(lower, GATES[gate_name]))

    def add(rule, message, match, critical=False, points=None):
        counts[rule] = counts.get(rule, 0) + 1
        if counts[rule] > PER_RULE:
            return
        start = max(0, match.start() - 30)
        found.append(Finding(rule, message, path, line_of(match.start()),
                             snippet(text[start: match.end() + 30]), critical, points))

    # At runtime these also turn up in honest code (install instructions in an
    # error message, a tool that drives PowerShell), so they count for less.
    weaker = None if install_time else 15
    weaker_powershell = None if install_time else 20

    if gate["exfil"]:
        for m in scan(EXFIL, "exfil"):
            add("exfil-endpoint", f"sends data to {m.group(0).split('/')[0]}", m,
                critical=install_time)
        for m in scan(DROPS, "exfil"):
            add("exfil-endpoint", f"uploads to {m.group(0).split('/')[0]}", m,
                critical=install_time, points=weaker)
    if gate["loot"]:
        for m in scan(STOLEN_GOODS, "loot"):
            add("secrets", f"reads {m.group(0)}", m)
    if gate["creds"]:
        for m in scan(CREDENTIALS, "creds"):
            add("credentials", f"reads {m.group(0)}", m)
    if gate["powershell"]:
        # The command is often built a few lines above the call, so look at the
        # whole file for the hiding/downloading part.
        hiding = POWERSHELL_HIDING.search(text)
        for m in scan(POWERSHELL, "powershell"):
            if hiding or POWERSHELL_IEX.search(text, m.start(), m.start() + 300):
                add("hidden-powershell", "starts PowerShell hidden or with encoded commands", m,
                    critical=install_time, points=weaker_powershell)
    if gate["pipe"]:
        for m in scan(PIPE_TO_SHELL, "pipe"):
            add("download-exec", "downloads a script or program and runs it", m,
                critical=install_time, points=weaker)
    if gate["decode"]:
        for m in scan(DECODE_TO_SHELL, "decode"):
            add("exec-decoded", "decodes a hidden command and runs it", m, critical=install_time)
    if gate["uninstall"] and install_time:
        for m in scan(SELF_UNINSTALL, "uninstall"):
            add("hides-traces", "uninstalls a package while installing, to cover its tracks", m)
    if gate["persist"]:
        for m in scan(PERSISTENCE, "persist"):
            add("persistence", "sets itself up to start again later", m)
    if gate["ip"]:
        for m in scan(URL_IP, "ip"):
            if public_ip(m.group(1)):
                add("raw-ip-url", f"talks to the bare IP address {m.group(1)}", m)
    return found


def binary_kind(data: bytes) -> str | None:
    if data[:2] == b"MZ" and len(data) > 64:
        return "a Windows program"
    if data[:4] == b"\x7fELF":
        return "a Linux program"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "a macOS program"
    return None
