"""Patterns that mean the same thing in any language: where data is sent,
which files are worth stealing, and how malware hides or sticks around."""

import ipaddress
import re

from .rules import Finding, snippet

# Services that are handy for receiving stolen data: no account needed,
# or a bot/webhook token is enough.
EXFIL = re.compile(
    r"discord(?:app)?\.com/api/webhooks/"
    r"|api\.telegram\.org/bot"
    r"|\bngrok(?:-free)?\.(?:io|app|dev)\b"
    r"|\bpipedream\.net\b|\bwebhook\.site\b|\brequestbin\.\w+|\bhookbin\.com\b|\bbeeceptor\.com\b"
    r"|\binteract\.sh\b|\boast\.(?:pro|live|site|online|fun|me)\b|burpcollaborator\.net|\boastify\.com\b"
    r"|\bdnslog\.cn\b|\bceye\.io\b|\bcanarytokens\.com\b"
    r"|\btransfer\.sh\b|\bfile\.io\b|\bgofile\.io\b|\banonfiles\.com\b"
    r"|pastebin\.com/raw|\bpaste\.ee/r/|\brentry\.co\b",
    re.IGNORECASE,
)

SEP = r"[/\\\\]+"
# Stores no normal library has a reason to open: browsers, chat apps, wallets.
STOLEN_GOODS = re.compile(
    r"\bLogin Data\b|\bLocal State\b|\bWeb Data\b|Network" + SEP + r"Cookies\b"
    r"|User Data" + SEP + r"Default" + SEP + r"Cookies\b|\bcookies\.sqlite\b|\bkey4\.db\b"
    r"|discord(?:canary|ptb)?" + SEP + r"Local Storage|Local Storage" + SEP + r"leveldb"
    r"|Telegram Desktop" + SEP + r"tdata|\bwallet\.dat\b|\bExodus" + SEP + r"exodus\.wallet"
    r"|\bElectrum" + SEP + r"wallets|\bAtomic" + SEP + r"Local Storage"
    r"|nkbihfbeogaeaoehlefnkodbefgpgknn"  # MetaMask's extension id
    r"|/etc/shadow\b|login\.keychain|keychain-db",
    re.IGNORECASE,
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
    r"\s-(?:e|en|enc|encodedcommand)\s|-w(?:indowstyle)?\s+h(?:idden)?\b|\biex\b|invoke-expression"
    r"|downloadstring|downloadfile|invoke-webrequest|frombase64string|-exec(?:utionpolicy)?\s+bypass",
    re.IGNORECASE,
)

PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|(?:curl|wget)\b[^\n;]*(?:-o|-O|>)\s*[^\s;]+[;&\s]+(?:chmod\s+\+?[0-7x]+|\./|sh |bash )"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*iex\b"
    r"|certutil[^\n]*-urlcache|bitsadmin[^\n]*/transfer|mshta\s+https?:",
    re.IGNORECASE,
)

PERSISTENCE = re.compile(
    r"Start Menu[/\\\\]+Programs[/\\\\]+Startup|CurrentVersion[/\\\\]+Run(?:Once)?\b"
    r"|schtasks(?:\.exe)?\s+/create|\bcrontab\s+-|/etc/cron\.|Library/LaunchAgents"
    r"|systemctl\s+--user\s+enable|\bat\.exe\b"
    r"|>>\s*['\"]?(?:~|\$HOME)?/?\.(?:bashrc|zshrc|bash_profile|profile)\b"
    r"|\.(?:bashrc|zshrc|bash_profile)['\"]\)?\s*,\s*['\"]a",
    re.IGNORECASE,
)

URL_IP = re.compile(r"\b(?:https?|tcp|udp|wss?)://(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE)


def public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_global


def check_text(text: str, path: str, line_of=None, install_time: bool = False) -> list[Finding]:
    """String-level checks. `line_of(offset)` maps a match back to a line."""
    line_of = line_of or (lambda pos: text.count("\n", 0, pos) + 1)
    found = []

    def add(rule, message, match, critical=False):
        start = max(0, match.start() - 30)
        found.append(Finding(rule, message, path, line_of(match.start()),
                             snippet(text[start: match.end() + 30]), critical))

    for m in EXFIL.finditer(text):
        add("exfil-endpoint", f"sends data to {m.group(0).split('/')[0]}", m,
            critical=install_time)
    for m in STOLEN_GOODS.finditer(text):
        add("secrets", f"reads {m.group(0)}", m)
    for m in CREDENTIALS.finditer(text):
        add("credentials", f"reads {m.group(0)}", m)
    for m in POWERSHELL.finditer(text):
        window = text[m.start(): m.start() + 300]
        if POWERSHELL_HIDING.search(window):
            add("hidden-powershell", "starts PowerShell hidden or with encoded commands", m,
                critical=install_time)
    for m in PIPE_TO_SHELL.finditer(text):
        add("download-exec", "downloads a script or program and runs it", m,
            critical=install_time)
    for m in PERSISTENCE.finditer(text):
        add("persistence", "sets itself up to start again later", m)
    for m in URL_IP.finditer(text):
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
