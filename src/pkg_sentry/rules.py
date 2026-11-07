"""Findings, how many points each kind is worth, and how they add up."""

from dataclasses import dataclass, field

# rule id -> (points, what it means). Points were tuned on the older half of
# the malware samples and on popular packages (see scripts/benchmark.py).
RULES = {
    # registry and name
    "known-malware": (100, "listed as malware"),
    "not-found": (50, "doesn't exist, so anyone could register it"),
    "typosquat": (35, "name is a near-copy of a popular package"),
    "very-new": (20, "first published in the last week"),
    "new": (12, "first published in the last month"),
    "revived": (15, "new release after more than a year of silence"),
    "confusion-version": (25, "huge version number, a dependency-confusion trick"),
    "no-source": (8, "no link to source code"),
    "install-script": (15, "runs a script when installed"),
    # code that runs by itself
    "install-hook": (10, "replaces the install command"),
    "pth-file": (35, ".pth file that runs code every time Python starts"),
    "shell-at-install": (30, "runs commands during install or import"),
    "network-at-install": (25, "connects to the internet during install or import"),
    # code
    "exec-decoded": (40, "decodes hidden code and runs it"),
    "download-exec": (40, "downloads something and runs it"),
    "fetch-and-run": (25, "downloads files and starts programs"),
    "exec-dynamic": (15, "runs code built at runtime"),
    "hidden-powershell": (35, "starts hidden or encoded PowerShell"),
    "steals-secrets": (35, "reads credentials and has a way to send them out"),
    "secrets": (15, "reads browser, chat app or wallet data"),
    "credentials": (5, "reads developer or cloud credentials"),
    "env-dump": (25, "collects all environment variables and sends them out"),
    "recon": (10, "collects details about the machine"),
    "exfil-endpoint": (30, "talks to a service popular for stealing data"),
    "raw-ip-url": (20, "talks to a bare IP address"),
    "obfuscated": (25, "deliberately scrambled code"),
    "persistence": (25, "sets itself up to run again later"),
    "hides-traces": (25, "covers its tracks"),
    "unread-code": (40, "parts of the package couldn't be read"),
    "compiled-python": (20, "ships compiled Python that can't be read"),
    "pth-code": (15, "runs a line of code every time Python starts"),
    "self-publish": (35, "publishes packages by itself, like spam or a worm"),
    "shell": (5, "runs shell commands"),
    # archive
    "archive-escape": (30, "tries to write files outside the package"),
    "disguised-binary": (35, "program hidden under another file type"),
    "binary-payload": (15, "ships a Windows program or script"),
}

# Things honest packages do too (esbuild downloads and runs a binary when it's
# installed). On their own they can reach medium but never high: that takes
# evidence, something that's hard to explain innocently.
BEHAVIOUR = {"install-script", "install-hook", "shell-at-install", "network-at-install", "shell",
             "exec-dynamic", "binary-payload", "credentials", "very-new", "new", "no-source",
             "revived", "fetch-and-run", "pth-code"}
BEHAVIOUR_CAP = 45

THRESHOLDS = (("high", 60), ("medium", 35), ("low", 15))
SEVERITIES = ("none", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Finding:
    rule: str
    message: str
    path: str | None = None
    line: int | None = None
    snippet: str | None = None
    critical: bool = False
    points: int | None = None  # overrides the rule's default

    @property
    def value(self) -> int:
        return RULES[self.rule][0] if self.points is None else self.points

    @property
    def where(self) -> str:
        if self.path and self.line:
            return f"{self.path}:{self.line}"
        return self.path or ""


@dataclass
class Verdict:
    score: int
    severity: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def at_least(self, severity: str) -> bool:
        return SEVERITIES.index(self.severity) >= SEVERITIES.index(severity)


def judge(findings: list[Finding], notes: list[str] | None = None) -> Verdict:
    """Each rule counts once (its strongest finding); the rest stay as evidence."""
    best: dict[str, Finding] = {}
    for f in findings:
        if f.rule not in best or f.value > best[f.rule].value:
            best[f.rule] = f
    behaviour = sum(f.value for f in best.values() if f.rule in BEHAVIOUR)
    evidence = sum(f.value for f in best.values() if f.rule not in BEHAVIOUR)
    score = min(100, min(behaviour, BEHAVIOUR_CAP) + evidence)
    critical = any(f.critical for f in findings)
    if critical:
        severity, score = "critical", max(score, 90)
    else:
        severity = next((name for name, floor in THRESHOLDS if score >= floor), "none")
    ordered = sorted(findings, key=lambda f: (-best[f.rule].value, f.rule, -f.value))
    return Verdict(score, severity, ordered, list(notes or []))


def snippet(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."
