"""Red flags in what the registry says about a release."""

import re
from datetime import datetime, timedelta, timezone

from .registry import PackageInfo
from .rules import Finding

# Dependency-confusion packages use a silly version so they win over the
# real internal package (99.9.9, 1337.0.0).
CONFUSION_VERSION = re.compile(r"^(?:9{2,}|1337|666|6969)\b")


def metadata_findings(info: PackageInfo, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    found = []

    if info.removed_as_malware:
        found.append(Finding("known-malware",
                             "npm replaced it with a security placeholder, which it does for "
                             "confirmed malware", critical=True))

    if info.created:
        age = now - info.created
        if age < timedelta(days=7):
            found.append(Finding("very-new", f"first published {_ago(age)}"))
        elif age < timedelta(days=30):
            found.append(Finding("new", f"first published {_ago(age)}"))

    if info.released and info.previous_release:
        gap = info.released - info.previous_release
        recent = now - info.released < timedelta(days=90)
        if gap > timedelta(days=365) and recent:
            found.append(Finding(
                "revived", f"this release came out {_ago(now - info.released)}, after "
                f"{gap.days // 365} year(s) without one. Hijacked accounts often look like this"))

    if CONFUSION_VERSION.match(info.version):
        found.append(Finding("confusion-version",
                             f"version {info.version} is the kind used to win over a company's "
                             "internal package (dependency confusion)"))

    if not info.repository and not _code_host(info.homepage):
        found.append(Finding("no-source", "no link to its source code"))

    return found


def _code_host(url: str | None) -> bool:
    return bool(url) and any(h in url for h in ("github.com", "gitlab.com", "bitbucket.org",
                                                "codeberg.org", "sr.ht"))


def _ago(delta: timedelta) -> str:
    if delta < timedelta(days=1):
        hours = max(1, int(delta.total_seconds() // 3600))
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = delta.days
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} ago"
    return f"{days // 30} months ago"
