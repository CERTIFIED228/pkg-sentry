import json
import re

from .check import Report

LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "none": "OK"}
COLOURS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
           "none": "\033[32m"}
RESET = "\033[0m"
# Snippets come from the package being checked. Raw escape codes could clear
# the warning off the screen and print "OK" instead, and bidi controls could
# make code read differently, so they're shown escaped.
UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")


def clean(text: str) -> str:
    return UNSAFE.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100
                      else f"\\u{ord(m.group()):04x}", text)


def as_text(report: Report, colour: bool = False, evidence: int = 3) -> str:
    verdict = report.verdict
    if report.error:
        return f"{clean(report.label)}\n  error: {clean(report.error)}"

    label = LABELS[verdict.severity]
    if report.incomplete:
        label += " (partly checked)"
    if colour:
        label = f"{COLOURS[verdict.severity]}{label}{RESET}"
    lines = [f"{clean(report.label)}  {label} {verdict.score}/100"]

    shown: dict[str, int] = {}
    for f in verdict.findings:
        count = shown.get(f.rule, 0)
        shown[f.rule] = count + 1
        if count == evidence:
            lines.append("      (more like this in other files)")
        if count >= evidence:
            continue
        where = f"  [{clean(f.where)}]" if f.where else ""
        lines.append(f"  - {clean(f.message)}{where}")
        if f.snippet:
            lines.append(f"      {clean(f.snippet)}")
    for reason in report.incomplete:
        lines.append(f"  not checked: {clean(reason)}")
    for note in verdict.notes:
        lines.append(f"  note: {clean(note)}")
    return "\n".join(lines)


def as_dict(report: Report) -> dict:
    verdict = report.verdict
    return {
        "ecosystem": report.spec.ecosystem,
        "name": report.info.name if report.info else report.spec.name,
        "version": report.info.version if report.info else report.spec.version,
        "summary": report.info.summary if report.info else None,
        "severity": verdict.severity,
        "score": verdict.score,
        "complete": not report.error and not report.incomplete,
        "error": report.error,
        "not_checked": report.incomplete,
        "findings": [
            {"rule": f.rule, "message": f.message, "path": f.path, "line": f.line,
             "snippet": f.snippet, "critical": f.critical, "points": f.value}
            for f in verdict.findings
        ],
        "notes": verdict.notes,
    }


def as_json(reports: list[Report]) -> str:
    return json.dumps([as_dict(r) for r in reports], indent=2)


def summary(reports: list[Report]) -> str:
    counts = {level: 0 for level in LABELS}
    errors = partial = 0
    for r in reports:
        if r.error:
            errors += 1
        else:
            counts[r.verdict.severity] += 1
            partial += bool(r.incomplete)
    parts = [f"{n} {LABELS[level].lower()}" for level, n in counts.items() if n]
    if partial:
        parts.append(f"{partial} only partly checked")
    if errors:
        parts.append(f"{errors} couldn't be checked")
    return f"{len(reports)} package(s): " + ", ".join(parts)
