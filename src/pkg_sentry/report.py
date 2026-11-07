import json

from .check import Report

LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "none": "OK"}
COLOURS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
           "none": "\033[32m"}
RESET = "\033[0m"


def as_text(report: Report, colour: bool = False, evidence: int = 3) -> str:
    verdict = report.verdict
    if report.error:
        return f"{report.label}\n  error: {report.error}"

    label = LABELS[verdict.severity]
    if colour:
        label = f"{COLOURS[verdict.severity]}{label}{RESET}"
    lines = [f"{report.label}  {label} {verdict.score}/100"]

    shown: dict[str, int] = {}
    for f in verdict.findings:
        count = shown.get(f.rule, 0)
        shown[f.rule] = count + 1
        if count == evidence:
            lines.append("      (more like this in other files)")
        if count >= evidence:
            continue
        where = f"  [{f.where}]" if f.where else ""
        lines.append(f"  - {f.message}{where}")
        if f.snippet:
            lines.append(f"      {f.snippet}")
    for note in verdict.notes:
        lines.append(f"  note: {note}")
    return "\n".join(lines)


def as_dict(report: Report) -> dict:
    verdict = report.verdict
    return {
        "ecosystem": report.spec.ecosystem,
        "name": report.info.name if report.info else report.spec.name,
        "version": report.info.version if report.info else report.spec.version,
        "severity": verdict.severity,
        "score": verdict.score,
        "error": report.error,
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
    errors = 0
    for r in reports:
        if r.error:
            errors += 1
        else:
            counts[r.verdict.severity] += 1
    parts = [f"{n} {LABELS[level].lower()}" for level, n in counts.items() if n]
    if errors:
        parts.append(f"{errors} couldn't be checked")
    return f"{len(reports)} package(s): " + ", ".join(parts)
