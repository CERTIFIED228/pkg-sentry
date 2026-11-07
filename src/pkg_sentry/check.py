"""Check one package end to end: known malware, name, metadata, code."""

from dataclasses import dataclass

from . import http
from .analyse import analyse
from .archive import ArchiveError, Unpacked, unpack
from .known import OSV
from .metadata import metadata_findings
from .names import load_popular
from .registry import PackageInfo, Registry, VersionNotFound
from .rules import Finding, Verdict, judge
from .spec import PackageSpec


@dataclass
class Report:
    spec: PackageSpec
    verdict: Verdict
    info: PackageInfo | None = None
    error: str | None = None

    @property
    def label(self) -> str:
        if self.info:
            return PackageSpec(self.spec.ecosystem, self.info.name, self.info.version).label
        return self.spec.label


class Checker:
    def __init__(self, registry: Registry | None = None, osv: OSV | None = None,
                 read_code: bool = True, max_download: int = 50_000_000):
        self.registry = registry or Registry()
        self.osv = osv  # None = offline, skip the lookup
        self.read_code = read_code
        self.max_download = max_download

    def check(self, spec: PackageSpec) -> Report:
        findings: list[Finding] = []
        notes: list[str] = []

        info = None
        try:
            info = self.registry.info(spec)
        except http.NotFound:
            pass
        except VersionNotFound as e:
            return Report(spec, judge([]), error=str(e))
        except (http.FetchError, KeyError, TypeError, ValueError) as e:
            return Report(spec, judge([]), error=f"couldn't read the registry: {e}")

        version = info.version if info else spec.version
        known = self._known(spec, version, notes)
        findings += known

        if info is None:
            if not known:
                findings.append(Finding(
                    "not-found", f"there's no {spec.name} on {_registry_name(spec)}. If something "
                    "depends on it, anyone can register the name and their code gets installed"))
            return Report(spec, judge(findings, notes))

        squat = load_popular(spec.ecosystem).squats(info.name)
        if squat:
            findings.append(Finding("typosquat", f"the name looks like {squat.how}"))
        findings += metadata_findings(info)

        if not self.read_code:
            notes.append("code wasn't read (--no-code)")
            if info.install_scripts:
                findings += [Finding("install-script", f"runs '{cmd}' on install")
                             for cmd in info.install_scripts.values()]
        else:
            findings += self._read_code(info, notes)

        return Report(spec, judge(findings, notes), info=info)

    def _known(self, spec, version, notes) -> list[Finding]:
        if self.osv is None:
            notes.append("known-malware lookup skipped (offline)")
            return []
        try:
            advisories = self.osv.lookup(spec.ecosystem, spec.name, version)
        except (http.FetchError, ValueError, AttributeError) as e:
            notes.append(f"couldn't reach OSV for the known-malware lookup: {e}")
            return []
        if advisories.vulnerabilities:
            count = len(advisories.vulnerabilities)
            notes.append(f"{count} known vulnerabilit{'y' if count == 1 else 'ies'} (not malware): "
                         + ", ".join(advisories.vulnerabilities[:5]))
        return [Finding("known-malware", f"{vuln_id}: {summary}".rstrip(": "), critical=True)
                for vuln_id, summary in advisories.malware]

    def _read_code(self, info: PackageInfo, notes: list[str]) -> list[Finding]:
        if not info.artifacts:
            notes.append("no files to download for this release")
            return []
        findings = []
        for artifact in info.artifacts:
            if artifact.size and artifact.size > self.max_download:
                notes.append(f"{artifact.filename} is {artifact.size:,} bytes, too big to read")
                continue
            try:
                data = self.registry.download(artifact, self.max_download)
                unpacked = unpack(data).strip_top_dir()
            except (http.FetchError, ArchiveError) as e:
                notes.append(f"couldn't read {artifact.filename}: {e}")
                continue
            notes += _skipped_notes(artifact.filename, unpacked)
            findings += [_in(artifact.filename, f) for f in analyse(unpacked, info.ecosystem)]
        return findings


def _in(filename: str, finding: Finding) -> Finding:
    if not finding.path:
        return finding
    return Finding(finding.rule, finding.message, f"{filename}/{finding.path}", finding.line,
                   finding.snippet, finding.critical, finding.points)


def _skipped_notes(filename: str, unpacked: Unpacked) -> list[str]:
    if not unpacked.skipped:
        return []
    shown = ", ".join(f"{path} ({why})" for path, why in unpacked.skipped[:3])
    more = len(unpacked.skipped) - 3
    return [f"{filename}: skipped {shown}" + (f" and {more} more" if more > 0 else "")]


def _registry_name(spec: PackageSpec) -> str:
    return "PyPI" if spec.ecosystem == "pypi" else "npm"
