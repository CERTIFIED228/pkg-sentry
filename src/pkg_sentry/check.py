"""Check one package end to end: known malware, name, metadata, code."""

from dataclasses import dataclass, field

from . import http
from .analyse import analyse
from .archive import ArchiveError, Unpacked, unpack
from .jsscan import scan_hooks
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
    # Why some of the code couldn't be read, so a clean verdict isn't the whole story.
    incomplete: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.info:
            return PackageSpec(self.spec.ecosystem, self.info.name, self.info.version).label
        return self.spec.label


class Checker:
    def __init__(self, registry: Registry | None = None, osv: OSV | None = None,
                 read_code: bool = True, max_download: int = 100_000_000):
        self.registry = registry or Registry()
        self.osv = osv  # None = offline, skip the lookup
        self.read_code = read_code
        self.max_download = max_download

    def check(self, spec: PackageSpec) -> Report:
        findings: list[Finding] = []
        notes: list[str] = []
        incomplete: list[str] = []

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

        squat = load_popular(spec.ecosystem).squats(info.name if info else spec.name)
        if squat:
            findings.append(Finding("typosquat", f"the name looks like {squat.how}"))

        if info is None:
            if not known:
                findings.append(Finding(
                    "not-found", f"there's no {spec.name} on {_registry_name(spec)}. If something "
                    "depends on it, anyone can register the name and their code gets installed"))
            return Report(spec, judge(findings, notes))

        findings += metadata_findings(info)
        if info.deprecated:
            notes.append(f"the registry marks this release as deprecated or yanked: "
                         f"{info.deprecated}")

        if not self.read_code:
            notes.append("code wasn't read (--no-code)")
            # npm publishes the scripts with the metadata, so hooks can still be checked.
            findings += scan_hooks("package.json", info.scripts)[0]
        else:
            findings += self._read_code(info, notes, incomplete)

        return Report(spec, judge(findings, notes), info=info, incomplete=incomplete)

    def _known(self, spec, version, notes) -> list[Finding]:
        if self.osv is None:
            notes.append("known-malware lookup skipped (offline)")
            return []
        try:
            advisories = self.osv.lookup(spec.ecosystem, spec.name, version)
        except (http.FetchError, ValueError, AttributeError):
            notes.append("couldn't reach OSV.dev, so the known-malware lookup was skipped")
            return []
        if advisories.vulnerabilities:
            count = len(advisories.vulnerabilities)
            notes.append(f"{count} known vulnerabilit{'y' if count == 1 else 'ies'} (not malware): "
                         + ", ".join(advisories.vulnerabilities[:5]))
        return [Finding("known-malware", f"{vuln_id}: {summary}".rstrip(": "), critical=True)
                for vuln_id, summary in advisories.malware]

    def _read_code(self, info: PackageInfo, notes: list[str],
                   incomplete: list[str]) -> list[Finding]:
        if not info.artifacts:
            notes.append("no files to download for this release")
            return []
        findings = []
        too_big = (f"is over the {self.max_download // 1_000_000} MB download limit, so its code "
                   "wasn't read")
        for artifact in info.artifacts:
            if artifact.size and artifact.size > self.max_download:
                incomplete.append(f"{artifact.filename} {too_big}")
                continue
            try:
                data = self.registry.download(artifact, self.max_download)
            except http.TooBig:
                incomplete.append(f"{artifact.filename} {too_big}")
                continue
            except http.FetchError as e:
                incomplete.append(f"couldn't download {artifact.filename}: {e}")
                continue
            try:
                # npm drops the first folder of every entry, whatever it's called.
                unpacked = (unpack(data, npm=True) if info.ecosystem == "npm"
                            else unpack(data).strip_top_dir())
            except ArchiveError as e:
                # pip and npm read archives this couldn't, so it isn't safe to call it clean.
                findings.append(Finding("unread-code", f"couldn't unpack it ({e}), so it could "
                                        "be hiding anything", artifact.filename))
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
