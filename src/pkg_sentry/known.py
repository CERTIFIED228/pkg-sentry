"""Known-malware lookup through OSV.dev.

OSV collects the OpenSSF malicious-packages reports, which use MAL- ids.
Registries delete malware quickly, so a name OSV knows about may no longer
exist on PyPI or npm at all; the lookup still works for those.
"""

from dataclasses import dataclass, field

from . import http

OSV_URL = "https://api.osv.dev"
ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}


@dataclass
class Advisories:
    malware: list[tuple[str, str]] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)


class OSV:
    def __init__(self, url: str = OSV_URL, timeout: float = 15):
        self.url, self.timeout = url, timeout

    def lookup(self, ecosystem: str, name: str, version: str | None = None) -> Advisories:
        query = {"package": {"name": name, "ecosystem": ECOSYSTEMS[ecosystem]}}
        if version:
            query["version"] = version
        result = Advisories()
        for _ in range(20):  # OSV pages long answers
            answer = http.post_json(f"{self.url}/v1/query", query, timeout=self.timeout)
            for vuln in answer.get("vulns") or []:
                vuln_id = vuln.get("id", "")
                if vuln_id.startswith("MAL-"):
                    summary = vuln.get("summary") or vuln.get("details", "")[:120]
                    result.malware.append((vuln_id, summary))
                else:
                    result.vulnerabilities.append(vuln_id)
            token = answer.get("next_page_token")
            if not token:
                break
            query["page_token"] = token
        return result
