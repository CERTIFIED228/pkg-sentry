import io
import tarfile
from datetime import datetime, timedelta, timezone

from pkg_sentry import http
from pkg_sentry.check import Checker
from pkg_sentry.known import Advisories
from pkg_sentry.registry import Artifact, PackageInfo, VersionNotFound
from pkg_sentry.spec import PackageSpec

OLD = datetime.now(timezone.utc) - timedelta(days=2000)


def tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, body in files.items():
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeRegistry:
    def __init__(self, packages=None, error=None):
        self.packages, self.error = packages or {}, error
        self.downloads = []

    def info(self, spec):
        if self.error:
            raise self.error
        if spec.name not in self.packages:
            raise http.NotFound(spec.name)
        info, _ = self.packages[spec.name]
        return info

    def download(self, artifact, max_bytes=None):
        self.downloads.append(artifact.filename)
        for info, files in self.packages.values():
            if any(a.filename == artifact.filename for a in info.artifacts):
                return files[artifact.filename]
        raise http.FetchError("gone")


class FakeOSV:
    def __init__(self, malware=(), vulns=(), down=False):
        self.result = Advisories(list(malware), list(vulns))
        self.down = down

    def lookup(self, ecosystem, name, version=None):
        if self.down:
            raise http.FetchError("no route")
        return self.result


def package(name, files, **kw):
    filename = f"{name}-1.0.tar.gz"
    info = PackageInfo(ecosystem="pypi", name=name, version="1.0", created=OLD, released=OLD,
                       repository="https://github.com/x/y",
                       artifacts=[Artifact(filename, f"https://files/{filename}", 100)], **kw)
    return {name: (info, {filename: tarball({f"{name}-1.0/{k}": v for k, v in files.items()})})}


def test_clean_package():
    registry = FakeRegistry(package("tidy", {"setup.py": "from setuptools import setup\nsetup()",
                                             "tidy/__init__.py": "x = 1"}))
    report = Checker(registry, FakeOSV()).check(PackageSpec("pypi", "tidy"))
    assert report.verdict.severity == "none"
    assert report.label == "tidy==1.0 (PyPI)"
    assert registry.downloads == ["tidy-1.0.tar.gz"]


def test_malicious_setup_py():
    registry = FakeRegistry(package("evil", {
        "setup.py": "import base64\nexec(base64.b64decode('eA=='))\n"}))
    report = Checker(registry, FakeOSV()).check(PackageSpec("pypi", "evil"))
    assert report.verdict.severity == "critical"
    hit = report.verdict.findings[0]
    assert hit.rule == "exec-decoded"
    assert hit.where == "evil-1.0.tar.gz/setup.py:2"


def test_known_malware_even_after_the_registry_deleted_it():
    osv = FakeOSV(malware=[("MAL-2023-1", "Malicious code in gone")])
    report = Checker(FakeRegistry(), osv).check(PackageSpec("pypi", "gone"))
    assert report.verdict.severity == "critical"
    assert report.verdict.findings[0].message == "MAL-2023-1: Malicious code in gone"


def test_missing_package_could_be_hijacked():
    report = Checker(FakeRegistry(), FakeOSV()).check(PackageSpec("npm", "internal-utils"))
    assert [f.rule for f in report.verdict.findings] == ["not-found"]
    assert report.verdict.severity == "medium"


def test_typosquat_name():
    registry = FakeRegistry(package("reqeusts", {"setup.py": "from setuptools import setup"}))
    report = Checker(registry, FakeOSV()).check(PackageSpec("pypi", "reqeusts"))
    assert "typosquat" in [f.rule for f in report.verdict.findings]
    assert "'requests'" in report.verdict.findings[0].message


def test_vulnerabilities_are_a_note_not_a_score():
    registry = FakeRegistry(package("old", {"setup.py": ""}))
    report = Checker(registry, FakeOSV(vulns=["GHSA-1", "PYSEC-2"])).check(
        PackageSpec("pypi", "old"))
    assert report.verdict.score == 0
    assert "2 known vulnerabilities (not malware): GHSA-1, PYSEC-2" in report.verdict.notes


def test_offline_and_osv_down_are_noted():
    registry = FakeRegistry(package("tidy", {"setup.py": ""}))
    offline = Checker(registry, None).check(PackageSpec("pypi", "tidy"))
    assert "known-malware lookup skipped (offline)" in offline.verdict.notes
    down = Checker(registry, FakeOSV(down=True)).check(PackageSpec("pypi", "tidy"))
    assert "couldn't reach OSV.dev, so the known-malware lookup was skipped" in down.verdict.notes


def test_missing_typo_name_says_what_was_meant():
    report = Checker(FakeRegistry(), FakeOSV()).check(PackageSpec("pypi", "reqeusts"))
    assert sorted(f.rule for f in report.verdict.findings) == ["not-found", "typosquat"]


def test_no_code_mode_uses_registry_scripts():
    pkgs = package("hooky", {"setup.py": ""}, install_scripts={"postinstall": "node x.js"})
    registry = FakeRegistry(pkgs)
    report = Checker(registry, FakeOSV(), read_code=False).check(PackageSpec("pypi", "hooky"))
    assert [f.rule for f in report.verdict.findings] == ["install-script"]
    assert registry.downloads == []


def test_too_big_to_download():
    pkgs = package("huge", {"setup.py": ""})
    pkgs["huge"][0].artifacts[0] = Artifact("huge-1.0.tar.gz", "https://f/h", 10**9)
    report = Checker(FakeRegistry(pkgs), FakeOSV()).check(PackageSpec("pypi", "huge"))
    assert any("too big to read" in n for n in report.verdict.notes)


def test_broken_download_is_noted():
    pkgs = package("broken", {"setup.py": ""})
    pkgs["broken"][1]["broken-1.0.tar.gz"] = b"not an archive"
    report = Checker(FakeRegistry(pkgs), FakeOSV()).check(PackageSpec("pypi", "broken"))
    assert any("couldn't read broken-1.0.tar.gz" in n for n in report.verdict.notes)


def test_registry_errors_are_reported():
    report = Checker(FakeRegistry(error=VersionNotFound("x has no release 9")), FakeOSV()).check(
        PackageSpec("pypi", "x", "9"))
    assert report.error == "x has no release 9"
    report = Checker(FakeRegistry(error=http.FetchError("timed out")), FakeOSV()).check(
        PackageSpec("pypi", "x"))
    assert report.error.startswith("couldn't read the registry")
