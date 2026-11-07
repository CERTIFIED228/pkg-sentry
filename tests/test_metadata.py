import json
from datetime import datetime, timedelta, timezone

import pytest

from pkg_sentry import http
from pkg_sentry.known import OSV
from pkg_sentry.metadata import metadata_findings
from pkg_sentry.registry import PackageInfo

NOW = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)


def info(**kw):
    base = dict(ecosystem="pypi", name="x", version="1.0", repository="https://github.com/a/b",
                created=NOW - timedelta(days=900), released=NOW - timedelta(days=200),
                previous_release=NOW - timedelta(days=300))
    return PackageInfo(**{**base, **kw})


def rules(i):
    return sorted(f.rule for f in metadata_findings(i, NOW))


def test_an_established_package_is_clean():
    assert rules(info()) == []


@pytest.mark.parametrize("days, rule", [(0.2, "very-new"), (3, "very-new"), (20, "new"),
                                         (31, None)])
def test_new_packages(days, rule):
    found = rules(info(created=NOW - timedelta(days=days), released=NOW, previous_release=None))
    assert found == ([rule] if rule else [])


def test_age_is_explained():
    found = metadata_findings(info(created=NOW - timedelta(hours=5)), NOW)
    assert found[0].message == "first published 5 hours ago"


def test_release_after_years_of_silence():
    i = info(released=NOW - timedelta(days=3), previous_release=NOW - timedelta(days=800))
    found = metadata_findings(i, NOW)
    assert [f.rule for f in found] == ["revived"]
    assert "2 year(s)" in found[0].message


def test_old_revival_doesnt_count():
    assert rules(info(released=NOW - timedelta(days=400),
                      previous_release=NOW - timedelta(days=1200))) == []


@pytest.mark.parametrize("version", ["99.9.9", "999.0.0", "1337.0.1", "9999.1"])
def test_dependency_confusion_versions(version):
    assert rules(info(version=version)) == ["confusion-version"]


@pytest.mark.parametrize("version", ["9.1.0", "2024.1.1", "1.99.0"])
def test_normal_versions(version):
    assert rules(info(version=version)) == []


def test_no_source_link():
    assert rules(info(repository=None, homepage="https://example.com")) == ["no-source"]
    assert rules(info(repository=None, homepage="https://gitlab.com/a/b")) == []


def test_npm_placeholder_is_known_malware():
    found = metadata_findings(info(removed_as_malware=True), NOW)
    assert found[0].rule == "known-malware" and found[0].critical


def test_osv_splits_malware_from_vulnerabilities(server):
    server["/v1/query"] = [
        (200, json.dumps({"vulns": [{"id": "MAL-2022-4691", "summary": "Malicious code in x"},
                                    {"id": "GHSA-aaaa"}], "next_page_token": "p2"}).encode(), {}),
        (200, json.dumps({"vulns": [{"id": "PYSEC-1"}]}).encode(), {}),
    ]
    result = OSV(server.url).lookup("pypi", "x", "1.0")
    assert result.malware == [("MAL-2022-4691", "Malicious code in x")]
    assert result.vulnerabilities == ["GHSA-aaaa", "PYSEC-1"]
    first, second = (json.loads(h[2]) for h in server.hits)
    assert first == {"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}
    assert second["page_token"] == "p2"


def test_osv_nothing_known(server):
    server["/v1/query"] = (200, b"{}", {})
    result = OSV(server.url).lookup("npm", "left-pad")
    assert (result.malware, result.vulnerabilities) == ([], [])
    assert json.loads(server.hits[0][2])["package"]["ecosystem"] == "npm"


def test_osv_down(server, monkeypatch):
    monkeypatch.setattr(http.time, "sleep", lambda s: None)
    server["/v1/query"] = (503, b"", {})
    with pytest.raises(http.FetchError):
        OSV(server.url).lookup("pypi", "x")
