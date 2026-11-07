import pytest

from pkg_sentry import http


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(http.time, "sleep", lambda s: None)


def test_get_json(server):
    server["/x"] = (200, b'{"a": 1}', {})
    assert http.get_json(server.url + "/x") == {"a": 1}


def test_sends_a_user_agent(server):
    server["/ua"] = (200, b"ok", {})
    http.get(server.url + "/ua")
    assert server.hits[-1][3]["User-Agent"].startswith("pkg-sentry/")


def test_404_is_not_found(server):
    with pytest.raises(http.NotFound):
        http.get(server.url + "/missing")


def test_retries_server_errors(server):
    server["/flaky"] = [(503, b"", {}), (200, b"ok", {})]
    assert http.get(server.url + "/flaky") == b"ok"
    assert len(server.hits) == 2


def test_gives_up_after_retries(server):
    server["/down"] = (500, b"", {})
    with pytest.raises(http.FetchError, match="HTTP 500"):
        http.get(server.url + "/down", retries=1)
    assert len(server.hits) == 2


def test_client_errors_are_not_retried(server):
    server["/nope"] = (403, b"", {})
    with pytest.raises(http.FetchError, match="403"):
        http.get(server.url + "/nope")
    assert len(server.hits) == 1


def test_refuses_big_responses_from_the_header(server):
    server["/big"] = (200, b"x" * 10, {"Content-Length": "999999"})
    with pytest.raises(http.FetchError, match="limit"):
        http.get(server.url + "/big", max_bytes=1000)


def test_refuses_big_responses_that_lie_about_their_size(server):
    # No Content-Length: the cap has to hold while reading.
    server["/stream"] = (200, b"x" * 5000, {"Content-Length": ""})
    with pytest.raises(http.FetchError, match="stopped reading"):
        http.get(server.url + "/stream", max_bytes=1000)


def test_bad_json(server):
    server["/html"] = (200, b"<html>", {})
    with pytest.raises(http.FetchError, match="isn't JSON"):
        http.get_json(server.url + "/html")


def test_post_json(server):
    server["/q"] = (200, b'{"vulns": []}', {})
    assert http.post_json(server.url + "/q", {"package": {"name": "x"}}) == {"vulns": []}
    method, _, body, headers = server.hits[-1]
    assert method == "POST"
    assert b'"name": "x"' in body
    assert headers["Content-Type"] == "application/json"


def test_unreachable_host():
    with pytest.raises(http.FetchError):
        http.get("http://127.0.0.1:9/", retries=0, timeout=2)


def test_cut_off_downloads_are_an_error(server):
    server["/short"] = (200, b"x" * 10, {"Content-Length": "100000"})
    with pytest.raises(http.FetchError):
        http.get(server.url + "/short", retries=0)
