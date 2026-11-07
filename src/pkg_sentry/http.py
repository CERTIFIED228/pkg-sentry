"""Tiny HTTP client on the standard library.

A tool that checks dependencies for supply-chain attacks should have as few
dependencies itself as it can, so this is urllib rather than requests.
"""

import http.client
import json
import time
import urllib.error
import urllib.request

from . import __version__

USER_AGENT = f"pkg-sentry/{__version__}"
CHUNK = 64 * 1024


class FetchError(Exception):
    pass


class NotFound(FetchError):
    pass


class TooBig(FetchError):
    pass


def get(
    url: str,
    *,
    max_bytes: int = 50_000_000,
    timeout: float = 20,
    retries: int = 2,
    headers: dict | None = None,
    data: bytes | None = None,
) -> bytes:
    request = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT})
    for key, value in (headers or {}).items():
        request.add_header(key, value)

    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return _read_capped(response, max_bytes, url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotFound(url) from None
            if e.code < 500 and e.code != 429 or attempt == retries:
                raise FetchError(f"{url}: HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError,
                http.client.HTTPException) as e:
            if attempt == retries:
                reason = getattr(e, "reason", e)
                raise FetchError(f"{url}: {reason}") from None
        time.sleep(2**attempt)
    raise AssertionError("unreachable")


def get_json(url: str, **kwargs):
    body = get(url, **kwargs)
    try:
        return json.loads(body)
    except ValueError:
        raise FetchError(f"{url}: response isn't JSON") from None


def post_json(url: str, payload: dict, **kwargs):
    headers = {"Content-Type": "application/json", **kwargs.pop("headers", {})}
    body = get(url, data=json.dumps(payload).encode(), headers=headers, **kwargs)
    try:
        return json.loads(body)
    except ValueError:
        raise FetchError(f"{url}: response isn't JSON") from None


def _read_capped(response, max_bytes: int, url: str) -> bytes:
    length = response.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > max_bytes:
        raise TooBig(f"{url}: {int(length):,} bytes is over the {max_bytes:,} byte limit")
    parts, total = [], 0
    while chunk := response.read(CHUNK):
        total += len(chunk)
        if total > max_bytes:
            raise TooBig(f"{url}: more than {max_bytes:,} bytes, stopped reading")
        parts.append(chunk)
    if length and length.isdigit() and total != int(length):
        # A cut-off download would otherwise look like a smaller, cleaner file.
        raise http.client.IncompleteRead(b"", int(length) - total)
    return b"".join(parts)
