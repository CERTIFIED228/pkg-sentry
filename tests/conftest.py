import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class Routes(dict):
    """path -> (status, body, headers) or a list of those, served in order."""

    def __init__(self):
        super().__init__()
        self.hits = []


@pytest.fixture
def server(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    routes = Routes()

    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body_in = self.rfile.read(length) if length else b""
            routes.hits.append((self.command, self.path, body_in, dict(self.headers)))
            answer = routes.get(self.path, (404, b"not found", {}))
            if isinstance(answer, list):
                answer = answer.pop(0) if len(answer) > 1 else answer[0]
            status, body, headers = answer
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            if "Content-Length" not in headers:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _serve

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    routes.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield routes
    httpd.shutdown()
