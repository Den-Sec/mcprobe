import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class LocalOOB:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._hits: dict[str, list[dict]] = {}
        store = self._hits

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                tok = self.path.strip("/").split("/")[0]
                store.setdefault(tok, []).append(
                    {"path": self.path, "headers": dict(self.headers)})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        self._srv = ThreadingHTTPServer((host, port), Handler)
        self.host, self.port = self._srv.server_address

    def __enter__(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._srv.shutdown()

    def new_token(self) -> tuple[str, str]:
        token = uuid.uuid4().hex[:12]
        return token, f"http://{self.host}:{self.port}/{token}"

    def interactions(self, token: str) -> list[dict]:
        return list(self._hits.get(token, []))
