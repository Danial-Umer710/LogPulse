"""Local development server. Needs no Azure account, Functions Core Tools or Azurite.

* Serves the same HTTP API as the Azure Function at http://localhost:7071/api/...
* Simulates the blob trigger: any file dropped into ``.localblobs/raw-logs/``
  (e.g. ``.localblobs/raw-logs/web-app/42/test.log``) is processed by the same
  ``service.process_blob`` function the Azure trigger calls.
"""

from __future__ import annotations

import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from . import api, service
from .store import ReportStore, get_store

log = logging.getLogger("logpulse.devserver")


class BlobFolderWatcher(threading.Thread):
    """Polls a folder and processes new or changed files, like a blob trigger does."""

    def __init__(self, root: Path, store: ReportStore, interval: float = 1.0) -> None:
        super().__init__(daemon=True, name="blob-watcher")
        self.root, self.store, self.interval = root, store, interval
        self.seen: dict[Path, float] = {}
        self._stop = threading.Event()

    def scan_once(self) -> list[dict]:
        processed = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            mtime = path.stat().st_mtime
            if self.seen.get(path) == mtime:
                continue
            if time.time() - mtime < 0.5:
                continue  # still being written; next scan picks it up
            self.seen[path] = mtime
            blob_name = path.relative_to(self.root).as_posix()
            try:
                report = service.process_blob(blob_name, path.read_bytes(), self.store)
                processed.append(report)
                print(f"  [blob trigger] {blob_name} -> {report['status'].upper()} "
                      f"({len(report['findings'])} findings, {report['duration_ms']} ms)")
            except Exception:  # keep the watcher alive, like the Functions host does
                log.exception("Failed to process %s", blob_name)
        return processed

    def run(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()


def make_handler(store: ReportStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LogPulseDev/0.1"

        def _dispatch(self, method: str) -> None:
            url = urlsplit(self.path)
            if url.path in ("/", ""):
                self.send_response(302)
                self.send_header("Location", "/api/dashboard")
                self.end_headers()
                return
            if not url.path.startswith("/api"):
                self._send(api.ApiResponse(404, {"error": "not found"}))
                return
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            resp = api.route(method, url.path[len("/api"):], dict(parse_qsl(url.query)), body, store)
            self._send(resp)

        def _send(self, resp: api.ApiResponse) -> None:
            payload = resp.encoded()
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(payload)))
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def log_message(self, fmt: str, *args) -> None:
            log.debug("%s - %s", self.address_string(), fmt % args)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 7071, blob_root: str = ".localblobs/raw-logs", watch: bool = True) -> None:
    store = get_store()
    watcher = None
    if watch:
        watcher = BlobFolderWatcher(Path(blob_root), store)
        watcher.start()
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    print(f"LogPulse dev server on http://{host}:{port}/api/dashboard")
    print(f"  store: {type(store).__name__}")
    if watch:
        print(f"  blob trigger simulation: drop logs into {Path(blob_root).resolve()}")
        print("    e.g. <pipeline>/<build_id>/<file>.log")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        if watcher:
            watcher.stop()
