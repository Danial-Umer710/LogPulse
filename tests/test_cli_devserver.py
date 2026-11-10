from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

from logpulse import cli
from logpulse.devserver import BlobFolderWatcher, make_handler
from logpulse.store import ReportQuery


def test_cli_analyze_exit_codes(samples_dir, capsys):
    failing = samples_dir / "github-actions/api-service/1042/pytest.log"
    passing = samples_dir / "github-actions/inventory-go/733/go-test.log"
    assert cli.main(["analyze", str(failing), "--no-color"]) == 1
    assert "FAILED" in capsys.readouterr().out
    assert cli.main(["analyze", str(passing), "--no-color"]) == 0
    capsys.readouterr()
    assert cli.main(["analyze", str(passing), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "passed"


def test_cli_ingest_and_query(samples_dir, local_store, capsys):
    assert cli.main(["ingest", str(samples_dir)]) == 0
    out = capsys.readouterr().out
    assert "stored api-service/1042-pytest.log: failed" in out
    assert cli.main(["query", "--status", "passed"]) == 0
    assert "inventory-go#733" in capsys.readouterr().out
    assert cli.main(["query", "--failures", "--category", "secret_leak", "--json"]) == 0
    items = json.loads(capsys.readouterr().out)
    assert items and all(f["category"] == "secret_leak" for f in items)


def test_blob_folder_watcher_processes_new_and_changed_files(tmp_path, local_store):
    root = tmp_path / "raw-logs"
    log = root / "web" / "9" / "ci.log"
    log.parent.mkdir(parents=True)
    log.write_bytes(b"npm ERR! code E404\n")
    old = time.time() - 5
    os.utime(log, (old, old))  # make it look fully written

    watcher = BlobFolderWatcher(root, local_store)
    assert [r["id"] for r in watcher.scan_once()] == ["9-ci.log"]
    assert watcher.scan_once() == []  # unchanged: not reprocessed

    log.write_bytes(b"=== 3 passed in 0.1s ===\n")
    os.utime(log, (old + 1, old + 1))
    assert watcher.scan_once()[0]["status"] == "passed"
    assert len(local_store.query(ReportQuery())) == 1


def test_devserver_serves_api(local_store):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(local_store))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        req = urllib.request.Request(f"{base}/api/analyze?store=true&pipeline=dev&build=1", data=b"FAILED t.py::test_a\n", method="POST")
        with urllib.request.urlopen(req) as r:
            assert r.status == 201
        with urllib.request.urlopen(f"{base}/api/reports") as r:
            assert json.loads(r.read())["count"] == 1
        with urllib.request.urlopen(f"{base}/") as r:  # redirects to the dashboard
            assert b"LogPulse" in r.read()
    finally:
        httpd.shutdown()
