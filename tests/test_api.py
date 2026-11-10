from __future__ import annotations

import json

import pytest

from logpulse import api

LOG = b"FAILED tests/test_a.py::test_x - boom\n##[error]Process completed with exit code 1.\n"


def call(store, method, path, params=None, body=b""):
    r = api.route(method, path, params or {}, body, store)
    data = json.loads(r.encoded()) if r.content_type.startswith("application/json") else r.encoded().decode()
    return r.status, data


def test_health(local_store):
    assert call(local_store, "GET", "health") == (200, {"status": "ok", "store": "LocalReportStore"})


def test_dashboard_served(local_store):
    status, html = call(local_store, "GET", "dashboard")
    assert status == 200 and "<title>LogPulse</title>" in html


def test_analyze_without_store_does_not_persist(local_store):
    status, doc = call(local_store, "POST", "analyze", {"pipeline": "web", "build": "5"}, LOG)
    assert status == 200 and doc["status"] == "failed"
    assert call(local_store, "GET", "reports")[1]["count"] == 0


def test_analyze_store_then_query(local_store):
    status, doc = call(local_store, "POST", "analyze", {"pipeline": "web", "build": "5", "name": "ci.log", "store": "true"}, LOG)
    assert status == 201 and doc["id"] == "5-ci.log"

    status, listing = call(local_store, "GET", "reports", {"status": "failed"})
    assert status == 200 and listing["count"] == 1
    assert "findings" not in listing["items"][0] and listing["items"][0]["finding_count"] == 2

    status, full = call(local_store, "GET", "reports/web/5-ci.log")
    assert status == 200 and len(full["findings"]) == 2

    status, failures = call(local_store, "GET", "failures", {"category": "test_failure"})
    assert failures["count"] == 1 and failures["items"][0]["build_id"] == "5"

    status, ov = call(local_store, "GET", "overview")
    assert ov["by_status"] == {"failed": 1}


def test_404s(local_store):
    assert call(local_store, "GET", "reports/web/nope")[0] == 404
    assert call(local_store, "GET", "nope")[0] == 404
    assert call(local_store, "DELETE", "reports")[0] == 404


@pytest.mark.parametrize(
    "params",
    [{"status": "broken"}, {"min_severity": "huge"}, {"category": "x"}, {"limit": "0"}, {"limit": "abc"}, {"limit": "501"}],
)
def test_validation_errors(local_store, params):
    status, body = call(local_store, "GET", "reports", params)
    assert status == 400 and "error" in body


def test_analyze_requires_body(local_store):
    assert call(local_store, "POST", "analyze")[0] == 400
