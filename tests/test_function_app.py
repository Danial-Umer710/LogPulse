"""Smoke-test the Azure Functions bindings without the Functions host."""

from __future__ import annotations

import json

import azure.functions as func
import pytest

import function_app


def user_fn(decorated):
    """In the v2 model the decorators wrap the function; unwrap it to call it directly."""
    return decorated.build().get_user_function()


def test_functions_are_registered():
    functions = function_app.app.get_functions()  # can only be indexed once per app instance
    assert {f.get_function_name() for f in functions} == {"ingest_log", "analyze", "http_api"}
    blob = next(f for f in functions if f.get_function_name() == "ingest_log")
    binding = blob.get_bindings()[0]
    assert binding.type == "blobTrigger" and binding.path == "raw-logs/{name}"
    assert binding.get_dict_repr()["source"] == "EventGrid"


def test_blob_trigger_stores_report(local_store):
    data = b"FAILED tests/t.py::test_a - boom\n"
    blob = func.blob.InputStream(data=data, name="raw-logs/web-app/77/unit.log", length=len(data))
    user_fn(function_app.ingest_log)(blob)
    doc = local_store.get("web-app", "77-unit.log")
    assert doc and doc["status"] == "failed" and doc["source_blob"] == "raw-logs/web-app/77/unit.log"


def test_blob_trigger_skips_oversized(local_store, monkeypatch):
    from logpulse import service

    monkeypatch.setattr(service, "MAX_LOG_BYTES", 5)
    blob = func.blob.InputStream(data=b"0123456789", name="raw-logs/web/1/big.log", length=10)
    user_fn(function_app.ingest_log)(blob)  # must not raise (no poison-queue retries)
    assert local_store.get("web", "1-big.log") is None


@pytest.mark.parametrize("path, status", [("health", 200), ("reports", 200), ("nope", 404)])
def test_http_api(local_store, path, status):
    req = func.HttpRequest(method="GET", url=f"/api/{path}", route_params={"path": path}, params={}, body=b"")
    resp = user_fn(function_app.http_api)(req)
    assert resp.status_code == status


def test_http_analyze(local_store):
    req = func.HttpRequest(method="POST", url="/api/analyze", params={"store": "1", "pipeline": "p", "build": "1"},
                           body=b"npm ERR! code E404\n")
    resp = user_fn(function_app.analyze)(req)
    assert resp.status_code == 201
    assert json.loads(resp.get_body())["findings"][0]["source"] == "npm"
