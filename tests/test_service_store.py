from __future__ import annotations

import gzip
import json

import pytest

from logpulse import service
from logpulse.store import CosmosReportStore, ReportQuery, build_cosmos_sql, get_store, set_store

FAILING = b"FAILED tests/test_a.py::test_x - assert 1 == 2\n=== 1 failed, 3 passed in 0.1s ===\n"
VULN = b"| openssl | CVE-2024-0001 | CRITICAL | fixed | 1.0 | 1.1 | bad thing |\n"
PASSING = b"=== 4 passed in 0.1s ===\n"


@pytest.mark.parametrize(
    "blob, expected",
    [
        ("web-app/1234/test.log", ("web-app", "1234", "test.log")),
        ("raw-logs/web-app/1234/test.log", ("web-app", "1234", "test.log")),
        ("web-app/build-99.log.gz", ("web-app", "build-99", "build-99.log.gz")),
        ("solo.txt", ("default", "solo", "solo.txt")),
        ("team a/feature#7/x?.log", ("team-a", "feature-7", "x?.log")),
        ("a/b/c/deep.log", ("a", "b", "deep.log")),
    ],
)
def test_parse_blob_path(blob, expected):
    assert service.parse_blob_path(blob) == expected


def test_decode_gzip_utf16_and_bom():
    assert service.decode_log(gzip.compress(b"hello"), "x.log.gz") == "hello"
    assert service.decode_log("héllo".encode("utf-16")) == "héllo"
    assert service.decode_log(b"\xef\xbb\xbfhi") == "hi"
    assert service.decode_log(b"bad \xff byte") == "bad � byte"


def test_decode_rejects_oversized(monkeypatch):
    monkeypatch.setattr(service, "MAX_LOG_BYTES", 10)
    with pytest.raises(service.LogTooLargeError):
        service.decode_log(b"x" * 11)


def test_process_blob_is_idempotent(local_store):
    a = service.process_blob("web/1/test.log", FAILING, local_store)
    b = service.process_blob("web/1/test.log", FAILING, local_store)
    assert a["id"] == b["id"] == "1-test.log"
    assert len(local_store.query(ReportQuery())) == 1
    stored = local_store.get("web", "1-test.log")
    assert stored["status"] == "failed" and stored["tests"]["failed"] == 1


def test_report_document_shape(local_store):
    doc = service.process_blob("web/1/test.log", FAILING, local_store)
    assert doc["type"] == "logReport" and doc["pipeline"] == "web" and doc["build_id"] == "1"
    assert doc["top_finding"] == "tests/test_a.py::test_x failed"
    json.dumps(doc)  # serializable for Cosmos


def test_fit_document_shrinks_huge_reports():
    text = "\n".join(f"FAILED tests/t.py::test_{i} - " + "x" * 400 for i in range(300))
    doc = service.analyze_text(text)
    assert len(json.dumps(doc)) <= service.MAX_DOC_BYTES


def _seed(store):
    service.process_blob("web/1/a.log", FAILING, store)
    service.process_blob("web/2/a.log", PASSING, store)
    service.process_blob("api/7/scan.log", VULN, store)
    service.process_blob("api/8/scan.log", VULN, store)


def test_local_store_queries(local_store):
    _seed(local_store)
    ids = lambda q: sorted(f"{d['pipeline']}/{d['build_id']}" for d in local_store.query(q))  # noqa: E731
    assert ids(ReportQuery()) == ["api/7", "api/8", "web/1", "web/2"]
    assert ids(ReportQuery(pipeline="web")) == ["web/1", "web/2"]
    assert ids(ReportQuery(status="passed")) == ["web/2"]
    assert ids(ReportQuery(min_severity="critical")) == ["api/7", "api/8"]
    assert ids(ReportQuery(category="test_failure")) == ["web/1"]
    assert ids(ReportQuery(q="openssl")) == ["api/7", "api/8"]
    assert ids(ReportQuery(q="TEST_X")) == ["web/1"]  # case-insensitive
    assert len(local_store.query(ReportQuery(limit=1))) == 1


def test_failures_and_overview(local_store):
    _seed(local_store)
    failures = service.list_failures(local_store, ReportQuery(min_severity="high"))
    assert {f["pipeline"] for f in failures} == {"web", "api"}
    assert all(f["severity"] in ("critical", "high") for f in failures)

    o = service.overview(local_store, ReportQuery())
    assert o["report_count"] == 4
    assert o["by_status"] == {"failed": 3, "passed": 1}
    top = o["recurring"][0]
    assert top["build_count"] == 2 and "CVE-2024-0001" in top["title"] and top["pipelines"] == ["api"]

    same = service.list_failures(local_store, ReportQuery(fingerprint=top["fingerprint"]))
    assert {f["build_id"] for f in same} == {"7", "8"}


def test_cosmos_sql_is_parameterized():
    sql, params = build_cosmos_sql(ReportQuery(pipeline="web", status="failed", min_severity="high",
                                               category="security", q="'; DROP --", fingerprint="abc", limit=9999))
    assert "DROP" not in sql
    values = {p["name"]: p["value"] for p in params}
    assert values["@q"] == "'; DROP --" and values["@sevs"] == ["critical", "high"] and values["@limit"] == 500
    assert "EXISTS(SELECT VALUE f FROM f IN c.findings WHERE" in sql
    assert sql.endswith("ORDER BY c.processed_at DESC OFFSET 0 LIMIT @limit")


def test_cosmos_sql_without_finding_filters_has_no_exists():
    sql, _ = build_cosmos_sql(ReportQuery())
    assert "EXISTS" not in sql and "c.type = 'logReport'" in sql


class FakeContainer:
    def __init__(self):
        self.items, self.calls = {}, []

    def upsert_item(self, item):
        self.items[(item["pipeline"], item["id"])] = {**item, "_etag": "x"}

    def read_item(self, item, partition_key):
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        try:
            return self.items[(partition_key, item)]
        except KeyError:
            raise CosmosResourceNotFoundError(message="nope") from None

    def query_items(self, **kwargs):
        self.calls.append(kwargs)
        return list(self.items.values())


def test_cosmos_store_with_fake_container():
    c = FakeContainer()
    store = CosmosReportStore(c)
    service.process_blob("web/1/a.log", FAILING, store)
    assert store.get("web", "1-a.log")["status"] == "failed"
    assert "_etag" not in store.get("web", "1-a.log")
    assert store.get("web", "missing") is None
    store.query(ReportQuery(pipeline="web"))
    assert c.calls[-1]["partition_key"] == "web"
    store.query(ReportQuery())
    assert c.calls[-1]["enable_cross_partition_query"] is True


def test_get_store_selects_backend(monkeypatch, tmp_path):
    set_store(None)
    monkeypatch.delenv("COSMOS_ENDPOINT", raising=False)
    monkeypatch.delenv("COSMOS_CONNECTION_STRING", raising=False)
    monkeypatch.setenv("LOGPULSE_STORE", "")
    monkeypatch.setenv("LOGPULSE_LOCAL_DB", str(tmp_path))
    assert type(get_store()).__name__ == "LocalReportStore"
    set_store(None)
