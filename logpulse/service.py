"""Use cases: process an uploaded log, query reports, build dashboard stats.

``function_app.py`` (Azure) and ``devserver.py`` (local) are thin adapters
around these functions.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from .models import SEVERITY_RANK, LogReport
from .parser import parse_log
from .store import ReportQuery, ReportStore, finding_matches

log = logging.getLogger(__name__)

MAX_LOG_BYTES = int(os.getenv("LOGPULSE_MAX_LOG_BYTES", str(100 * 1024 * 1024)))
MAX_DOC_BYTES = 1_800_000  # Cosmos DB items are capped at 2 MB; leave headroom
_ID_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


class LogTooLargeError(ValueError):
    pass


def safe_id(value: str) -> str:
    """Cosmos ids may not contain / \\ ? #. Keep ids readable and deterministic."""
    return _ID_UNSAFE.sub("-", value).strip("-")[:200] or "log"


def parse_blob_path(blob_name: str) -> tuple[str, str, str]:
    """Get (pipeline, build_id, file name) from a blob path inside the ``raw-logs`` container.

    Naming convention::

        <pipeline>/<build_id>/<file>.log   ->  ("web-app", "1234", "test.log")
        <pipeline>/<file>.log              ->  ("web-app", "<file>", "<file>.log")
        <file>.log                         ->  ("default", "<file>", "<file>.log")
    """
    parts = [p for p in PurePosixPath(blob_name.replace("\\", "/")).parts if p not in ("/", "")]
    if parts and parts[0] == "raw-logs":  # tolerate the container name being included
        parts = parts[1:]
    filename = parts[-1] if parts else "log"
    stem = filename
    for suffix in (".gz", ".log", ".txt"):
        stem = stem.removesuffix(suffix)
    if len(parts) >= 3:
        return safe_id(parts[0]), safe_id(parts[1]), filename
    if len(parts) == 2:
        return safe_id(parts[0]), safe_id(stem), filename
    return "default", safe_id(stem), filename


def decode_log(data: bytes, name: str = "") -> str:
    """Bytes to text. Handles gzip, UTF-8 (with or without BOM) and UTF-16 logs (common from Windows agents)."""
    if name.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    if len(data) > MAX_LOG_BYTES:
        raise LogTooLargeError(f"log is {len(data)} bytes; limit is {MAX_LOG_BYTES}")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _fit_document(doc: dict[str, Any]) -> dict[str, Any]:
    """Shrink a report until it fits in one Cosmos DB item."""
    size = len(json.dumps(doc))
    if size <= MAX_DOC_BYTES:
        return doc
    for f in doc["findings"]:  # contexts take the most space; trim them first
        f["context"] = f.get("context", [])[:3]
    while len(json.dumps(doc)) > MAX_DOC_BYTES and len(doc["findings"]) > 10:
        doc["findings"] = doc["findings"][: int(len(doc["findings"]) * 0.75)]
        doc["findings_truncated"] = True
    return doc


def analyze_text(
    text: str,
    *,
    pipeline: str = "default",
    build_id: str = "local",
    source_blob: str = "",
    size_bytes: int | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    result = parse_log(text)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

    filename = PurePosixPath(source_blob).name if source_blob else "log"
    report = LogReport(
        id=safe_id(f"{build_id}-{filename}"),
        pipeline=pipeline,
        build_id=build_id,
        source_blob=source_blob,
        status=result.status,
        ci_platform=result.ci_platform,
        detected_tools=result.detected_tools,
        line_count=result.line_count,
        size_bytes=size_bytes if size_bytes is not None else len(text.encode("utf-8", errors="replace")),
        processed_at=datetime.now(UTC).isoformat(timespec="seconds"),
        duration_ms=elapsed_ms,
        severity_counts=result.severity_counts,
        category_counts=result.category_counts,
        tests=result.tests.to_dict(),
        findings=[f.to_dict() for f in result.findings],
        top_finding=result.findings[0].title if result.findings else None,
        findings_truncated=result.truncated,
    )
    return _fit_document(report.to_dict())


def process_blob(blob_name: str, data: bytes, store: ReportStore) -> dict[str, Any]:
    """The blob-trigger use case: decode, parse, store.

    Idempotent: the document id comes from the blob path, so if a trigger fires
    twice for the same blob (blob triggers are at-least-once), the second run
    overwrites the first instead of creating a duplicate.
    """
    pipeline, build_id, _ = parse_blob_path(blob_name)
    text = decode_log(data, blob_name)
    report = analyze_text(text, pipeline=pipeline, build_id=build_id, source_blob=blob_name, size_bytes=len(data))
    store.upsert(report)
    log.info(
        "Processed %s: status=%s findings=%d (%s) in %.1f ms",
        blob_name, report["status"], len(report["findings"]), report["severity_counts"], report["duration_ms"],
    )
    return report


# --- Read side --------------------------------------------------------------

SUMMARY_FIELDS = (
    "id", "pipeline", "build_id", "source_blob", "status", "ci_platform", "detected_tools", "line_count",
    "size_bytes", "processed_at", "duration_ms", "severity_counts", "category_counts", "tests", "top_finding",
    "findings_truncated",
)


def summarize(doc: dict[str, Any]) -> dict[str, Any]:
    out = {k: doc.get(k) for k in SUMMARY_FIELDS}
    out["finding_count"] = len(doc.get("findings", []))
    return out


def list_reports(store: ReportStore, query: ReportQuery) -> list[dict[str, Any]]:
    return [summarize(d) for d in store.query(query)]


def list_failures(store: ReportStore, query: ReportQuery) -> list[dict[str, Any]]:
    """Every finding that matches the query, across reports, newest first, worst first."""
    out = []
    for doc in store.query(ReportQuery(**{**query.__dict__, "limit": 500})):
        for f in doc.get("findings", []):
            if finding_matches(f, query):
                out.append({
                    **f, "report_id": doc["id"], "pipeline": doc["pipeline"], "build_id": doc["build_id"],
                    "processed_at": doc["processed_at"],
                })
    out.sort(key=lambda f: (f["processed_at"], SEVERITY_RANK.get(f["severity"], 0)), reverse=True)
    return out[: query.limit]


def overview(store: ReportStore, query: ReportQuery) -> dict[str, Any]:
    """Dashboard numbers: status totals, severity totals, failures per pipeline, recurring problems."""
    docs = store.query(ReportQuery(**{**query.__dict__, "limit": 500}))
    by_status = Counter(d["status"] for d in docs)
    severity = Counter()
    pipelines: dict[str, Counter] = defaultdict(Counter)
    recurring: dict[str, dict[str, Any]] = {}

    for d in docs:
        pipelines[d["pipeline"]][d["status"]] += 1
        for sev, n in d.get("severity_counts", {}).items():
            severity[sev] += n
        for f in d.get("findings", []):
            if SEVERITY_RANK.get(f["severity"], 0) < SEVERITY_RANK["medium"]:
                continue
            entry = recurring.setdefault(f["fingerprint"], {
                "fingerprint": f["fingerprint"], "title": f["title"], "category": f["category"],
                "severity": f["severity"], "builds": set(), "pipelines": set(), "last_seen": d["processed_at"],
            })
            entry["builds"].add(f"{d['pipeline']}#{d['build_id']}")
            entry["pipelines"].add(d["pipeline"])
            entry["last_seen"] = max(entry["last_seen"], d["processed_at"])

    top = sorted(recurring.values(), key=lambda e: (len(e["builds"]), SEVERITY_RANK[e["severity"]]), reverse=True)[:10]
    for e in top:
        e["build_count"] = len(e.pop("builds"))
        e["pipelines"] = sorted(e["pipelines"])

    return {
        "report_count": len(docs),
        "by_status": dict(by_status),
        "by_severity": dict(severity),
        "by_pipeline": {p: dict(c) for p, c in sorted(pipelines.items())},
        "recurring": top,
    }
