"""Storage backends for log reports.

* ``CosmosReportStore`` is used in Azure. The container is partitioned by ``/pipeline``.
* ``LocalReportStore`` writes JSON files to disk for local development and
  tests. It needs no Azure account and supports the same queries.

``get_store()`` picks a backend from environment variables.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import SEVERITY_RANK

log = logging.getLogger(__name__)


@dataclass
class ReportQuery:
    pipeline: str | None = None
    status: str | None = None
    min_severity: str | None = None
    category: str | None = None
    q: str | None = None  # free-text search over finding title / message / test name / package / id
    fingerprint: str | None = None
    since: str | None = None  # ISO-8601 lower bound on processed_at
    limit: int = 50

    def severities(self) -> list[str] | None:
        if not self.min_severity:
            return None
        floor = SEVERITY_RANK[self.min_severity]
        return [s for s, r in SEVERITY_RANK.items() if r >= floor]

    @property
    def filters_findings(self) -> bool:
        return any((self.min_severity, self.category, self.q, self.fingerprint))


TEXT_FIELDS = ("title", "message", "test_name", "package", "identifier", "file")


def finding_matches(f: dict[str, Any], query: ReportQuery) -> bool:
    """Python version of the finding filter (the Cosmos backend has the SQL version)."""
    sevs = query.severities()
    if sevs is not None and f.get("severity") not in sevs:
        return False
    if query.category and f.get("category") != query.category:
        return False
    if query.fingerprint and f.get("fingerprint") != query.fingerprint:
        return False
    if query.q:
        needle = query.q.lower()
        if not any(needle in str(f.get(k, "")).lower() for k in TEXT_FIELDS):
            return False
    return True


def report_matches(doc: dict[str, Any], query: ReportQuery) -> bool:
    if query.pipeline and doc.get("pipeline") != query.pipeline:
        return False
    if query.status and doc.get("status") != query.status:
        return False
    if query.since and doc.get("processed_at", "") < query.since:
        return False
    if query.filters_findings and not any(finding_matches(f, query) for f in doc.get("findings", [])):
        return False
    return True


class ReportStore(Protocol):
    def upsert(self, report: dict[str, Any]) -> None: ...
    def get(self, pipeline: str, report_id: str) -> dict[str, Any] | None: ...
    def query(self, query: ReportQuery) -> list[dict[str, Any]]: ...
    def delete(self, pipeline: str, report_id: str) -> bool: ...


# ---------------------------------------------------------------------------


class LocalReportStore:
    """Stores one JSON file per report at ``<root>/<pipeline>/<id>.json``."""

    def __init__(self, root: str | os.PathLike[str] = ".localdb") -> None:
        self.root = Path(root)

    def _path(self, pipeline: str, report_id: str) -> Path:
        return self.root / pipeline / f"{report_id}.json"

    def upsert(self, report: dict[str, Any]) -> None:
        path = self._path(report["pipeline"], report["id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
        tmp.replace(path)  # atomic on the same filesystem

    def get(self, pipeline: str, report_id: str) -> dict[str, Any] | None:
        path = self._path(pipeline, report_id)
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def delete(self, pipeline: str, report_id: str) -> bool:
        path = self._path(pipeline, report_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def query(self, query: ReportQuery) -> list[dict[str, Any]]:
        if not self.root.exists():
            return []
        pattern = f"{query.pipeline}/*.json" if query.pipeline else "*/*.json"
        docs = []
        for path in self.root.glob(pattern):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                log.warning("Skipping unreadable report file %s", path)
                continue
            if report_matches(doc, query):
                docs.append(doc)
        docs.sort(key=lambda d: d.get("processed_at", ""), reverse=True)
        return docs[: query.limit]


# ---------------------------------------------------------------------------


def build_cosmos_sql(query: ReportQuery) -> tuple[str, list[dict[str, Any]]]:
    """Turn a ``ReportQuery`` into parameterized Cosmos DB SQL (user input never goes into the SQL text)."""
    where = ["c.type = 'logReport'"]
    params: list[dict[str, Any]] = [{"name": "@limit", "value": max(1, min(query.limit, 500))}]

    if query.pipeline:
        where.append("c.pipeline = @pipeline")
        params.append({"name": "@pipeline", "value": query.pipeline})
    if query.status:
        where.append("c.status = @status")
        params.append({"name": "@status", "value": query.status})
    if query.since:
        where.append("c.processed_at >= @since")
        params.append({"name": "@since", "value": query.since})

    f_where = []
    if (sevs := query.severities()) is not None:
        f_where.append("ARRAY_CONTAINS(@sevs, f.severity)")
        params.append({"name": "@sevs", "value": sevs})
    if query.category:
        f_where.append("f.category = @category")
        params.append({"name": "@category", "value": query.category})
    if query.fingerprint:
        f_where.append("f.fingerprint = @fp")
        params.append({"name": "@fp", "value": query.fingerprint})
    if query.q:
        f_where.append("(" + " OR ".join(f"CONTAINS(f.{k}, @q, true)" for k in TEXT_FIELDS) + ")")
        params.append({"name": "@q", "value": query.q})
    if f_where:
        where.append(f"EXISTS(SELECT VALUE f FROM f IN c.findings WHERE {' AND '.join(f_where)})")

    sql = f"SELECT * FROM c WHERE {' AND '.join(where)} ORDER BY c.processed_at DESC OFFSET 0 LIMIT @limit"
    return sql, params


class CosmosReportStore:
    def __init__(self, container: Any) -> None:
        self.container = container

    @classmethod
    def from_env(cls) -> CosmosReportStore:
        from azure.cosmos import CosmosClient, PartitionKey  # imported lazily: local mode needs no SDK

        database = os.getenv("COSMOS_DATABASE", "logpulse")
        container = os.getenv("COSMOS_CONTAINER", "reports")
        conn = os.getenv("COSMOS_CONNECTION_STRING")
        endpoint = os.getenv("COSMOS_ENDPOINT")
        key = os.getenv("COSMOS_KEY")

        if conn:
            client = CosmosClient.from_connection_string(conn)
        elif endpoint and key:
            client = CosmosClient(endpoint, credential=key)
        elif endpoint:
            # Managed identity in Azure, or your `az login` session locally.
            from azure.identity import DefaultAzureCredential

            client = CosmosClient(endpoint, credential=DefaultAzureCredential())
        else:
            raise RuntimeError("Cosmos store selected but COSMOS_CONNECTION_STRING / COSMOS_ENDPOINT is not set")

        if os.getenv("COSMOS_CREATE_IF_MISSING", "").lower() in ("1", "true", "yes"):
            # Only for key-based auth (e.g. the Cosmos emulator). With RBAC, the
            # infrastructure templates create the database and container.
            db = client.create_database_if_not_exists(database)
            return cls(db.create_container_if_not_exists(container, partition_key=PartitionKey(path="/pipeline")))
        return cls(client.get_database_client(database).get_container_client(container))

    def upsert(self, report: dict[str, Any]) -> None:
        self.container.upsert_item(report)

    def get(self, pipeline: str, report_id: str) -> dict[str, Any] | None:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        try:
            return _strip_system_fields(self.container.read_item(item=report_id, partition_key=pipeline))
        except CosmosResourceNotFoundError:
            return None

    def delete(self, pipeline: str, report_id: str) -> bool:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        try:
            self.container.delete_item(item=report_id, partition_key=pipeline)
            return True
        except CosmosResourceNotFoundError:
            return False

    def query(self, query: ReportQuery) -> list[dict[str, Any]]:
        sql, params = build_cosmos_sql(query)
        kwargs: dict[str, Any] = {"query": sql, "parameters": params}
        if query.pipeline:
            kwargs["partition_key"] = query.pipeline  # single-partition query: cheaper
        else:
            kwargs["enable_cross_partition_query"] = True
        return [_strip_system_fields(d) for d in self.container.query_items(**kwargs)]


def _strip_system_fields(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if not k.startswith("_")}


# ---------------------------------------------------------------------------

_store: ReportStore | None = None


def get_store() -> ReportStore:
    """Choose a backend: ``LOGPULSE_STORE=cosmos|local``, or auto-detect from Cosmos settings."""
    global _store
    if _store is None:
        mode = os.getenv("LOGPULSE_STORE", "").lower()
        if not mode:
            mode = "cosmos" if (os.getenv("COSMOS_CONNECTION_STRING") or os.getenv("COSMOS_ENDPOINT")) else "local"
        if mode == "cosmos":
            _store = CosmosReportStore.from_env()
        else:
            _store = LocalReportStore(os.getenv("LOGPULSE_LOCAL_DB", ".localdb"))
        log.info("LogPulse store: %s", type(_store).__name__)
    return _store


def set_store(store: ReportStore | None) -> None:
    """Override the backend (used by tests and the dev server)."""
    global _store
    _store = store
