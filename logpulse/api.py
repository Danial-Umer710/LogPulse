"""HTTP API logic, separate from the web framework.

``function_app.py`` maps Azure Functions HTTP triggers onto ``route()``, and
``devserver.py`` maps Python's built-in ``http.server`` onto the same
function. The same handlers run locally and in Azure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from . import service
from .models import SEVERITY_RANK, Category
from .store import ReportQuery, ReportStore

STATUSES = {"failed", "unstable", "passed"}
CATEGORIES = {c.value for c in Category}


@dataclass
class ApiResponse:
    status: int
    body: Any
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)

    def encoded(self) -> bytes:
        if isinstance(self.body, bytes):
            return self.body
        if isinstance(self.body, str):
            return self.body.encode("utf-8")
        return json.dumps(self.body, indent=2, default=str).encode("utf-8")


class BadRequest(ValueError):
    pass


def parse_query(params: dict[str, str]) -> ReportQuery:
    def pick(name: str, allowed: set[str] | None = None) -> str | None:
        value = (params.get(name) or "").strip()
        if not value:
            return None
        if allowed is not None and value not in allowed:
            raise BadRequest(f"'{name}' must be one of: {', '.join(sorted(allowed))}")
        return value

    try:
        limit = int(params.get("limit") or 50)
    except ValueError as exc:
        raise BadRequest("'limit' must be an integer") from exc
    if not 1 <= limit <= 500:
        raise BadRequest("'limit' must be between 1 and 500")

    return ReportQuery(
        pipeline=pick("pipeline"),
        status=pick("status", STATUSES),
        min_severity=pick("min_severity", set(SEVERITY_RANK)),
        category=pick("category", CATEGORIES),
        q=pick("q"),
        fingerprint=pick("fingerprint"),
        since=pick("since"),
        limit=limit,
    )


def _dashboard_html() -> str:
    return resources.files("logpulse").joinpath("static/dashboard.html").read_text(encoding="utf-8")


def route(method: str, path: str, params: dict[str, str], body: bytes, store: ReportStore) -> ApiResponse:
    """Dispatch one request. ``path`` is relative to /api, e.g. ``reports/web-app/42-test.log``."""
    method = method.upper()
    parts = [p for p in path.strip("/").split("/") if p]
    try:
        if not parts or parts == ["dashboard"]:
            return ApiResponse(200, _dashboard_html(), "text/html; charset=utf-8")
        head = parts[0]

        if head == "health" and method == "GET":
            return ApiResponse(200, {"status": "ok", "store": type(store).__name__})

        if head == "reports" and method == "GET":
            if len(parts) == 3:
                doc = store.get(parts[1], parts[2])
                return ApiResponse(200, doc) if doc else ApiResponse(404, {"error": "report not found"})
            if len(parts) == 1:
                q = parse_query(params)
                items = service.list_reports(store, q)
                return ApiResponse(200, {"count": len(items), "items": items})

        if head == "failures" and method == "GET" and len(parts) == 1:
            q = parse_query(params)
            items = service.list_failures(store, q)
            return ApiResponse(200, {"count": len(items), "items": items})

        if head == "overview" and method == "GET" and len(parts) == 1:
            return ApiResponse(200, service.overview(store, parse_query(params)))

        if head == "analyze" and method == "POST" and len(parts) == 1:
            if not body:
                raise BadRequest("request body must contain the raw log text")
            try:
                text = service.decode_log(body)
            except service.LogTooLargeError as exc:
                return ApiResponse(413, {"error": str(exc)})
            pipeline = service.safe_id(params.get("pipeline") or "adhoc")
            build_id = service.safe_id(params.get("build") or "manual")
            name = service.safe_id(params.get("name") or "upload.log")
            report = service.analyze_text(
                text, pipeline=pipeline, build_id=build_id,
                source_blob=f"{pipeline}/{build_id}/{name}", size_bytes=len(body),
            )
            if params.get("store", "").lower() in ("1", "true", "yes"):
                store.upsert(report)
                return ApiResponse(201, report)
            return ApiResponse(200, report)

        return ApiResponse(404, {"error": f"no route for {method} /api/{path.strip('/')}"})
    except BadRequest as exc:
        return ApiResponse(400, {"error": str(exc)})
