"""Azure Functions entry point (Python v2 programming model).

Triggers:
  * ``ingest_log``: Event Grid based blob trigger on ``raw-logs/{name}``.
    Parses each uploaded log and upserts a report into Cosmos DB.
  * ``analyze``: POST /api/analyze. Parses a log sent in the request body.
    Needs a function key.
  * ``api``: GET /api/{health|reports|failures|overview|dashboard}. Read-only
    query API and dashboard.

The logic lives in the ``logpulse`` package, so it can run and be tested
without Azure.
"""

from __future__ import annotations

import logging

import azure.functions as func

from logpulse import api, service
from logpulse.store import get_store

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


# source=EVENT_GRID: Blob Storage pushes a BlobCreated event and the function
# runs within seconds. The older polling trigger can lag by minutes, and the
# Flex Consumption plan requires Event Grid.
@app.blob_trigger(arg_name="blob", path="raw-logs/{name}", connection="AzureWebJobsStorage", source=func.BlobSource.EVENT_GRID)
def ingest_log(blob: func.InputStream) -> None:
    name = blob.name or "unknown.log"
    logging.info("New log blob: %s (%s bytes)", name, blob.length)
    try:
        report = service.process_blob(name, blob.read(), get_store())
    except service.LogTooLargeError as exc:
        # Retrying will never help, so log the error and stop instead of
        # filling the poison queue.
        logging.error("Skipping %s: %s", name, exc)
        return
    logging.info("Stored report %s/%s status=%s", report["pipeline"], report["id"], report["status"])


def _to_http(resp: api.ApiResponse) -> func.HttpResponse:
    return func.HttpResponse(resp.encoded(), status_code=resp.status, mimetype=resp.content_type.split(";")[0],
                             headers=resp.headers, charset="utf-8")


@app.route(route="analyze", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def analyze(req: func.HttpRequest) -> func.HttpResponse:
    return _to_http(api.route("POST", "analyze", dict(req.params), req.get_body(), get_store()))


@app.route(route="{*path}", methods=["GET"])
def http_api(req: func.HttpRequest) -> func.HttpResponse:
    path = req.route_params.get("path", "")
    return _to_http(api.route("GET", path, dict(req.params), b"", get_store()))
