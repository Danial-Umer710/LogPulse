"""Command-line interface.

    python -m logpulse analyze samples/*.log            # human-readable summary
    python -m logpulse analyze build.log --json         # full report as JSON
    python -m logpulse ingest samples/ --pipeline demo  # parse and save to the store (like the blob trigger)
    python -m logpulse query --min-severity high -q timeout
    python -m logpulse serve                            # local API, dashboard and blob simulator

Exit code of ``analyze``: 0 = passed, 1 = failed, 2 = unstable. A CI job can
run LogPulse on its own output and act on the result.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

from . import service
from .models import SEVERITY_RANK, Category
from .store import ReportQuery, get_store

COLORS = {"critical": "\033[1;35m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[37m"}
STATUS_COLORS = {"failed": "\033[1;31m", "unstable": "\033[1;33m", "passed": "\033[1;32m"}
RESET = "\033[0m"


def _color(enabled: bool, code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def _expand(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        matches = glob.glob(p, recursive=True) or [p]
        for m in matches:
            path = Path(m)
            if path.is_dir():
                files.extend(sorted(f for f in path.rglob("*") if f.is_file()))
            elif path.is_file():
                files.append(path)
            else:
                print(f"warning: {m} not found", file=sys.stderr)
    return files


def print_report(report: dict, color: bool, max_findings: int = 15) -> None:
    status = report["status"]
    tests = report.get("tests") or {}
    print(_color(color, STATUS_COLORS.get(status, ""), f"■ {status.upper()}") +
          f"  {report['source_blob'] or report['id']}  [{report['ci_platform']}]  "
          f"{report['line_count']} lines, {report['duration_ms']} ms")
    if tests:
        print("  tests: " + ", ".join(f"{k}={v}" for k, v in tests.items()))
    if report["severity_counts"]:
        counts = sorted(report["severity_counts"].items(), key=lambda kv: -SEVERITY_RANK[kv[0]])
        print("  findings: " + ", ".join(_color(color, COLORS[s], f"{n} {s}") for s, n in counts))
    for f in report["findings"][:max_findings]:
        sev = _color(color, COLORS[f["severity"]], f"{f['severity']:<8}")
        times = f" ×{f['occurrences']}" if f.get("occurrences", 1) > 1 else ""
        where = f"  ({f['file']}{':' + str(f['file_line']) if f.get('file_line') else ''})" if f.get("file") else ""
        print(f"  {sev} L{f['line']:<5} {f['category']:<15} {f['title'][:110]}{times}{where}")
    extra = len(report["findings"]) - max_findings
    if extra > 0:
        print(f"  … {extra} more (use --json or --all)")
    print()


def cmd_analyze(args: argparse.Namespace) -> int:
    files = _expand(args.paths)
    if not files:
        print("no input files", file=sys.stderr)
        return 64
    color = sys.stdout.isatty() and not args.no_color and os.getenv("NO_COLOR") is None
    reports = []
    for path in files:
        text = service.decode_log(path.read_bytes(), path.name)
        report = service.analyze_text(text, pipeline=args.pipeline, build_id=args.build or path.stem,
                                      source_blob=path.as_posix(), size_bytes=path.stat().st_size)
        reports.append(report)
        if not args.json:
            print_report(report, color, 10_000 if args.all else 15)
    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2))
    statuses = {r["status"] for r in reports}
    return 1 if "failed" in statuses else 2 if "unstable" in statuses else 0


def cmd_ingest(args: argparse.Namespace) -> int:
    store = get_store()
    files = _expand(args.paths)
    for path in files:
        # Without --pipeline, use the last three path parts as <pipeline>/<build>/<file>,
        # the same naming convention the blob trigger uses.
        blob_name = (f"{args.pipeline}/{args.build or path.stem}/{path.name}" if args.pipeline
                     else "/".join(path.parts[-3:]))
        report = service.process_blob(blob_name, path.read_bytes(), store)
        print(f"stored {report['pipeline']}/{report['id']}: {report['status']} ({len(report['findings'])} findings)")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    q = ReportQuery(pipeline=args.pipeline, status=args.status, min_severity=args.min_severity,
                    category=args.category, q=args.q, limit=args.limit)
    store = get_store()
    if args.failures:
        items = service.list_failures(store, q)
        if args.json:
            print(json.dumps(items, indent=2))
        for f in items if not args.json else []:
            print(f"{f['severity']:<8} {f['pipeline']}#{f['build_id']:<10} {f['category']:<15} {f['title'][:100]}")
    else:
        items = service.list_reports(store, q)
        if args.json:
            print(json.dumps(items, indent=2))
        for r in items if not args.json else []:
            print(f"{r['processed_at']}  {r['status']:<9} {r['pipeline']}#{r['build_id']:<10} "
                  f"{r['finding_count']:>3} findings  {(r['top_finding'] or '')[:80]}")
    if not items:
        print("no matches", file=sys.stderr)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .devserver import serve

    serve(args.host, args.port, watch=not args.no_watch)
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252
    p = argparse.ArgumentParser(prog="logpulse", description="Extract test failures and security warnings from CI/CD logs.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="parse log files and print a summary (stores nothing)")
    a.add_argument("paths", nargs="+")
    a.add_argument("--json", action="store_true")
    a.add_argument("--all", action="store_true", help="show every finding")
    a.add_argument("--pipeline", default="local")
    a.add_argument("--build")
    a.add_argument("--no-color", action="store_true")
    a.set_defaults(fn=cmd_analyze)

    i = sub.add_parser("ingest", help="parse and save reports to the store, the same way the blob trigger does")
    i.add_argument("paths", nargs="+")
    i.add_argument("--pipeline", help="pipeline name (default: taken from the path)")
    i.add_argument("--build")
    i.set_defaults(fn=cmd_ingest)

    q = sub.add_parser("query", help="search stored reports")
    q.add_argument("--pipeline")
    q.add_argument("--status", choices=["failed", "unstable", "passed"])
    q.add_argument("--min-severity", choices=list(SEVERITY_RANK))
    q.add_argument("--category", choices=[c.value for c in Category])
    q.add_argument("-q", help="free-text search")
    q.add_argument("--failures", action="store_true", help="list individual findings instead of reports")
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--json", action="store_true")
    q.set_defaults(fn=cmd_query)

    s = sub.add_parser("serve", help="run the local API, dashboard and blob-trigger simulator")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=7071)
    s.add_argument("--no-watch", action="store_true")
    s.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
