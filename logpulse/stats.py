"""Read pass/fail totals from the summary lines that test runners print."""

from __future__ import annotations

import re

from .models import TestStats

_PYTEST = re.compile(r"^=+\s*(?P<body>.*?\b(?:passed|failed|error|errors)\b.*?)\s+in\s+[\d.]+s(?:\s+\([\d:]+\))?\s*=+$")
_PYTEST_PART = re.compile(r"(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed|deselected)")

_JEST = re.compile(r"^Tests:\s+(?P<body>.+?total)\s*$")
_JEST_PART = re.compile(r"(\d+)\s+(passed|failed|skipped|todo|total)")

_MAVEN = re.compile(r"^\[(?:INFO|WARNING|ERROR)\]\s+Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)\s*$")
_GRADLE = re.compile(r"(\d+)\s+tests? completed,\s+(\d+)\s+failed(?:,\s+(\d+)\s+skipped)?")
_DOTNET = re.compile(r"^(?:Failed|Passed)!\s+-\s+Failed:\s+(\d+),\s+Passed:\s+(\d+),\s+Skipped:\s+(\d+),\s+Total:\s+(\d+)")
_UNITTEST_RAN = re.compile(r"^Ran (\d+) tests? in [\d.]+s")
_UNITTEST_RESULT = re.compile(r"^FAILED \((?P<body>[^)]*)\)\s*$")
_GO_RESULT = re.compile(r"^\s*--- (PASS|FAIL|SKIP):")


def extract_test_stats(lines: list[str]) -> TestStats:
    """Combine the summary lines of every test runner found in ``lines``.

    A framework's last summary wins (Maven prints per-class totals before the
    aggregate). Different frameworks in one log, e.g. backend pytest plus
    frontend Jest, are added together.
    """
    per_framework: dict[str, TestStats] = {}
    go_counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    unittest_total: int | None = None

    for line in lines:
        s = line.strip()

        if m := _PYTEST.match(s):
            parts = {k.rstrip("s") if k.startswith("error") else k: int(n) for n, k in _PYTEST_PART.findall(m["body"])}
            passed, failed, err, skipped = (parts.get(k, 0) for k in ("passed", "failed", "error", "skipped"))
            per_framework["pytest"] = TestStats(
                total=passed + failed + err + skipped + parts.get("xfailed", 0) + parts.get("xpassed", 0),
                passed=passed, failed=failed, errors=err, skipped=skipped,
            )
        elif m := _JEST.match(s):
            parts = {k: int(n) for n, k in _JEST_PART.findall(m["body"])}
            per_framework["jest"] = TestStats(
                total=parts.get("total"), passed=parts.get("passed", 0), failed=parts.get("failed", 0),
                skipped=parts.get("skipped", 0) + parts.get("todo", 0), errors=0,
            )
        elif m := _MAVEN.match(s):
            run, fail, err, skip = map(int, m.groups())
            per_framework["maven"] = TestStats(total=run, failed=fail, errors=err, skipped=skip, passed=run - fail - err - skip)
        elif m := _GRADLE.search(s):
            run, fail, skip = int(m[1]), int(m[2]), int(m[3] or 0)
            per_framework["gradle"] = TestStats(total=run, failed=fail, skipped=skip, errors=0, passed=run - fail - skip)
        elif m := _DOTNET.match(s):
            fail, passed, skip, total = map(int, m.groups())
            per_framework["dotnet"] = TestStats(total=total, failed=fail, passed=passed, skipped=skip, errors=0)
        elif m := _UNITTEST_RAN.match(s):
            unittest_total = int(m[1])
            per_framework["unittest"] = TestStats(total=unittest_total, passed=unittest_total, failed=0, errors=0, skipped=0)
        elif (m := _UNITTEST_RESULT.match(s)) and unittest_total is not None:
            parts = dict(re.findall(r"(\w+)=(\d+)", m["body"]))
            fail, err, skip = int(parts.get("failures", 0)), int(parts.get("errors", 0)), int(parts.get("skipped", 0))
            per_framework["unittest"] = TestStats(
                total=unittest_total, failed=fail, errors=err, skipped=skip, passed=unittest_total - fail - err - skip
            )
        elif m := _GO_RESULT.match(line):
            if not line.startswith("    "):  # ignore sub-test lines; count top-level tests only
                go_counts[m[1]] += 1

    if any(go_counts.values()):
        per_framework["go"] = TestStats(
            total=sum(go_counts.values()), passed=go_counts["PASS"], failed=go_counts["FAIL"], skipped=go_counts["SKIP"], errors=0
        )

    combined = TestStats()
    for stats in per_framework.values():
        combined.merge(stats)
    return combined
