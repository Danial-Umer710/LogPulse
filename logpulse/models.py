"""Data model for LogPulse reports.

A raw CI/CD log becomes one ``LogReport`` that holds many ``Finding`` objects.
The report is stored as a single JSON document in Cosmos DB, partitioned by
``pipeline``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.value]

    @classmethod
    def parse(cls, value: str) -> Severity:
        v = value.strip().lower()
        aliases = {"moderate": "medium", "warning": "low", "warn": "low", "error": "high", "unknown": "medium"}
        return cls(aliases.get(v, v))


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Category(str, Enum):
    TEST_FAILURE = "test_failure"
    BUILD_ERROR = "build_error"
    EXCEPTION = "exception"
    SECURITY = "security"
    SECRET_LEAK = "secret_leak"
    INFRASTRUCTURE = "infrastructure"
    CI_ERROR = "ci_error"
    WARNING = "warning"


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    line: int
    source: str
    message: str = ""
    test_name: str | None = None
    file: str | None = None
    file_line: int | None = None
    identifier: str | None = None  # e.g. CVE id, error code, rule id
    package: str | None = None
    context: list[str] = field(default_factory=list)
    fingerprint: str = ""
    occurrences: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", [])}


@dataclass
class TestStats:
    total: int | None = None
    passed: int | None = None
    failed: int | None = None
    errors: int | None = None
    skipped: int | None = None

    def merge(self, other: TestStats) -> None:
        """Add another framework's counts onto this one (multi-suite logs)."""
        for name in ("total", "passed", "failed", "errors", "skipped"):
            theirs = getattr(other, name)
            if theirs is None:
                continue
            mine = getattr(self, name)
            setattr(self, name, theirs if mine is None else mine + theirs)

    def is_empty(self) -> bool:
        return all(getattr(self, n) is None for n in ("total", "passed", "failed", "errors", "skipped"))

    def to_dict(self) -> dict[str, int]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class LogReport:
    id: str
    pipeline: str
    build_id: str
    source_blob: str
    status: str  # failed | unstable | passed
    ci_platform: str
    detected_tools: list[str]
    line_count: int
    size_bytes: int
    processed_at: str
    duration_ms: float
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    tests: dict[str, int]
    findings: list[dict[str, Any]]
    top_finding: str | None = None
    findings_truncated: bool = False
    type: str = "logReport"
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
