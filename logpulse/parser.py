"""Turn a raw CI/CD log into structured findings.

The parser is pure Python with no Azure dependency, so the Azure Function,
the local dev server, the CLI and the unit tests all run the same code.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field

from .models import SEVERITY_RANK, Category, Finding, Severity, TestStats
from .rules import RULE_GROUPS, STATE_RULES, Ctx, scan_secrets
from .stats import extract_test_stats

MAX_LINE_CHARS = 2000
CONTEXT_LINE_CHARS = 300

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
_TIMESTAMP = re.compile(
    r"^(?:\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?\s?|\[\d{2}:\d{2}:\d{2}(?:\.\d+)?\]\s)"
)
_GITLAB_SECTION = re.compile(r"section_(?:start|end):\d+:[\w.-]+(?:\[[^\]]*\])?")

_PLATFORM_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("github-actions", re.compile(r"##\[group\]|^Run actions/|GITHUB_ACTIONS|Current runner version:", re.M)),
    ("azure-pipelines", re.compile(r"##\[section\]|^Agent name:|Azure Pipelines|##vso\[", re.M)),
    ("gitlab-ci", re.compile(r"Running with gitlab-runner|section_start:\d+|^\$ .*\n.*Job succeeded", re.M)),
    ("jenkins", re.compile(r"^Started by (?:user|timer|an SCM change|upstream)|^\[Pipeline\]|^Finished: (?:SUCCESS|FAILURE)", re.M)),
    ("circleci", re.compile(r"CIRCLECI|circleci-agent", re.M)),
]


@dataclass
class ParseResult:
    findings: list[Finding]
    tests: TestStats
    ci_platform: str
    detected_tools: list[str]
    line_count: int
    truncated: bool = False
    severity_counts: dict[str, int] = field(default_factory=dict)
    category_counts: dict[str, int] = field(default_factory=dict)

    @property
    def status(self) -> str:
        """failed = anything high/critical; unstable = medium; passed otherwise."""
        worst = max((SEVERITY_RANK[f.severity] for f in self.findings), default=-1)
        failed_tests = (self.tests.failed or 0) + (self.tests.errors or 0)
        if worst >= SEVERITY_RANK["high"] or failed_tests > 0:
            return "failed"
        if worst >= SEVERITY_RANK["medium"]:
            return "unstable"
        return "passed"


def clean_line(raw: str) -> str:
    """Remove ANSI colours, runner timestamps, GitLab section markers and progress-bar overwrites."""
    line = raw.rstrip("\n")
    if "\r" in line:
        # Progress bars redraw with \r: only the final redraw is visible.
        parts = [p for p in line.split("\r") if p.strip()]
        line = parts[-1] if parts else ""
    line = _ANSI.sub("", line)
    line = _GITLAB_SECTION.sub("", line)
    line = _TIMESTAMP.sub("", line, count=1)
    return line[:MAX_LINE_CHARS].rstrip()


def detect_platform(text: str) -> str:
    head = text[:200_000]
    for name, marker in _PLATFORM_MARKERS:
        if marker.search(head):
            return name
    return "unknown"


_WORKSPACE_PREFIX = re.compile(
    r"^(?:/home/runner/work/[^/]+/[^/]+/|/home/vsts/work/\d+/s/|/__w/[^/]+/[^/]+/|/var/lib/jenkins/workspace/[^/]+/|"
    r"/builds/[^/]+/[^/]+/|[A-Za-z]:\\a\\[^\\]+\\[^\\]+\\|/github/workspace/|\./)"
)


def relative_path(path: str) -> str:
    """Strip CI workspace prefixes so the same source file has the same path on every runner."""
    return _WORKSPACE_PREFIX.sub("", path)


_NORMALIZE_NUMBERS = re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b|\d+(?:\.\d+)*")
_NORMALIZE_SPACE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Mask numbers, hashes and durations in free text, so ``timed out after 31s``
    in build 41 and ``timed out after 29s`` in build 42 are recognised as the same problem."""
    return _NORMALIZE_SPACE.sub(" ", _NORMALIZE_NUMBERS.sub("#", text.lower())).strip()


def fingerprint(category: str, source: str, key: str) -> str:
    """A stable id for "the same problem", even across builds, so you can ask "which builds hit this error?"."""
    return hashlib.sha1(f"{category}|{source}|{key}".encode()).hexdigest()[:16]


def finding_key(raw: dict) -> str:
    """Exact identifiers (CVE ids, test names, rule ids) are kept as they are:
    CVE-2024-45491 and CVE-2024-45492 are different problems. Free-text titles
    are normalized."""
    exact = [str(raw[k]) for k in ("package", "identifier", "test_name") if raw.get(k)]
    if raw.get("file") and raw["category"] == Category.BUILD_ERROR.value:
        exact.append(f"{raw['file']}:{raw.get('file_line')}")
    if not raw.get("identifier") and not raw.get("test_name"):
        exact.append(normalize_text(raw["title"]))
    return "|".join(exact)


def _context(lines: list[str], i: int, before: int, after: int) -> list[str]:
    start, end = max(0, i - before), min(len(lines), i + after + 1)
    return [ln[:CONTEXT_LINE_CHARS] for ln in lines[start:end]]


def parse_log(
    text: str,
    *,
    max_findings: int = 300,
    context_before: int = 2,
    context_after: int = 3,
) -> ParseResult:
    raw_lines = text.splitlines()
    lines = [clean_line(r) for r in raw_lines]

    found: dict[str, Finding] = {}
    order: list[str] = []
    state: dict = {}

    def add(raw: dict, i: int) -> None:
        if raw.get("file"):
            raw["file"] = relative_path(raw["file"])
        fp =fingerprint(raw["category"], raw["source"], finding_key(raw))
        if fp in found:
            found[fp].occurrences += 1
            return
        ctx_lines = raw.pop("context", None) or _context(lines, i, context_before, context_after)
        extra = {k: raw.pop(k) for k in list(raw) if k not in Finding.__dataclass_fields__}
        f = Finding(line=i + 1, context=ctx_lines, fingerprint=fp, **raw)
        if extra:
            # Rule-specific fields (e.g. installed/fixed versions) go in the message.
            details = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in extra.items())
            f.message = f"{f.message} ({details})" if f.message else details
        found[fp] = f
        order.append(fp)

    # Pass 1: secrets. Redact them before any rule or context capture sees the line.
    for i, line in enumerate(lines):
        kinds, redacted = scan_secrets(line)
        if kinds:
            lines[i] = redacted
            for kind in kinds:
                add({
                    "category": Category.SECRET_LEAK.value, "severity": Severity.CRITICAL.value,
                    "title": f"Possible {kind} exposed in log", "source": "secret-scanner",
                    "identifier": kind, "message": redacted.strip()[:CONTEXT_LINE_CHARS],
                }, i)

    # Pass 2: detection rules.
    for i, line in enumerate(lines):
        if not line.strip():
            if state.get("npm_audit") and i + 1 < len(lines) and not lines[i + 1].strip():
                state["npm_audit"] = False  # two blank lines end the npm audit block
            continue
        ctx = Ctx(lines=lines, i=i, state=state)
        stripped = line.strip()
        for r in STATE_RULES:
            m = r.pattern.search(stripped)
            if m:
                r.build(m, ctx)
        if re.match(r"^\d+ vulnerabilit(?:y|ies)\b|^found \d+ vulnerabilit", stripped):
            state["npm_audit"] = False
        for group in RULE_GROUPS.values():
            for r in group:
                # Rules see the raw (cleaned) line. Indentation matters: an indented
                # "Error: ..." inside a Jest failure belongs to that test and must not
                # also be reported as a top-level error. Rules that should tolerate
                # indentation include ``^\s*`` in their own pattern.
                m = r.pattern.search(line)
                if not m:
                    continue
                result = r.build(m, ctx)
                if result is not None:
                    add(result, i)
                    break

    findings = [found[fp] for fp in order]
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.line))
    truncated = len(findings) > max_findings
    findings = findings[:max_findings]

    return ParseResult(
        findings=findings,
        tests=extract_test_stats(lines),
        ci_platform=detect_platform(text),
        detected_tools=sorted({f.source for f in findings} - {"generic", "ci-runner", "runner", "secret-scanner", "scanner", "security-heuristic"}),
        line_count=len(raw_lines),
        truncated=truncated,
        severity_counts=dict(Counter(f.severity for f in findings)),
        category_counts=dict(Counter(f.category for f in findings)),
    )
