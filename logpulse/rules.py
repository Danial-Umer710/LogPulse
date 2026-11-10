"""Detection rules for CI/CD logs.

Each rule is a compiled regex and a ``build`` function. ``build`` turns a
match into a finding dict, or returns ``None`` to reject the match. Rules sit
in independent *groups*. Inside a group the first rule that accepts a line
wins. Groups don't affect each other, so a single line such as
``##[error]... exit code 137`` can report both a CI error and an OOM kill.

To support a new tool, add a rule to the right group. The parser needs no
other changes.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .models import Category as C
from .models import Severity as S

FindingDict = dict[str, Any]


@dataclass
class Ctx:
    """What a rule's ``build`` function can see about the current line."""

    lines: list[str]
    i: int
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def line(self) -> str:
        return self.lines[self.i]

    def after(self, max_lines: int = 3) -> list[str]:
        return self.lines[self.i + 1 : self.i + 1 + max_lines]

    def next_nonempty(self, max_lines: int = 3) -> str | None:
        for candidate in self.after(max_lines):
            if candidate.strip():
                return candidate.strip()
        return None

    def search_after(self, pattern: re.Pattern[str], max_lines: int = 4) -> re.Match[str] | None:
        for candidate in self.after(max_lines):
            m = pattern.search(candidate)
            if m:
                return m
        return None


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    build: Callable[[re.Match[str], Ctx], FindingDict | None]


def rule(name: str, pattern: str, flags: int = 0):
    """Decorator: register ``fn`` as the builder for ``pattern``."""

    def wrap(fn: Callable[[re.Match[str], Ctx], FindingDict | None]) -> Rule:
        return Rule(name=name, pattern=re.compile(pattern, flags), build=fn)

    return wrap


def finding(category: C, severity: S | str, title: str, source: str, **extra: Any) -> FindingDict:
    sev = severity if isinstance(severity, S) else S.parse(severity)
    out: FindingDict = {"category": category.value, "severity": sev.value, "title": title.strip()[:300], "source": source}
    for k, v in extra.items():
        if v not in (None, ""):
            out[k] = v.strip()[:1000] if isinstance(v, str) else v
    return out


def _int(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


# ---------------------------------------------------------------------------
# Secret detection: runs on every line *before* the other rules, and the
# matched value is redacted so it never reaches storage.
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("Azure storage key", re.compile(r"AccountKey=[A-Za-z0-9+/]{80,}={0,2}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "Hard-coded credential",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b"
            r"\s*[=:]\s*['\"]?(?!\*+|\$\{|\$\(|<|%|xxx|redacted|null|none|true|false)([^\s'\"]{8,})"
        ),
    ),
]


def scan_secrets(line: str) -> tuple[list[str], str]:
    """Return (kinds of secrets found, redacted line)."""
    kinds: list[str] = []
    redacted = line
    for kind, pattern in SECRET_PATTERNS:
        if not pattern.search(redacted):
            continue
        kinds.append(kind)
        if kind == "Hard-coded credential":
            redacted = pattern.sub(lambda m: m.group(0).replace(m.group(2), "***REDACTED***"), redacted)
        elif kind == "Private key":
            pass  # the header line itself is not secret; flag it
        else:
            redacted = pattern.sub("***REDACTED***", redacted)
    return kinds, redacted


# ---------------------------------------------------------------------------
# Group 1: security scanners (npm audit, Trivy, Snyk, Bandit, pip-audit ...)
# ---------------------------------------------------------------------------

VULN_ID = r"(?P<vid>CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)"
SEVERITY_WORD = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|MODERATE|LOW|UNKNOWN|Critical|High|Medium|Moderate|Low)\b")


@rule("npm-audit-header", r"^#\s*npm audit report")
def _npm_header(m, ctx):
    ctx.state["npm_audit"] = True
    return None


@rule("npm-audit-package", r"^(?P<pkg>@?[\w./-]+)\s+(?P<range>[<>=*~^\d].*)$")
def _npm_package(m, ctx):
    if ctx.state.get("npm_audit"):
        ctx.state["npm_pkg"] = m["pkg"]
    return None


@rule("npm-audit-severity", r"^Severity:\s*(?P<sev>critical|high|moderate|low)\s*$")
def _npm_severity(m, ctx):
    if ctx.state.get("npm_audit"):
        ctx.state["npm_sev"] = m["sev"]
    return None


@rule("npm-audit-advisory", r"^(?P<title>.+?)\s+-\s+https?://github\.com/advisories/(?P<vid>GHSA[\w-]+)\s*$")
def _npm_advisory(m, ctx):
    if not ctx.state.get("npm_audit"):
        return None
    pkg = ctx.state.get("npm_pkg")
    return finding(
        C.SECURITY, ctx.state.get("npm_sev", "medium"), f"{m['vid']} in {pkg}: {m['title']}", "npm-audit",
        identifier=m["vid"], package=pkg, message=m["title"],
    )


@rule("trivy-row", r"^[│|].*" + VULN_ID)
def _trivy_row(m, ctx):
    cells = [c.strip() for c in re.split(r"[│|]", ctx.line)]
    try:
        idx = next(n for n, c in enumerate(cells) if re.fullmatch(VULN_ID, c))
    except StopIteration:
        return None
    pkg = cells[idx - 1] if idx > 0 and cells[idx - 1] else ctx.state.get("trivy_pkg")
    if pkg:
        ctx.state["trivy_pkg"] = pkg
    rest = cells[idx + 1 :]
    sev_match = next((SEVERITY_WORD.fullmatch(c) for c in rest if SEVERITY_WORD.fullmatch(c)), None)
    severity = sev_match.group(1) if sev_match else "medium"
    desc = next((c for c in reversed(rest) if c and not c.startswith("http")), "")
    # Trivy wraps long titles onto continuation rows whose other cells are empty.
    for nxt in ctx.after(4):
        nxt_cells = [c.strip() for c in re.split(r"[│|]", nxt)]
        if not nxt.lstrip().startswith(("│", "|")) or len(nxt_cells) != len(cells) or any(nxt_cells[1 : len(cells) - 2]):
            break
        if nxt_cells[-2]:
            desc = f"{desc} {nxt_cells[-2]}".strip()
    versions = [c for c in rest if re.match(r"^v?\d[\w.+:~-]*$", c)]
    return finding(
        C.SECURITY, severity, f"{m['vid']} in {pkg}" + (f": {desc}" if desc else ""), "trivy",
        identifier=m["vid"], package=pkg, message=desc,
        installed_version=versions[0] if versions else None,
        fixed_version=versions[1] if len(versions) > 1 else None,
    )


@rule("snyk", r"✗\s+(?P<sev>Low|Medium|High|Critical) severity vulnerability found in (?P<pkg>\S+)")
def _snyk(m, ctx):
    desc = ctx.search_after(re.compile(r"Description:\s*(.+)"), 3)
    vid = ctx.search_after(re.compile(r"Info:\s*\S*?(SNYK-[\w-]+|CVE-\d{4}-\d+)"), 4)
    title = desc.group(1) if desc else "vulnerability"
    return finding(
        C.SECURITY, m["sev"], f"{m['pkg']}: {title}", "snyk",
        package=m["pkg"], identifier=vid.group(1) if vid else None, message=title,
    )


@rule("bandit", r"^>>\s*Issue:\s*\[(?P<id>B\d+):(?P<rid>\w+)\]\s*(?P<msg>.+)$")
def _bandit(m, ctx):
    sev = ctx.search_after(re.compile(r"Severity:\s*(\w+)"), 2)
    loc = ctx.search_after(re.compile(r"Location:\s*(?:\./)?(.+?):(\d+)"), 3)
    return finding(
        C.SECURITY, sev.group(1) if sev else "medium", f"{m['id']} {m['rid']}: {m['msg']}", "bandit",
        identifier=m["id"], message=m["msg"],
        file=loc.group(1) if loc else None, file_line=_int(loc.group(2)) if loc else None,
    )


@rule("vuln-id-generic", VULN_ID)
def _vuln_generic(m, ctx):
    if ctx.state.get("npm_audit"):
        return None
    line = ctx.line.strip()
    sev = SEVERITY_WORD.search(line)
    first = line.split()[0] if line.split() else ""
    pkg = first if first and first != m["vid"] and re.match(r"^@?[\w./-]+$", first) else None
    return finding(
        C.SECURITY, sev.group(1) if sev else "medium", f"{m['vid']}" + (f" in {pkg}" if pkg else ""), "scanner",
        identifier=m["vid"], package=pkg, message=line,
    )


@rule(
    "insecure-config",
    r"(?i)(certificate verify failed|InsecureRequestWarning|SSL verification (?:is )?disabled|"
    r"unable to verify the first certificate|self[- ]signed certificate in certificate chain|"
    r"running (?:as|with) (?:root|privileged)|--allow-insecure|security warning)",
)
def _insecure(m, ctx):
    return finding(C.SECURITY, S.MEDIUM, f"Insecure configuration: {m.group(1)}", "security-heuristic", message=ctx.line.strip())


# ---------------------------------------------------------------------------
# Group 2: infrastructure / runner problems
# ---------------------------------------------------------------------------


@rule(
    "oom",
    r"(?i)(java\.lang\.OutOfMemoryError(?::\s*[\w ]+)?|JavaScript heap out of memory|OOMKilled|"
    r"\bout of memory\b|exit code:? 137\b|Killed signal terminated program|MemoryError\b)",
)
def _oom(m, ctx):
    return finding(C.INFRASTRUCTURE, S.CRITICAL, f"Out of memory: {m.group(1)}", "runner", message=ctx.line.strip())


@rule("segfault", r"(?i)\b(segmentation fault|core dumped|SIGSEGV|SIGABRT)\b")
def _segv(m, ctx):
    return finding(C.INFRASTRUCTURE, S.CRITICAL, f"Process crashed: {m.group(1)}", "runner", message=ctx.line.strip())


@rule("disk-full", r"(?i)\b(no space left on device|ENOSPC|disk quota exceeded)\b")
def _disk(m, ctx):
    return finding(C.INFRASTRUCTURE, S.CRITICAL, f"Disk full: {m.group(1)}", "runner", message=ctx.line.strip())


@rule(
    "timeout",
    r"(?i)(has exceeded the maximum execution time|job was cancel+ed because|timed out after [\w .]+|"
    r"exceeded timeout of \d+\s*ms|deadline exceeded|operation timed out|Timeout of \d+ms exceeded)",
)
def _timeout(m, ctx):
    return finding(C.INFRASTRUCTURE, S.HIGH, f"Timeout: {m.group(1)}", "runner", message=ctx.line.strip())


@rule(
    "network",
    r"(?i)(could not resolve host[: ]\s*\S+|getaddrinfo (?:ENOTFOUND|EAI_AGAIN)\s*\S*|ECONNREFUSED|ECONNRESET|"
    r"TLS handshake timeout|429 Too Many Requests|toomanyrequests|Temporary failure in name resolution)",
)
def _network(m, ctx):
    return finding(C.INFRASTRUCTURE, S.MEDIUM, f"Network problem: {m.group(1)}", "runner", message=ctx.line.strip())


# ---------------------------------------------------------------------------
# Group 3: tests, compilers, build tools, CI runners (first match wins)
# ---------------------------------------------------------------------------

# --- CI runner annotations --------------------------------------------------


@rule("gha-command", r"^::(?P<lvl>error|warning)(?:\s+(?P<params>[^:]*))?::(?P<msg>.*)$")
def _gha(m, ctx):
    params = dict(p.split("=", 1) for p in (m["params"] or "").split(",") if "=" in p)
    is_err = m["lvl"] == "error"
    return finding(
        C.CI_ERROR if is_err else C.WARNING, S.HIGH if is_err else S.LOW, m["msg"] or m["lvl"], "github-actions",
        file=params.get("file"), file_line=_int(params.get("line")), message=m["msg"],
    )


@rule("vso-error", r"^##\[(?P<lvl>error|warning)\]\s*(?P<msg>.+)$")
def _vso(m, ctx):
    is_err = m["lvl"] == "error"
    exit_code = re.search(r"exit(?:ed with)? code '?(\d+)'?", m["msg"])
    return finding(
        C.CI_ERROR if is_err else C.WARNING, S.HIGH if is_err else S.LOW, m["msg"], "ci-runner",
        identifier=f"exit {exit_code.group(1)}" if exit_code else None, message=m["msg"],
    )


# --- Test frameworks --------------------------------------------------------


@rule("pytest-failed", r"^(?P<kind>FAILED|ERROR)\s+(?P<test>\S+::\S+|\S+\.py)(?:\s+-\s+(?P<msg>.*))?$")
def _pytest(m, ctx):
    verb = "failed" if m["kind"] == "FAILED" else "errored"
    return finding(
        C.TEST_FAILURE, S.HIGH, f"{m['test']} {verb}", "pytest",
        test_name=m["test"], file=m["test"].split("::")[0], message=m["msg"],
    )


@rule("unittest", r"^(?P<kind>FAIL|ERROR):\s+(?P<method>\w+)\s+\((?P<cls>[\w.]+)\)")
def _unittest(m, ctx):
    name = f"{m['cls']}.{m['method']}"
    return finding(C.TEST_FAILURE, S.HIGH, f"{name} {'failed' if m['kind'] == 'FAIL' else 'errored'}", "unittest", test_name=name)


@rule(
    "maven-surefire",
    r"^\[ERROR\]\s+(?P<test>[\w.$]+(?:\([\w.$]*\))?)\s+(?:--\s+)?Time elapsed:.*?<<<\s*(?P<kind>FAILURE|ERROR)!",
)
def _surefire(m, ctx):
    return finding(
        C.TEST_FAILURE, S.HIGH, f"{m['test']} {'failed' if m['kind'] == 'FAILURE' else 'errored'}", "junit",
        test_name=m["test"], message=ctx.next_nonempty(2),
    )


@rule("gradle-test", r"^(?P<cls>[\w.$]+)\s+>\s+(?P<test>.+?)\s+FAILED$")
def _gradle_test(m, ctx):
    name = f"{m['cls']} > {m['test']}"
    return finding(C.TEST_FAILURE, S.HIGH, f"{name} failed", "junit", test_name=name, message=ctx.next_nonempty(2))


@rule("go-test", r"^\s*--- FAIL:\s+(?P<test>\S+)(?:\s+\((?P<dur>[\d.]+s)\))?")
def _go_test(m, ctx):
    detail = ctx.search_after(re.compile(r"^\s+(?P<file>[\w./-]+\.go):(?P<line>\d+):\s*(?P<msg>.+)$"), 3)
    return finding(
        C.TEST_FAILURE, S.HIGH, f"{m['test']} failed", "go-test", test_name=m["test"],
        file=detail["file"] if detail else None, file_line=_int(detail["line"]) if detail else None,
        message=detail["msg"] if detail else None,
    )


@rule("dotnet-test", r"^\s*Failed\s+(?P<test>[\w.]+(?:\(.*\))?)\s+\[(?P<dur>[^\]]+)\]")
def _dotnet(m, ctx):
    msg = None
    after = ctx.after(4)
    for n, candidate in enumerate(after):
        if candidate.strip().startswith("Error Message:") and n + 1 < len(after):
            msg = after[n + 1].strip()
            break
    return finding(C.TEST_FAILURE, S.HIGH, f"{m['test']} failed", "dotnet-test", test_name=m["test"], message=msg)


@rule("jest-suite", r"^\s*●\s+Test suite failed to run")
def _jest_suite(m, ctx):
    return finding(C.BUILD_ERROR, S.HIGH, "Jest test suite failed to run", "jest", message=ctx.next_nonempty(3))


@rule("jest-test", r"^\s*●\s+(?P<name>.+?\s+›\s+.+)$")
def _jest(m, ctx):
    return finding(C.TEST_FAILURE, S.HIGH, f"{m['name']} failed", "jest", test_name=m["name"], message=ctx.next_nonempty(3))


@rule("go-race", r"^WARNING: DATA RACE")
def _go_race(m, ctx):
    where = ctx.search_after(re.compile(r"^\s+(?P<fn>[\w./*()-]+\.\w+)\(\)"), 3)
    title = f"Data race in {where['fn']}" if where else "Data race detected"
    return finding(C.EXCEPTION, S.HIGH, title, "go-race", message=ctx.next_nonempty(1))


@rule("rspec", r"^rspec\s+(?P<file>\./\S+?):(?P<line>\d+)\s+#\s+(?P<name>.+)$")
def _rspec(m, ctx):
    return finding(
        C.TEST_FAILURE, S.HIGH, f"{m['name']} failed", "rspec", test_name=m["name"], file=m["file"], file_line=_int(m["line"])
    )


# --- Uncaught exceptions ----------------------------------------------------

# Python prints the exception as an unindented "dotted.Name: message" line
# after the frames. Custom exceptions don't always end in "Error".
PY_EXC_LINE = re.compile(r"^(?P<exc>[A-Za-z_][\w.]*)(?::\s*(?P<msg>.*))?$")
PY_FRAME = re.compile(r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+)')


@rule("python-traceback", r"^Traceback \(most recent call last\):")
def _py_traceback(m, ctx):
    file = line_no = None
    frames: list[str] = []
    for candidate in ctx.lines[ctx.i + 1 : ctx.i + 300]:
        frame = PY_FRAME.match(candidate)
        if frame:
            file, line_no = frame["file"], frame["line"]
            frames.append(candidate.strip())
            continue
        if not candidate.strip() or candidate[0].isspace():
            continue  # source lines under frames, or carets
        exc = PY_EXC_LINE.match(candidate.strip())
        if exc and frames:
            return finding(
                C.EXCEPTION, S.HIGH, candidate.strip(), "python",
                identifier=exc["exc"], message=exc["msg"], file=file, file_line=_int(line_no),
                context=[*frames[-4:], candidate.strip()],
            )
        if not exc:
            return None  # an unindented line that isn't an exception: not a traceback we understand
    return None


@rule("java-exception", r'^Exception in thread "(?P<thread>[^"]+)"\s+(?P<exc>[\w.$]+)(?::\s*(?P<msg>.*))?$')
def _java_exc(m, ctx):
    frame = ctx.search_after(re.compile(r"^\s+at\s+[\w.$<>]+\((?P<file>[\w.]+):(?P<line>\d+)\)"), 3)
    return finding(
        C.EXCEPTION, S.HIGH, f"{m['exc']}: {m['msg'] or ''}".rstrip(": "), "java",
        identifier=m["exc"], message=m["msg"],
        file=frame["file"] if frame else None, file_line=_int(frame["line"]) if frame else None,
    )


@rule("node-exception", r"^(?:Uncaught\s+)?(?P<exc>[A-Z]\w*Error):\s+(?P<msg>.+)$")
def _node_exc(m, ctx):
    frame = ctx.search_after(re.compile(r"^\s+at\s+.*?\(?(?P<file>[^\s():]+\.(?:m?js|cjs|ts|tsx)):(?P<line>\d+):\d+\)?"), 2)
    if not frame:
        return None  # a bare "SomethingError: ..." line without a JS stack is not enough
    return finding(
        C.EXCEPTION, S.HIGH, f"{m['exc']}: {m['msg']}", "node",
        identifier=m["exc"], message=m["msg"], file=frame["file"], file_line=_int(frame["line"]),
    )


# --- Compilers & type checkers ----------------------------------------------


@rule(
    "tsc",
    r"^(?P<file>[^\s(]+\.(?:ts|tsx|mts|cts))(?:\((?P<l1>\d+),\d+\)|:(?P<l2>\d+):\d+)\s*[:-]\s*error\s+(?P<code>TS\d+):\s*(?P<msg>.+)$",
)
def _tsc(m, ctx):
    return finding(
        C.BUILD_ERROR, S.HIGH, f"{m['code']}: {m['msg']}", "tsc",
        identifier=m["code"], file=m["file"], file_line=_int(m["l1"] or m["l2"]), message=m["msg"],
    )


@rule("maven-compile", r"^\[ERROR\]\s+(?P<file>\S+\.(?:java|kt|scala)):\[(?P<line>\d+),\d+\]\s+(?P<msg>.+)$")
def _mvn_compile(m, ctx):
    return finding(
        C.BUILD_ERROR, S.HIGH, f"Compilation error: {m['msg']}", "maven",
        file=m["file"], file_line=_int(m["line"]), message=m["msg"],
    )


@rule("javac", r"^(?P<file>\S+\.java):(?P<line>\d+):\s+error:\s+(?P<msg>.+)$")
def _javac(m, ctx):
    return finding(C.BUILD_ERROR, S.HIGH, f"Compilation error: {m['msg']}", "javac", file=m["file"], file_line=_int(m["line"]), message=m["msg"])


@rule("gcc", r"^(?P<file>\S+\.(?:c|cc|cpp|cxx|h|hpp|m|mm)):(?P<line>\d+):\d+:\s+(?:fatal\s+)?error:\s+(?P<msg>.+)$")
def _gcc(m, ctx):
    return finding(C.BUILD_ERROR, S.HIGH, f"Compilation error: {m['msg']}", "gcc", file=m["file"], file_line=_int(m["line"]), message=m["msg"])


@rule("go-build", r"^(?P<file>\S+\.go):(?P<line>\d+):\d+:\s+(?P<msg>.+)$")
def _go_build(m, ctx):
    return finding(C.BUILD_ERROR, S.HIGH, f"Go build error: {m['msg']}", "go", file=m["file"], file_line=_int(m["line"]), message=m["msg"])


@rule("mypy", r"^(?P<file>\S+\.pyi?):(?P<line>\d+):(?:\d+:)?\s+error:\s+(?P<msg>.+?)(?:\s+\[(?P<code>[\w-]+)\])?$")
def _mypy(m, ctx):
    return finding(
        C.BUILD_ERROR, S.MEDIUM, f"Type error: {m['msg']}", "mypy",
        identifier=m["code"], file=m["file"], file_line=_int(m["line"]), message=m["msg"],
    )


@rule("python-lint", r"^(?P<file>\S+\.py):(?P<line>\d+):\d+:\s+(?P<code>[A-Z]{1,4}\d{2,4})\s+(?P<msg>.+)$")
def _pylint(m, ctx):
    return finding(
        C.WARNING, S.LOW, f"{m['code']} {m['msg']}", "lint",
        identifier=m["code"], file=m["file"], file_line=_int(m["line"]), message=m["msg"],
    )


@rule("rustc", r"^error(?:\[(?P<code>E\d+)\])?:\s+(?P<msg>.+)$")
def _rustc(m, ctx):
    loc = ctx.search_after(re.compile(r"^\s*-->\s+(?P<file>\S+?):(?P<line>\d+):\d+"), 2)
    return finding(
        C.BUILD_ERROR, S.HIGH, f"{('error[' + m['code'] + ']') if m['code'] else 'error'}: {m['msg']}",
        "rustc" if loc else "generic",
        identifier=m["code"], message=m["msg"],
        file=loc["file"] if loc else None, file_line=_int(loc["line"]) if loc else None,
    )


# --- Build tools / package managers -----------------------------------------


@rule(
    "maven-goal",
    r"^\[ERROR\]\s+Failed to execute goal\s+(?P<goal>\S+)\s+(?:\((?P<exec>[^)]*)\)\s+)?on project\s+(?P<proj>[\w.-]+):\s*(?P<msg>.+)$",
)
def _mvn_goal(m, ctx):
    plugin = m["goal"].split(":")[1] if m["goal"].count(":") >= 2 else m["goal"]
    return finding(
        C.BUILD_ERROR, S.HIGH, f"Maven {plugin} failed on {m['proj']}", "maven",
        identifier=m["goal"], message=m["msg"],
    )


@rule("gradle-failure", r"^\*\s+What went wrong:")
def _gradle(m, ctx):
    msg = ctx.next_nonempty(2) or "Gradle build failed"
    return finding(C.BUILD_ERROR, S.HIGH, f"Gradle: {msg}", "gradle", message=msg)


@rule("npm-error", r"^npm (?:ERR!|error) code (?P<code>\S+)")
def _npm(m, ctx):
    details = []
    for candidate in ctx.after(8):
        d = re.match(r"^npm (?:ERR!|error)\s+(?!code|errno|path|syscall|A complete log)(.+)$", candidate)
        if d and d.group(1).strip():
            details.append(d.group(1).strip())
    msg = " ".join(details[:3])
    return finding(C.BUILD_ERROR, S.HIGH, f"npm {m['code']}" + (f": {details[0]}" if details else ""), "npm", identifier=m["code"], message=msg)


@rule(
    "pip",
    r"^ERROR:\s+(?P<msg>(?:Could not find a version|No matching distribution|Failed building wheel|ResolutionImpossible|"
    r"Cannot install|Could not install|pip's dependency resolver|Failed to build).*)$",
)
def _pip(m, ctx):
    return finding(C.BUILD_ERROR, S.HIGH, f"pip: {m['msg']}", "pip", message=m["msg"])


@rule("docker-step", r"^#\d+\s+(?:\d+\.\d+\s+)?ERROR:?\s+(?P<msg>.+)$")
def _docker_step(m, ctx):
    # BuildKit prints the same failure twice (step output, then "failed to solve").
    # Both rules use the same title so the fingerprint merges them.
    return finding(C.BUILD_ERROR, S.HIGH, f"Docker build failed: {m['msg']}", "docker", message=m["msg"])


@rule("docker-solve", r"^(?:ERROR:\s+)?failed to (?:solve|build)(?::|\s+with)\s*(?P<msg>.+)$")
def _docker_solve(m, ctx):
    return finding(C.BUILD_ERROR, S.HIGH, f"Docker build failed: {m['msg']}", "docker", message=m["msg"])


@rule("make", r"^(?:g?make)(?:\[\d+\])?:\s+\*\*\*\s+(?P<msg>.+)$")
def _make(m, ctx):
    return finding(C.BUILD_ERROR, S.MEDIUM, f"make: {m['msg']}", "make", message=m["msg"])


# --- Job-level outcomes -----------------------------------------------------


@rule(
    "job-failed",
    r"(?i)^(?:ERROR:\s+Job failed:\s*(?P<gl>.+)|Finished:\s+(?P<jk>FAILURE|ABORTED)|"
    r".*\bexited with (?:exit )?code[: ]+'?(?P<code>[1-9]\d*)'?|.*Process completed with exit code (?P<gh>[1-9]\d*))",
)
def _job_failed(m, ctx):
    if m["gl"]:
        return finding(C.CI_ERROR, S.HIGH, f"GitLab job failed: {m['gl']}", "gitlab", message=m["gl"])
    if m["jk"]:
        return finding(C.CI_ERROR, S.HIGH, f"Jenkins build {m['jk'].upper()}", "jenkins")
    code = m["code"] or m["gh"]
    return finding(C.CI_ERROR, S.HIGH, f"Step exited with code {code}", "ci-runner", identifier=f"exit {code}", message=ctx.line.strip())


# --- Generic fallbacks (keep last) ------------------------------------------

GENERIC_NOISE = re.compile(
    r"(?i)^(to see the full stack trace|re-run maven|for more information about|"
    r"-> \[help|\[help \d+\]|tests run:|failures:\s*$|errors:\s*$|there (?:are|were) test failures|"
    r"please refer to|after correcting the problems|$)"
)


@rule("generic-error", r"^(?:\[(?:ERROR|FATAL)\]|ERROR:|FATAL:|Error:|error:|FATAL ERROR:)(?P<sp>\s*)(?P<msg>.*)$")
def _generic_error(m, ctx):
    # "[ERROR]   detail" with deep indentation is a continuation of a block
    # that a specific rule above already reported.
    if len(m["sp"]) >= 2 or GENERIC_NOISE.match(m["msg"].strip()):
        return None
    return finding(C.BUILD_ERROR, S.MEDIUM, m["msg"], "generic", message=m["msg"])


@rule("generic-warning", r"^(?:\[WARNING\]|WARNING:|WARN(?:ING)?\s+)\s*(?P<msg>\S.*)$")
def _generic_warning(m, ctx):
    return finding(C.WARNING, S.LOW, m["msg"], "generic", message=m["msg"])


# ---------------------------------------------------------------------------

STATE_RULES: list[Rule] = [_npm_header, _npm_package, _npm_severity]

RULE_GROUPS: dict[str, list[Rule]] = {
    "security": [_npm_advisory, _trivy_row, _snyk, _bandit, _vuln_generic, _insecure],
    "infrastructure": [_oom, _segv, _disk, _timeout, _network],
    "main": [
        _gha, _vso,
        _pytest, _unittest, _surefire, _gradle_test, _go_test, _dotnet, _jest_suite, _jest, _rspec, _go_race,
        _py_traceback, _java_exc, _node_exc,
        _tsc, _mvn_compile, _javac, _gcc, _go_build, _mypy, _pylint,
        _mvn_goal, _gradle, _npm, _pip, _docker_step, _docker_solve, _make,
        _job_failed,
        _rustc, _generic_error, _generic_warning,
    ],
}
