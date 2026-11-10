"""Small, focused inputs for each detection rule."""

from __future__ import annotations

import json

import pytest

from logpulse.parser import clean_line, fingerprint, normalize_text, parse_log


def only(text: str, **expect):
    r = parse_log(text)
    matches = [f for f in r.findings if all(getattr(f, k) == v for k, v in expect.items())]
    assert matches, f"no finding with {expect}; got {[(f.category, f.source, f.title) for f in r.findings]}"
    return matches[0]


@pytest.mark.parametrize(
    "line, category, source, needle",
    [
        ("::error file=app.py,line=10::Something broke", "ci_error", "github-actions", "Something broke"),
        ("##[error]Bash exited with code '2'.", "ci_error", "ci-runner", "exited with code"),
        ("FAIL: test_add (tests.test_math.MathTest)", "test_failure", "unittest", "tests.test_math.MathTest.test_add"),
        ("CalculatorTest > divideByZero() FAILED", "test_failure", "junit", "CalculatorTest > divideByZero()"),
        ("  Failed MyApp.Tests.OrderTests.Total_IsRounded [12 ms]", "test_failure", "dotnet-test", "MyApp.Tests.OrderTests.Total_IsRounded"),
        ("rspec ./spec/models/user_spec.rb:12 # User validates email", "test_failure", "rspec", "User validates email"),
        ("src/main.c:14:5: error: 'foo' undeclared (first use in this function)", "build_error", "gcc", "'foo' undeclared"),
        ("src/App.java:22: error: cannot find symbol", "build_error", "javac", "cannot find symbol"),
        ("[ERROR] /src/main/java/A.java:[10,5] cannot find symbol", "build_error", "maven", "cannot find symbol"),
        ("app/models.py:31: error: Incompatible return value type  [return-value]", "build_error", "mypy", "Incompatible return"),
        ("app/views.py:3:1: F401 'os' imported but unused", "warning", "lint", "F401"),
        ("npm ERR! code ERESOLVE", "build_error", "npm", "ERESOLVE"),
        ("ERROR: Could not find a version that satisfies the requirement torch==9.9", "build_error", "pip", "Could not find a version"),
        ("make: *** [Makefile:12: build] Error 1", "build_error", "make", "Makefile:12"),
        ("Error: The operation was canceled.", "build_error", "generic", "operation was canceled"),
        ("FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory", "infrastructure", "runner", "out of memory"),
        ("/bin/sh: line 1:   812 Segmentation fault      (core dumped) ./app", "infrastructure", "runner", "Segmentation fault"),
        ("write /tmp/x: no space left on device", "infrastructure", "runner", "no space left"),
        ("##[error]The job running on runner X has exceeded the maximum execution time of 360 minutes.", "infrastructure", "runner", "maximum execution time"),
        ("fatal: unable to access 'https://x/': Could not resolve host: github.com", "infrastructure", "runner", "Could not resolve host"),
        ("urllib3/connectionpool.py:1099: InsecureRequestWarning: Unverified HTTPS request", "security", "security-heuristic", "InsecureRequestWarning"),
        ("✗ High severity vulnerability found in minimist", "security", "snyk", "minimist"),
        ("jinja2  2.11.3  CVE-2024-22195  3.1.3", "security", "scanner", "CVE-2024-22195 in jinja2"),
        ("ERROR: Job failed: exit code 137", "ci_error", "gitlab", "exit code 137"),
        ("Finished: ABORTED", "ci_error", "jenkins", "ABORTED"),
    ],
)
def test_single_line_rules(line, category, source, needle):
    f = only(line, category=category, source=source)
    assert needle in f.title or needle in (f.test_name or "") or needle in (f.message or "")


def test_exit_code_137_is_also_reported_as_oom():
    r = parse_log("ERROR: Job failed: exit code 137")
    assert {f.category for f in r.findings} == {"ci_error", "infrastructure"}


def test_tsc_both_formats():
    a = only("src/a.ts(3,7): error TS2304: Cannot find name 'x'.", source="tsc")
    b = only("src/b.ts:3:7 - error TS2304: Cannot find name 'y'.", source="tsc")
    assert (a.file, a.file_line, b.file, b.file_line) == ("src/a.ts", 3, "src/b.ts", 3)


def test_rustc_uses_location_line():
    f = only("error[E0382]: borrow of moved value: `v`\n  --> src/main.rs:5:20\n", source="rustc")
    assert (f.identifier, f.file, f.file_line) == ("E0382", "src/main.rs", 5)


def test_gradle_what_went_wrong():
    f = only("FAILURE: Build failed with an exception.\n\n* What went wrong:\nExecution failed for task ':app:test'.\n", source="gradle")
    assert f.message == "Execution failed for task ':app:test'."


def test_java_uncaught_exception():
    text = 'Exception in thread "main" java.lang.IllegalStateException: boom\n\tat com.x.Main.run(Main.java:42)\n'
    f = only(text, category="exception", source="java")
    assert (f.identifier, f.file, f.file_line) == ("java.lang.IllegalStateException", "Main.java", 42)


def test_node_exception_requires_stack_frame():
    assert not [f for f in parse_log("TypeError: just a message in prose").findings if f.source == "node"]
    f = only("TypeError: Cannot read properties of undefined (reading 'id')\n    at handler (/app/src/api.js:17:9)\n", source="node")
    assert f.file_line == 17


def test_python_traceback_with_nested_frames():
    text = (
        "Traceback (most recent call last):\n"
        '  File "/app/main.py", line 3, in <module>\n'
        "    run()\n"
        '  File "/app/job.py", line 9, in run\n'
        "    1 / 0\n"
        "    ~~^~~\n"
        "ZeroDivisionError: division by zero\n"
    )
    f = only(text, category="exception")
    assert (f.identifier, f.message, f.file, f.file_line) == ("ZeroDivisionError", "division by zero", "/app/job.py", 9)


def test_duplicate_lines_are_merged_with_count():
    r = parse_log("\n".join(["npm ERR! code E404"] * 3))
    assert len(r.findings) == 1 and r.findings[0].occurrences == 3


def test_different_tests_with_numbers_are_not_merged():
    r = parse_log("FAILED tests/t.py::test_case_1\nFAILED tests/t.py::test_case_2\n")
    assert len([f for f in r.findings if f.category == "test_failure"]) == 2


def test_fingerprint_stable_across_builds_for_free_text():
    a = parse_log("Error: request timed out after 31s on attempt 2").findings
    b = parse_log("Error: request timed out after 29s on attempt 5").findings
    assert {f.fingerprint for f in a} == {f.fingerprint for f in b}


def test_normalize_text_masks_numbers_and_hashes():
    assert normalize_text("Build 4f2a91c0d took 31.5s") == normalize_text("Build 9e8d7c6b5 took 2.0s")
    assert fingerprint("a", "b", "x") != fingerprint("a", "b", "y")


def test_clean_line_strips_ansi_timestamps_and_progress():
    assert clean_line("2026-01-01T10:00:00.1234567Z \x1b[31mFAILED\x1b[0m x") == "FAILED x"
    assert clean_line("[2026-01-01T10:00:00.000Z] hello") == "hello"
    assert clean_line("10%\r50%\r100% done") == "100% done"
    assert clean_line("section_start:1700000000:build_script\r\x1b[0KBuilding") == "Building"


def test_secrets_are_redacted_everywhere():
    secret = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    text = f"some line\necho token={secret}\nnpm ERR! code E401\n"
    r = parse_log(text)
    leak = only(text, category="secret_leak")
    assert leak.severity == "critical"
    blob = json.dumps([f.to_dict() for f in r.findings])
    assert secret not in blob, "secret value leaked into the stored report"
    assert "***REDACTED***" in blob


@pytest.mark.parametrize("line", ["password=${{ secrets.DB }}", "PASSWORD: ***", "api_key = <your-key-here>", "password: null"])
def test_masked_or_placeholder_credentials_are_not_flagged(line):
    assert not [f for f in parse_log(line).findings if f.category == "secret_leak"]


def test_maven_continuation_lines_are_not_generic_errors():
    text = "[ERROR] Failures: \n[ERROR]   FooTest.bar:12 expected:<1> but was:<2>\n[ERROR] -> [Help 1]\n"
    assert not parse_log(text).findings


def test_clean_log_passes():
    r = parse_log("Compiling...\nAll good\n===== 12 passed in 0.50s =====\n")
    assert r.status == "passed" and r.findings == [] and r.tests.passed == 12


def test_huge_log_is_capped():
    text = "\n".join(f"FAILED tests/t.py::test_{i}" for i in range(1000))
    r = parse_log(text, max_findings=100)
    assert len(r.findings) == 100 and r.truncated
