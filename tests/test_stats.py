from logpulse.stats import extract_test_stats


def stats(text: str) -> dict:
    return extract_test_stats(text.splitlines()).to_dict()


def test_pytest_summary_variants():
    assert stats("=== 3 failed, 10 passed, 2 skipped in 4.20s ===") == {"total": 15, "passed": 10, "failed": 3, "errors": 0, "skipped": 2}
    assert stats("===== 1 failed, 2 passed, 3 errors in 1.00s (0:00:01) =====")["errors"] == 3
    assert stats("==== 7 passed in 0.12s ====") == {"total": 7, "passed": 7, "failed": 0, "errors": 0, "skipped": 0}


def test_jest_summary():
    assert stats("Tests:       1 failed, 2 skipped, 9 passed, 12 total") == {"total": 12, "passed": 9, "failed": 1, "errors": 0, "skipped": 2}


def test_maven_uses_final_aggregate():
    text = (
        "[ERROR] Tests run: 3, Failures: 1, Errors: 0, Skipped: 0, Time elapsed: 0.1 s <<< FAILURE! -- in A\n"
        "[ERROR] Tests run: 10, Failures: 1, Errors: 2, Skipped: 1\n"
    )
    assert stats(text) == {"total": 10, "passed": 6, "failed": 1, "errors": 2, "skipped": 1}


def test_gradle_and_dotnet():
    assert stats("12 tests completed, 2 failed, 1 skipped")["failed"] == 2
    assert stats("Failed!  - Failed:     1, Passed:    41, Skipped:     0, Total:    42, Duration: 2 s") == {
        "total": 42, "passed": 41, "failed": 1, "errors": 0, "skipped": 0,
    }


def test_unittest():
    assert stats("Ran 8 tests in 0.010s\n\nFAILED (failures=2, errors=1)") == {"total": 8, "passed": 5, "failed": 2, "errors": 1, "skipped": 0}
    assert stats("Ran 4 tests in 0.010s\n\nOK")["passed"] == 4


def test_multiple_frameworks_are_summed():
    text = "==== 5 passed in 1.0s ====\nTests:       1 failed, 3 passed, 4 total\n"
    assert stats(text) == {"total": 9, "passed": 8, "failed": 1, "errors": 0, "skipped": 0}


def test_no_summary():
    assert stats("hello\nworld") == {}
