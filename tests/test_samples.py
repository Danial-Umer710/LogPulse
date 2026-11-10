"""End-to-end parser checks against the realistic logs in samples/."""

from __future__ import annotations

import pytest

from logpulse.parser import parse_log

PYTEST = "github-actions/api-service/1042/pytest.log"
MAVEN = "azure-pipelines/billing-java/20261103.4/maven-build.log"
JEST = "gitlab-ci/web-frontend/88123/jest-and-audit.log"
TRIVY = "jenkins/payments-api/512/docker-trivy.log"
GO_PASS = "github-actions/inventory-go/733/go-test.log"
GO_FAIL = "github-actions/inventory-go/734/go-test.log"


def titles(result, category=None):
    return [f.title for f in result.findings if category is None or f.category == category]


def test_github_actions_pytest(sample_text):
    r = parse_log(sample_text(PYTEST))
    assert r.ci_platform == "github-actions"
    assert r.status == "failed"
    assert r.tests.to_dict() == {"total": 48, "passed": 45, "failed": 2, "errors": 1, "skipped": 0}
    tests = {f.test_name for f in r.findings if f.category == "test_failure"}
    assert tests == {
        "tests/test_orders.py::test_create_order_total",
        "tests/test_orders.py::test_cancel_order_after_ship",
        "tests/test_payments.py::test_refund_partial_amount",
    }
    exc = next(f for f in r.findings if f.category == "exception")
    assert exc.identifier == "app.domain.errors.InvalidTransition"
    assert exc.file == "app/domain/order.py" and exc.file_line == 52  # runner workspace prefix stripped
    bandit = {f.identifier for f in r.findings if f.source == "bandit"}
    assert bandit == {"B608", "B105"}
    assert any(f.category == "secret_leak" and f.identifier == "AWS access key" for f in r.findings)
    assert "pytest" in r.detected_tools and "bandit" in r.detected_tools


def test_azure_pipelines_maven(sample_text):
    r = parse_log(sample_text(MAVEN))
    assert r.ci_platform == "azure-pipelines"
    assert r.status == "failed"
    assert r.tests.to_dict() == {"total": 19, "passed": 16, "failed": 1, "errors": 1, "skipped": 1}
    failing = {f.test_name for f in r.findings if f.category == "test_failure"}
    assert failing == {
        "com.contoso.billing.InvoiceCalculatorTest.appliesVatForEuCustomers",
        "com.contoso.billing.PaymentGatewayClientTest.retriesOnGatewayTimeout",
    }
    vat = next(f for f in r.findings if f.test_name and "Vat" in f.test_name)
    assert "expected: <121.00> but was: <120.99>" in vat.message
    assert any("maven-surefire-plugin" in t for t in titles(r, "build_error"))
    # Maven's boilerplate "[ERROR] Re-run Maven..." lines must not become findings
    assert not any("Re-run Maven" in t or "Help 1" in t for t in titles(r))


def test_gitlab_jest_npm_audit_tsc(sample_text):
    r = parse_log(sample_text(JEST))
    assert r.ci_platform == "gitlab-ci"
    assert r.tests.to_dict() == {"total": 39, "passed": 37, "failed": 2, "skipped": 0, "errors": 0}

    advisories = {f.identifier: (f.package, f.severity) for f in r.findings if f.source == "npm-audit"}
    assert advisories == {
        "GHSA-p6mc-m468-83gw": ("lodash", "critical"),
        "GHSA-35jh-r3h4-6jhm": ("lodash", "critical"),
        "GHSA-8hc4-vh64-cxmj": ("axios", "high"),
        "GHSA-c2qf-rxjj-qqgw": ("semver", "medium"),
    }
    ts = {f.identifier for f in r.findings if f.source == "tsc"}
    assert ts == {"TS2322", "TS2345"}
    jest = {f.test_name for f in r.findings if f.source == "jest" and f.category == "test_failure"}
    assert jest == {"CartSummary › shows free shipping banner above threshold", "CartSummary › applies discount code"}
    assert any(f.title == "Jest test suite failed to run" and "Cannot find module" in f.message for f in r.findings)
    assert any(f.source == "gitlab" for f in r.findings)
    # The indented "Error"/"expect" lines inside the Jest failures belong to the
    # tests; they must not show up as separate generic errors.
    assert not any(f.source == "generic" for f in r.findings)


def test_jenkins_docker_trivy(sample_text):
    r = parse_log(sample_text(TRIVY))
    assert r.ci_platform == "jenkins"
    cves = {f.identifier: (f.package, f.severity) for f in r.findings if f.source == "trivy"}
    assert cves == {
        "CVE-2024-5535": ("libssl3", "critical"),
        "CVE-2024-45491": ("libexpat1", "high"),
        "CVE-2024-45492": ("libexpat1", "high"),  # package inherited from the row above
        "CVE-2024-45296": ("path-to-regexp", "high"),
    }
    regexp = next(f for f in r.findings if f.identifier == "CVE-2024-45296")
    assert regexp.title.endswith("expressions cause ReDoS")  # wrapped table row joined
    assert "fixed version: 0.1.10" in regexp.message
    oom = [f for f in r.findings if f.category == "infrastructure"]
    assert oom and oom[0].severity == "critical"
    docker = [f for f in r.findings if f.source == "docker"]
    assert len(docker) == 1 and docker[0].occurrences == 2  # step error + "failed to solve" merged
    assert any(f.title == "Jenkins build FAILURE" for f in r.findings)


def test_go_passing_build_is_passed(sample_text):
    r = parse_log(sample_text(GO_PASS))
    assert r.status == "passed"
    assert r.tests.to_dict() == {"total": 5, "passed": 4, "failed": 0, "skipped": 1, "errors": 0}
    assert [f.severity for f in r.findings] == ["low"]  # only the deprecation warning


def test_go_failing_build(sample_text):
    r = parse_log(sample_text(GO_FAIL))
    assert r.status == "failed"
    failing = {f.test_name: f for f in r.findings if f.category == "test_failure"}
    assert set(failing) == {"TestReleaseStock", "TestConcurrentReservations"}
    assert failing["TestReleaseStock"].file == "stock_test.go"
    assert failing["TestReleaseStock"].message == "expected available=10, got 9"
    assert any(f.source == "go" and f.file == "internal/report/export.go" for f in r.findings)
    assert any(f.source == "go-race" for f in r.findings)


@pytest.mark.parametrize("path", [PYTEST, MAVEN, JEST, TRIVY, GO_PASS, GO_FAIL])
def test_findings_are_sorted_and_unique(sample_text, path):
    r = parse_log(sample_text(path))
    ranks = [{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f.severity] for f in r.findings]
    assert ranks == sorted(ranks, reverse=True)
    fps = [f.fingerprint for f in r.findings]
    assert len(fps) == len(set(fps))
    assert all(f.context for f in r.findings)
