from scanner.checks.base import BaseCheck


class DummyCheck(BaseCheck):
    check_id = "dummy-check"
    default_severity = "medium"
    cis_reference = "CIS Test 1.1"


def test_scanned_increments_total():
    check = DummyCheck(credential=None, subscription_id="sub-1")
    assert check.total_scanned == 0
    check._scanned()
    check._scanned()
    check._scanned(3)
    assert check.total_scanned == 5


def test_finding_uses_default_severity_when_not_overridden():
    check = DummyCheck(credential=None, subscription_id="sub-1")
    finding = check._finding(
        resource_id="res-1",
        resource_name="my-resource",
        description="something is wrong",
        remediation="fix it",
    )
    assert finding.check_id == "dummy-check"
    assert finding.severity == "medium"
    assert finding.cis_reference == "CIS Test 1.1"
    assert finding.resource_id == "res-1"


def test_finding_severity_can_be_overridden_per_call():
    check = DummyCheck(credential=None, subscription_id="sub-1")
    finding = check._finding(
        resource_id="res-1",
        resource_name="my-resource",
        description="something is very wrong",
        remediation="fix it now",
        severity="critical",
    )
    assert finding.severity == "critical"
