from scanner.checks.base import Finding
from scanner.scoring import score


def _finding(check_id, resource_id, severity="high"):
    return Finding(
        check_id=check_id,
        resource_id=resource_id,
        resource_name=resource_id,
        severity=severity,
        description="test finding",
        remediation="test remediation",
    )


def test_no_applicable_controls_scores_100():
    """A subscription with none of the checked resource types has
    nothing to be non-compliant about — score should be a perfect 100,
    not zero or undefined."""
    result = score([], check_totals={"some-check": 0}, check_meta={})
    assert result["score"] == 100.0
    assert result["grade"] == "A"
    assert result["controls"] == []


def test_fully_compliant_scores_100():
    """Controls with resources but zero findings should be fully
    compliant."""
    check_totals = {"nsg-open-inbound": 5, "storage-public-access": 3}
    check_meta = {
        "nsg-open-inbound": {"severity": "critical", "cis_reference": "6.1"},
        "storage-public-access": {"severity": "high", "cis_reference": "3.7"},
    }
    result = score([], check_totals, check_meta)
    assert result["score"] == 100.0
    assert result["total_findings"] == 0


def test_known_scenario_matches_hand_calculated_score():
    """Regression test pinned to a real scan result: four controls,
    weighted by severity, should combine to exactly 21.4 — see the
    worked calculation this mirrors:
        nsg (critical, w5):  1/1 failed -> compliance 0.0
        storage (high, w3):  1/2 failed -> compliance 0.5
        disk (high, w3):     1/1 failed -> compliance 0.0
        rbac (high, w3):     2/4 failed -> compliance 0.5
        weighted sum = 5*0 + 3*0.5 + 3*0 + 3*0.5 = 3.0
        weight total = 5 + 3 + 3 + 3 = 14
        score = 100 * 3.0 / 14 = 21.4
    """
    findings = [
        _finding("nsg-open-inbound", "nsg-1", severity="critical"),
        _finding("storage-public-access", "storage-1", severity="high"),
        _finding("disk-encryption", "disk-1", severity="critical"),
        _finding("rbac-owner-at-subscription", "assignment-1", severity="high"),
        _finding("rbac-owner-at-subscription", "assignment-2", severity="high"),
    ]
    check_totals = {
        "nsg-open-inbound": 1,
        "storage-public-access": 2,
        "disk-encryption": 1,
        "rbac-owner-at-subscription": 4,
    }
    check_meta = {
        "nsg-open-inbound": {"severity": "critical", "cis_reference": ""},
        "storage-public-access": {"severity": "high", "cis_reference": ""},
        "disk-encryption": {"severity": "high", "cis_reference": ""},
        "rbac-owner-at-subscription": {"severity": "high", "cis_reference": ""},
    }
    result = score(findings, check_totals, check_meta)
    assert result["score"] == 21.4
    assert result["grade"] == "F"
    assert result["total_findings"] == 5


def test_multiple_findings_on_same_resource_count_once():
    """A resource with two separate findings from the same check should
    only count as one failed resource, not two — compliance is about
    how many resources failed, not how many findings they produced."""
    findings = [
        _finding("storage-public-access", "storage-1", severity="high"),
        _finding("storage-public-access", "storage-1", severity="medium"),
    ]
    check_totals = {"storage-public-access": 2}
    check_meta = {"storage-public-access": {"severity": "high", "cis_reference": ""}}
    result = score(findings, check_totals, check_meta)
    control = result["controls"][0]
    assert control["failed_resources"] == 1
    assert control["compliance"] == 0.5


def test_grade_boundaries():
    check_totals = {"c": 100}
    check_meta = {"c": {"severity": "low", "cis_reference": ""}}

    def score_for_failed(failed):
        findings = [
            _finding("c", f"r{i}", severity="low") for i in range(failed)
        ]
        return score(findings, check_totals, check_meta)["grade"]

    assert score_for_failed(0) == "A"    # 100
    assert score_for_failed(15) == "B"   # 85
    assert score_for_failed(40) == "C"   # 60
    assert score_for_failed(65) == "D"   # 35
    assert score_for_failed(90) == "F"   # 10
