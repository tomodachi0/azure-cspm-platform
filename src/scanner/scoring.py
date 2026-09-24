"""CIS-style resource-coverage compliance score.

Each check is a "control." A control's compliance is the fraction of
the resources it actually examined that passed:

    compliance_i = 1 - failed_i / total_i

Controls are combined into one 0-100 score, weighted by severity, so
scale is reflected (50 bad resources score worse than 1) without
falling back to an arbitrary per-finding deduction:

    score = 100 * sum(weight_i * compliance_i) / sum(weight_i)

Controls with zero applicable resources are excluded entirely — a
control with nothing to check contributes nothing to the score.
"""
from collections import Counter, defaultdict

CONTROL_WEIGHTS = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def score(findings, check_totals: dict, check_meta: dict) -> dict:
    """
    check_totals: {check_id: total_resources_scanned}
    check_meta:   {check_id: {"severity": ..., "cis_reference": ...}}
    """
    failed_by_check = defaultdict(set)
    for f in findings:
        failed_by_check[f.check_id].add(f.resource_id)

    controls = []
    weighted_sum = 0.0
    weight_total = 0.0

    for check_id, total in check_totals.items():
        if total == 0:
            continue  # control not applicable — no resources of this type

        meta = check_meta.get(check_id, {})
        severity = meta.get("severity", "medium")
        weight = CONTROL_WEIGHTS.get(severity, 1)

        failed = len(failed_by_check.get(check_id, ()))
        compliance = 1 - (failed / total)

        controls.append({
            "check_id": check_id,
            "cis_reference": meta.get("cis_reference", ""),
            "severity": severity,
            "total_resources": total,
            "failed_resources": failed,
            "compliance": round(compliance, 4),
        })

        weighted_sum += weight * compliance
        weight_total += weight

    final_score = round(100 * weighted_sum / weight_total, 1) if weight_total else 100.0

    return {
        "score": final_score,
        "grade": _grade(final_score),
        "total_findings": len(findings),
        "by_severity": dict(Counter(f.severity for f in findings)),
        "controls": controls,
    }


def _grade(value) -> str:
    if value >= 90:
        return "A"
    if value >= 75:
        return "B"
    if value >= 50:
        return "C"
    if value >= 25:
        return "D"
    return "F"
