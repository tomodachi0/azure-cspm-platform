"""Turns a flat list of findings into a 0-100 posture score.

Simple weighted-deduction model: start at 100, subtract weight per
finding by severity, floor at 0. Easy to explain in a defense and easy
to swap for a more sophisticated CIS-weighted model later.
"""
from collections import Counter

SEVERITY_WEIGHTS = {
    "critical": 15,
    "high": 8,
    "medium": 3,
    "low": 1,
}


def score_findings(findings) -> dict:
    counts = Counter(f.severity for f in findings)
    deduction = sum(SEVERITY_WEIGHTS.get(sev, 1) * n for sev, n in counts.items())
    score = max(0, 100 - deduction)

    return {
        "score": score,
        "total_findings": len(findings),
        "by_severity": dict(counts),
        "grade": _grade(score),
    }


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "F"
