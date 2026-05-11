from typing import Any, Dict, List


SEVERITY_POINTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}


STATUS_BASE_POINTS = {
    "allowed": 5,
    "blocked": 40,
    "fallback": 50,
}


def calculate_risk_score(event: Dict[str, Any]) -> int:
    """
    Educational risk scoring logic.

    The score is intentionally simple and explainable:
    - Status contributes base risk.
    - Violation severities add risk.
    - Multiple retry attempts add risk.
    - Score is capped at 100.
    """

    score = STATUS_BASE_POINTS.get(event.get("status"), 10)

    violations: List[Dict[str, Any]] = event.get("violations", []) or []

    for violation in violations:
        severity = violation.get("severity", "medium")
        score += SEVERITY_POINTS.get(severity, 15)

        code = violation.get("code", "")

        if code.startswith("pii_"):
            score += 15

        if code == "prompt_injection":
            score += 20

        if code == "llm_provider_error":
            score += 10

    attempts = event.get("attempts", 0) or 0

    if attempts > 1:
        score += 10

    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def enrich_event_with_risk(event: Dict[str, Any]) -> Dict[str, Any]:
    score = calculate_risk_score(event)
    enriched = dict(event)
    enriched["risk_score"] = score
    enriched["risk_level"] = risk_level(score)
    return enriched
