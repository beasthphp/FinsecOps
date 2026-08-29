"""Combine deterministic rule risk with ML anomaly severity."""

from __future__ import annotations

from dataclasses import dataclass


RULE_WEIGHT = 0.60
ML_WEIGHT = 0.40

STRONG_RULE_RISK_FLOOR = 70.0
ML_ANOMALY_RISK_FLOOR = 70.0
HIGH_EVIDENCE_FLOOR = 55.0
SINGLE_PATTERN_MAX_RISK = 69.0
MULTI_RULE_CRITICAL_COUNT = 2

SEVERITY_THRESHOLDS = (
    (70.0, "CRITICAL"),
    (50.0, "HIGH"),
    (30.0, "MEDIUM"),
    (0.0, "LOW"),
)


@dataclass(frozen=True)
class RiskResult:
    final_risk: float
    severity: str


def combine_risk(
    rule_risk: float,
    ml_risk: float,
    triggered_rule_count: int = 0,
) -> RiskResult:
    """Weighted score that keeps single-pattern and mixed attacks distinct."""

    weighted = RULE_WEIGHT * float(rule_risk) + ML_WEIGHT * float(ml_risk)
    source_floor = 0.0
    strong_rule = rule_risk >= STRONG_RULE_RISK_FLOOR
    ml_anomaly = ml_risk >= ML_ANOMALY_RISK_FLOOR
    multi_rule_attack = triggered_rule_count >= MULTI_RULE_CRITICAL_COUNT

    if strong_rule or ml_anomaly:
        source_floor = max(source_floor, HIGH_EVIDENCE_FLOOR)

    critical_evidence = multi_rule_attack and (strong_rule or ml_anomaly)
    if critical_evidence:
        source_floor = max(source_floor, SEVERITY_THRESHOLDS[0][0])

    final_risk = min(100.0, max(weighted, source_floor))
    if not critical_evidence and final_risk >= SEVERITY_THRESHOLDS[0][0]:
        final_risk = SINGLE_PATTERN_MAX_RISK
    final_risk = round(final_risk, 2)
    return RiskResult(final_risk=final_risk, severity=classify_severity(final_risk))


def classify_severity(final_risk: float) -> str:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if final_risk >= threshold:
            return severity
    return "LOW"
