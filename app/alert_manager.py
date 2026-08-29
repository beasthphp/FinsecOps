"""Alert construction and explanation for risky behavior windows."""

from __future__ import annotations

from app.feature_extractor import BehaviorWindow
from app.risk_engine import RiskResult
from app.rule_engine import RuleResult


ALERT_THRESHOLD = 30.0
BEHAVIORAL_ANOMALY_TYPE = "BEHAVIORAL_ANOMALY"


def build_alert(
    window: BehaviorWindow,
    rule_result: RuleResult,
    ml_result: dict[str, object],
    risk_result: RiskResult,
) -> dict[str, object] | None:
    if risk_result.final_risk < ALERT_THRESHOLD:
        return None

    ml_anomaly = bool(ml_result["is_anomaly"])
    alert_type = choose_alert_type(rule_result, ml_anomaly)
    reasons = list(rule_result.reasons)

    if ml_anomaly:
        reasons.append(
            "Isolation Forest classified the user's hourly activity as anomalous."
        )
    elif float(ml_result["ml_risk"]) >= 50:
        reasons.append(
            "Isolation Forest assigned elevated anomaly severity, but did not cross the anomaly boundary."
        )

    if not reasons:
        reasons.append("Combined risk crossed the alert threshold.")

    description = format_description(
        window=window,
        alert_type=alert_type,
        severity=risk_result.severity,
        final_risk=risk_result.final_risk,
        reasons=reasons,
    )

    return {
        "timestamp": window.timestamp,
        "window_start": window.window_start_text,
        "user_id": window.user_id,
        "source_ip": window.primary_source_ip,
        "alert_type": alert_type,
        "description": description,
        "triggered_rules": rule_result.triggered_rules,
        "ml_anomaly": ml_anomaly,
        "reasons": reasons,
        "rule_risk": rule_result.rule_risk,
        "ml_risk": round(float(ml_result["ml_risk"]), 2),
        "final_risk": risk_result.final_risk,
        "severity": risk_result.severity,
    }


def choose_alert_type(rule_result: RuleResult, ml_anomaly: bool) -> str:
    if rule_result.findings:
        return max(rule_result.findings, key=lambda item: item.risk).name
    if ml_anomaly:
        return BEHAVIORAL_ANOMALY_TYPE
    return "RISK_THRESHOLD"


def format_description(
    window: BehaviorWindow,
    alert_type: str,
    severity: str,
    final_risk: float,
    reasons: list[str],
) -> str:
    bullets = "\n".join(f"- {reason}" for reason in reasons)
    return (
        f"{severity} alert: {alert_type}\n\n"
        f"User: {window.user_id}\n"
        f"Source IP: {window.primary_source_ip}\n"
        f"Risk: {final_risk}\n\n"
        f"Reasons:\n{bullets}"
    )
