"""Explainable rule-based detections for FinSecOps security behavior windows."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timedelta

from app.feature_extractor import BehaviorWindow, parse_timestamp
from app.log_generator import BASELINE_USER_IPS


BRUTE_FORCE_FAILED_LOGINS = 5
BRUTE_FORCE_WINDOW_MINUTES = 5
BRUTE_FORCE_RISK = 70.0

SUSPICIOUS_LOGIN_NEW_IP_RISK = 35.0
SUSPICIOUS_LOGIN_UNUSUAL_TIME_RISK = 25.0
SUSPICIOUS_LOGIN_BOTH_RISK = 55.0
UNUSUAL_LOGIN_START_HOUR = 0
UNUSUAL_LOGIN_END_HOUR = 5

PRIVILEGE_MISUSE_RISK = 80.0
DATA_EXFILTRATION_RISK = 75.0
DATA_EXFILTRATION_MB_THRESHOLD = 1000.0
DATA_EXFILTRATION_FILE_THRESHOLD = 100

ADDITIONAL_RULE_BONUS = 7.0


@dataclass(frozen=True)
class RuleFinding:
    name: str
    risk: float
    reason: str


@dataclass(frozen=True)
class RuleResult:
    triggered_rules: list[str]
    rule_risk: float
    reasons: list[str]
    findings: list[RuleFinding]


def analyze_window(
    window: BehaviorWindow,
    baseline_ips: dict[str, set[str]] | None = None,
) -> RuleResult:
    baseline = baseline_ips or BASELINE_USER_IPS
    findings = [
        finding
        for finding in (
            detect_brute_force(window),
            detect_suspicious_login(window, baseline),
            detect_privilege_misuse(window),
            detect_data_exfiltration(window),
        )
        if finding is not None
    ]
    if not findings:
        return RuleResult(triggered_rules=[], rule_risk=0.0, reasons=[], findings=[])

    scores = sorted((finding.risk for finding in findings), reverse=True)
    rule_risk = min(100.0, scores[0] + ADDITIONAL_RULE_BONUS * (len(scores) - 1))
    return RuleResult(
        triggered_rules=[finding.name for finding in findings],
        rule_risk=round(rule_risk, 2),
        reasons=[finding.reason for finding in findings],
        findings=findings,
    )


def detect_brute_force(window: BehaviorWindow) -> RuleFinding | None:
    failed = [
        event
        for event in sorted(window.events, key=lambda item: parse_timestamp(item["timestamp"]))
        if event["event_type"] == "LOGIN_FAILED"
    ]
    for index, event in enumerate(failed):
        start = parse_timestamp(event["timestamp"])
        end = start + timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        candidates = [
            item
            for item in failed[index:]
            if start <= parse_timestamp(item["timestamp"]) <= end
        ]
        by_ip = Counter(str(item["source_ip"]) for item in candidates)
        same_ip_count = by_ip.most_common(1)[0][1] if by_ip else 0
        same_user_count = len(candidates)
        count = max(same_ip_count, same_user_count)
        if count >= BRUTE_FORCE_FAILED_LOGINS:
            return RuleFinding(
                name="BRUTE_FORCE",
                risk=BRUTE_FORCE_RISK,
                reason=(
                    f"{count} failed login attempts detected within "
                    f"{BRUTE_FORCE_WINDOW_MINUTES} minutes."
                ),
            )
    return None


def detect_suspicious_login(
    window: BehaviorWindow,
    baseline_ips: dict[str, set[str]],
) -> RuleFinding | None:
    known_ips = baseline_ips.get(window.user_id, set())
    best: RuleFinding | None = None

    for event in window.events:
        if event["event_type"] != "LOGIN_SUCCESS":
            continue
        timestamp = parse_timestamp(event["timestamp"])
        new_ip = str(event["source_ip"]) not in known_ips
        unusual_time = UNUSUAL_LOGIN_START_HOUR <= timestamp.hour < UNUSUAL_LOGIN_END_HOUR

        if not (new_ip or unusual_time):
            continue

        if new_ip and unusual_time:
            risk = SUSPICIOUS_LOGIN_BOTH_RISK
            reason = (
                "Successful login came from a previously unseen IP during "
                "an unusual 00:00-05:00 time window."
            )
        elif new_ip:
            risk = SUSPICIOUS_LOGIN_NEW_IP_RISK
            reason = "Successful login came from a previously unseen IP address."
        else:
            risk = SUSPICIOUS_LOGIN_UNUSUAL_TIME_RISK
            reason = "Successful login occurred during an unusual 00:00-05:00 time window."

        finding = RuleFinding("SUSPICIOUS_LOGIN", risk, reason)
        if best is None or finding.risk > best.risk:
            best = finding

    return best


def detect_privilege_misuse(window: BehaviorWindow) -> RuleFinding | None:
    count = sum(1 for event in window.events if event["event_type"] == "ADMIN_ACCESS")
    if count and window.role != "admin":
        return RuleFinding(
            name="PRIVILEGE_MISUSE",
            risk=PRIVILEGE_MISUSE_RISK,
            reason=f"{count} admin access event(s) were performed by a {window.role} user.",
        )
    return None


def detect_data_exfiltration(window: BehaviorWindow) -> RuleFinding | None:
    download_mb = float(window.features["download_mb"])
    files_downloaded = int(window.features["files_downloaded"])
    crossed_mb = download_mb > DATA_EXFILTRATION_MB_THRESHOLD
    crossed_files = files_downloaded > DATA_EXFILTRATION_FILE_THRESHOLD

    if crossed_mb or crossed_files:
        return RuleFinding(
            name="DATA_EXFILTRATION",
            risk=DATA_EXFILTRATION_RISK,
            reason=(
                f"{files_downloaded} files and {download_mb:.0f} MB were downloaded "
                "within one hour."
            ),
        )
    return None
