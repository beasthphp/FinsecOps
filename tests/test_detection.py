from datetime import datetime
from pathlib import Path

import pytest

from app.alert_manager import build_alert
from app.feature_extractor import extract_behavior_windows
from app.log_generator import LogGenerator
from app.ml_detector import MLDetector
from app.risk_engine import combine_risk
from app.rule_engine import analyze_window


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest_pipeline.joblib"
BASE_TIME = datetime(2026, 8, 29, 10, 0, 0)


@pytest.fixture(scope="module")
def detector() -> MLDetector:
    return MLDetector(MODEL_PATH)


def single_window(events):
    windows = extract_behavior_windows(events)
    assert len(windows) == 1
    return windows[0]


def analyze_events(events, detector):
    window = single_window(events)
    rule_result = analyze_window(window)
    ml_result = detector.analyze_behavior(window.features)
    risk_result = combine_risk(
        rule_result.rule_risk,
        float(ml_result["ml_risk"]),
        triggered_rule_count=len(rule_result.triggered_rules),
    )
    alert = build_alert(window, rule_result, ml_result, risk_result)
    return window, rule_result, ml_result, risk_result, alert


def test_normal_user_has_no_major_alert(detector):
    generator = LogGenerator(seed=7)
    events = generator.generate_normal_activity(user_ids=["user_05"], base_time=BASE_TIME)

    _, rule_result, ml_result, risk_result, alert = analyze_events(events, detector)

    assert rule_result.rule_risk < 50
    assert float(ml_result["ml_risk"]) < 70
    assert risk_result.final_risk < 50
    assert alert is None


def test_brute_force_rule_detects_eight_failed_logins(detector):
    events = LogGenerator().simulate_brute_force(base_time=BASE_TIME)

    _, rule_result, _, risk_result, alert = analyze_events(events, detector)

    assert "BRUTE_FORCE" in rule_result.triggered_rules
    assert rule_result.rule_risk >= 70
    assert risk_result.severity == "HIGH"
    assert alert is not None
    assert alert["severity"] == "HIGH"


def test_privilege_misuse_rule_detects_employee_admin_access(detector):
    events = LogGenerator().simulate_privilege_misuse(base_time=BASE_TIME)

    _, rule_result, _, risk_result, alert = analyze_events(events, detector)

    assert "PRIVILEGE_MISUSE" in rule_result.triggered_rules
    assert risk_result.severity == "HIGH"
    assert alert is not None
    assert alert["severity"] == "HIGH"


def test_suspicious_login_creates_medium_alert(detector):
    events = LogGenerator().simulate_suspicious_login(base_time=BASE_TIME)

    _, rule_result, _, risk_result, alert = analyze_events(events, detector)

    assert "SUSPICIOUS_LOGIN" in rule_result.triggered_rules
    assert risk_result.severity == "MEDIUM"
    assert alert is not None
    assert alert["severity"] == "MEDIUM"


def test_data_exfiltration_rule_detects_large_download(detector):
    events = LogGenerator().simulate_data_exfiltration(base_time=BASE_TIME)

    _, rule_result, _, risk_result, alert = analyze_events(events, detector)

    assert "DATA_EXFILTRATION" in rule_result.triggered_rules
    assert risk_result.severity == "HIGH"
    assert alert is not None
    assert alert["severity"] == "HIGH"


def test_ml_anomaly_without_strong_rule_becomes_behavioral_alert(detector):
    events = LogGenerator().simulate_behavioral_anomaly(base_time=BASE_TIME)

    _, rule_result, ml_result, risk_result, alert = analyze_events(events, detector)

    assert "BRUTE_FORCE" not in rule_result.triggered_rules
    assert "DATA_EXFILTRATION" not in rule_result.triggered_rules
    assert bool(ml_result["is_anomaly"])
    assert risk_result.severity == "HIGH"
    assert alert is not None
    assert alert["alert_type"] == "BEHAVIORAL_ANOMALY"


def test_combined_attack_produces_critical_alert(detector):
    events = LogGenerator().simulate_mixed_attack(base_time=BASE_TIME)

    _, rule_result, ml_result, risk_result, alert = analyze_events(events, detector)

    assert "BRUTE_FORCE" in rule_result.triggered_rules
    assert "DATA_EXFILTRATION" in rule_result.triggered_rules
    assert bool(ml_result["is_anomaly"])
    assert risk_result.severity == "CRITICAL"
    assert alert is not None
    assert alert["severity"] == "CRITICAL"
