"""Run the FinSecOps security event simulation and processing pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.alert_manager import build_alert
from app.database import (
    DEFAULT_DB_PATH,
    fetch_events,
    initialize_database,
    insert_alert,
    insert_events,
    insert_ml_result,
    insert_risk_result,
    reset_database,
)
from app.feature_extractor import extract_behavior_windows, floor_to_hour
from app.log_generator import LogGenerator
from app.ml_detector import DEFAULT_MODEL_PATH, MLDetector
from app.risk_engine import combine_risk
from app.rule_engine import analyze_window


SCENARIOS = (
    "normal",
    "brute_force",
    "suspicious_login",
    "privilege_misuse",
    "data_exfiltration",
    "behavioral_anomaly",
    "mixed_attack",
)

DEMO_SCENARIOS = (
    "normal",
    "brute_force",
    "suspicious_login",
    "privilege_misuse",
    "data_exfiltration",
    "behavioral_anomaly",
    "mixed_attack",
)


def generate_and_process(
    scenario: str,
    db_path: Path | str = DEFAULT_DB_PATH,
    model_path: Path | str = DEFAULT_MODEL_PATH,
    seed: int | None = 42,
) -> dict[str, object]:
    generator = LogGenerator(seed=seed)
    events = generator.generate_scenario(scenario)
    initialize_database(db_path)
    insert_events(events, db_path)
    touched_windows = {
        (str(event["user_id"]), floor_to_hour(event["timestamp"]).isoformat())
        for event in events
    }
    summary = process_windows(
        db_path=db_path,
        model_path=model_path,
        touched_windows=touched_windows,
    )
    summary["scenario"] = scenario
    summary["events_generated"] = len(events)
    return summary


def process_windows(
    db_path: Path | str = DEFAULT_DB_PATH,
    model_path: Path | str = DEFAULT_MODEL_PATH,
    touched_windows: set[tuple[str, str]] | None = None,
) -> dict[str, object]:
    initialize_database(db_path)
    events = fetch_events(db_path)
    detector = MLDetector(model_path)
    windows = extract_behavior_windows(events)
    processed = 0
    alerts_created = 0
    alert_records: list[dict[str, object]] = []

    for window in windows:
        key = (window.user_id, window.window_start_text)
        if touched_windows is not None and key not in touched_windows:
            continue

        ml_result = detector.analyze_behavior(window.features)
        rule_result = analyze_window(window)
        risk_result = combine_risk(
            rule_result.rule_risk,
            float(ml_result["ml_risk"]),
            triggered_rule_count=len(rule_result.triggered_rules),
        )

        insert_ml_result(
            {
                "timestamp": window.timestamp,
                "window_start": window.window_start_text,
                "user_id": window.user_id,
                "anomaly_prediction": ml_result["is_anomaly"],
                "decision_score": ml_result["decision_score"],
                "ml_risk": ml_result["ml_risk"],
                "features": window.features,
            },
            db_path,
        )

        insert_risk_result(
            {
                "timestamp": window.timestamp,
                "window_start": window.window_start_text,
                "user_id": window.user_id,
                "source_ip": window.primary_source_ip,
                "triggered_rules": rule_result.triggered_rules,
                "ml_anomaly": ml_result["is_anomaly"],
                "rule_risk": rule_result.rule_risk,
                "ml_risk": ml_result["ml_risk"],
                "final_risk": risk_result.final_risk,
                "severity": risk_result.severity,
            },
            db_path,
        )

        alert = build_alert(window, rule_result, ml_result, risk_result)
        if alert is not None:
            insert_alert(alert, db_path)
            alert_records.append(alert)
            alerts_created += 1

        processed += 1

    return {
        "windows_processed": processed,
        "alerts_created": alerts_created,
        "alerts": alert_records,
    }


def run_demo(
    db_path: Path | str = DEFAULT_DB_PATH,
    model_path: Path | str = DEFAULT_MODEL_PATH,
    reset: bool = True,
) -> list[dict[str, object]]:
    if reset:
        reset_database(db_path)
    return [
        generate_and_process(scenario, db_path=db_path, model_path=model_path)
        for scenario in DEMO_SCENARIOS
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=SCENARIOS,
        help="Generate and process one scenario. Without this flag, the full demo runs.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear the demo SQLite database before running.",
    )
    parser.add_argument(
        "--keep-db",
        action="store_true",
        help="Do not reset the database before the default full demo.",
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help="Path to the SQLite database.",
    )
    parser.add_argument(
        "--model",
        default=str(DEFAULT_MODEL_PATH),
        help="Path to isolation_forest_pipeline.joblib.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db_path = Path(args.db)
    model_path = Path(args.model)

    if args.reset:
        reset_database(db_path)

    if args.scenario:
        summary = generate_and_process(args.scenario, db_path=db_path, model_path=model_path)
        print_summary([summary], db_path)
        return

    summaries = run_demo(db_path=db_path, model_path=model_path, reset=not args.keep_db and not args.reset)
    print_summary(summaries, db_path)


def print_summary(summaries: list[dict[str, object]], db_path: Path) -> None:
    total_events = sum(int(summary["events_generated"]) for summary in summaries)
    total_windows = sum(int(summary["windows_processed"]) for summary in summaries)
    total_alerts = sum(int(summary["alerts_created"]) for summary in summaries)

    print("FinSecOps simulation complete")
    print(f"Database: {db_path}")
    print(f"Events generated: {total_events}")
    print(f"Behavior windows processed: {total_windows}")
    print(f"Alerts created: {total_alerts}")
    print()

    for summary in summaries:
        print(
            f"- {summary['scenario']}: "
            f"{summary['events_generated']} events, "
            f"{summary['windows_processed']} windows, "
            f"{summary['alerts_created']} alerts"
        )
        for alert in summary["alerts"]:
            print(
                f"  {alert['severity']} {alert['alert_type']} "
                f"for {alert['user_id']} risk={alert['final_risk']}"
            )


if __name__ == "__main__":
    main()
