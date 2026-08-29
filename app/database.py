"""SQLite persistence for security events, ML results, and alerts."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import json
import sqlite3
from typing import Iterable, Iterator


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "finsecops.db"


@contextmanager
def connect(db_path: Path | str = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database(db_path: Path | str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                resource TEXT NOT NULL,
                success INTEGER NOT NULL,
                bytes_transferred INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_security_events_user_time
                ON security_events(user_id, timestamp);

            CREATE INDEX IF NOT EXISTS idx_security_events_type_time
                ON security_events(event_type, timestamp);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                window_start TEXT NOT NULL,
                user_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                description TEXT NOT NULL,
                triggered_rules TEXT NOT NULL,
                ml_anomaly INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                rule_risk REAL NOT NULL,
                ml_risk REAL NOT NULL,
                final_risk REAL NOT NULL,
                severity TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_time
                ON alerts(timestamp);

            CREATE TABLE IF NOT EXISTS ml_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                window_start TEXT NOT NULL,
                user_id TEXT NOT NULL,
                anomaly_prediction INTEGER NOT NULL,
                decision_score REAL NOT NULL,
                ml_risk REAL NOT NULL,
                features TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS risk_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                window_start TEXT NOT NULL,
                user_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                triggered_rules TEXT NOT NULL,
                ml_anomaly INTEGER NOT NULL,
                rule_risk REAL NOT NULL,
                ml_risk REAL NOT NULL,
                final_risk REAL NOT NULL,
                severity TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_risk_results_time
                ON risk_results(timestamp);
            """
        )


def reset_database(db_path: Path | str = DEFAULT_DB_PATH) -> None:
    initialize_database(db_path)
    with connect(db_path) as connection:
        connection.execute("DELETE FROM risk_results")
        connection.execute("DELETE FROM ml_results")
        connection.execute("DELETE FROM alerts")
        connection.execute("DELETE FROM security_events")


def insert_event(event: dict[str, object], db_path: Path | str = DEFAULT_DB_PATH) -> int:
    return insert_events([event], db_path)[0]


def insert_events(
    events: Iterable[dict[str, object]],
    db_path: Path | str = DEFAULT_DB_PATH,
) -> list[int]:
    initialize_database(db_path)
    rows = [
        (
            str(event["timestamp"]),
            str(event["user_id"]),
            str(event["role"]),
            str(event["source_ip"]),
            str(event["event_type"]),
            str(event["resource"]),
            int(bool(event["success"])),
            int(event.get("bytes_transferred", 0) or 0),
        )
        for event in events
    ]
    if not rows:
        return []

    with connect(db_path) as connection:
        cursor = connection.executemany(
            """
            INSERT INTO security_events (
                timestamp, user_id, role, source_ip, event_type, resource,
                success, bytes_transferred
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        last_id = cursor.lastrowid or connection.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]
        first_id = last_id - len(rows) + 1
        return list(range(first_id, last_id + 1))


def fetch_events(
    db_path: Path | str = DEFAULT_DB_PATH,
    limit: int | None = None,
) -> list[dict[str, object]]:
    initialize_database(db_path)
    query = "SELECT * FROM security_events ORDER BY timestamp ASC, id ASC"
    params: tuple[object, ...] = ()
    if limit is not None:
        query = "SELECT * FROM security_events ORDER BY timestamp DESC, id DESC LIMIT ?"
        params = (limit,)

    with connect(db_path) as connection:
        rows = [dict(row) for row in connection.execute(query, params).fetchall()]

    if limit is not None:
        rows.reverse()
    return rows


def insert_ml_result(
    result: dict[str, object],
    db_path: Path | str = DEFAULT_DB_PATH,
) -> int:
    initialize_database(db_path)
    with connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO ml_results (
                timestamp, window_start, user_id, anomaly_prediction,
                decision_score, ml_risk, features
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(result["timestamp"]),
                str(result["window_start"]),
                str(result["user_id"]),
                int(bool(result["anomaly_prediction"])),
                float(result["decision_score"]),
                float(result["ml_risk"]),
                json.dumps(result["features"], sort_keys=True),
            ),
        )
        return int(cursor.lastrowid)


def insert_alert(alert: dict[str, object], db_path: Path | str = DEFAULT_DB_PATH) -> int:
    initialize_database(db_path)
    with connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO alerts (
                timestamp, window_start, user_id, source_ip, alert_type,
                description, triggered_rules, ml_anomaly, reasons,
                rule_risk, ml_risk, final_risk, severity
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(alert["timestamp"]),
                str(alert["window_start"]),
                str(alert["user_id"]),
                str(alert["source_ip"]),
                str(alert["alert_type"]),
                str(alert["description"]),
                json.dumps(alert.get("triggered_rules", [])),
                int(bool(alert.get("ml_anomaly", False))),
                json.dumps(alert.get("reasons", [])),
                float(alert["rule_risk"]),
                float(alert["ml_risk"]),
                float(alert["final_risk"]),
                str(alert["severity"]),
            ),
        )
        return int(cursor.lastrowid)


def insert_risk_result(
    result: dict[str, object],
    db_path: Path | str = DEFAULT_DB_PATH,
) -> int:
    initialize_database(db_path)
    with connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO risk_results (
                timestamp, window_start, user_id, source_ip, triggered_rules,
                ml_anomaly, rule_risk, ml_risk, final_risk, severity
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(result["timestamp"]),
                str(result["window_start"]),
                str(result["user_id"]),
                str(result["source_ip"]),
                json.dumps(result.get("triggered_rules", [])),
                int(bool(result.get("ml_anomaly", False))),
                float(result["rule_risk"]),
                float(result["ml_risk"]),
                float(result["final_risk"]),
                str(result["severity"]),
            ),
        )
        return int(cursor.lastrowid)


def fetch_alerts(
    db_path: Path | str = DEFAULT_DB_PATH,
    limit: int | None = None,
) -> list[dict[str, object]]:
    initialize_database(db_path)
    query = "SELECT * FROM alerts ORDER BY timestamp DESC, id DESC"
    params: tuple[object, ...] = ()
    if limit is not None:
        query += " LIMIT ?"
        params = (limit,)

    with connect(db_path) as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]
