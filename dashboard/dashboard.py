"""Streamlit dashboard for the FinSecOps monitoring prototype."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import sys

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import DEFAULT_DB_PATH, initialize_database, reset_database
from scripts.run_simulation import generate_and_process


st.set_page_config(page_title="FinSecOps", page_icon="F", layout="wide")


def load_table(table: str) -> pd.DataFrame:
    initialize_database(DEFAULT_DB_PATH)
    with sqlite3.connect(DEFAULT_DB_PATH) as connection:
        return pd.read_sql_query(f"SELECT * FROM {table}", connection)


def run_action(scenario: str) -> None:
    summary = generate_and_process(scenario)
    st.session_state["last_action"] = (
        f"{summary['scenario']} generated {summary['events_generated']} events, "
        f"processed {summary['windows_processed']} window(s), "
        f"created {summary['alerts_created']} alert(s)."
    )
    st.rerun()


def reset_demo() -> None:
    reset_database(DEFAULT_DB_PATH)
    st.session_state["last_action"] = "Demo database reset."
    st.rerun()


st.title("FinSecOps")
st.caption("Security Monitoring Dashboard")

if "last_action" in st.session_state:
    st.success(st.session_state["last_action"])

events_df = load_table("security_events")
alerts_df = load_table("alerts")
ml_df = load_table("ml_results")
risk_df = load_table("risk_results")

controls = st.container()
with controls:
    st.subheader("Simulation")
    button_cols = st.columns(4)
    actions = [
        ("Generate Normal Traffic", "normal"),
        ("Simulate Brute Force", "brute_force"),
        ("Simulate Suspicious Login", "suspicious_login"),
        ("Simulate Privilege Misuse", "privilege_misuse"),
        ("Simulate Data Exfiltration", "data_exfiltration"),
        ("Simulate Behavioral Anomaly", "behavioral_anomaly"),
        ("Simulate Mixed Attack", "mixed_attack"),
    ]
    for index, (label, scenario) in enumerate(actions):
        with button_cols[index % len(button_cols)]:
            if st.button(label, use_container_width=True):
                run_action(scenario)
    with button_cols[-1]:
        if st.button("Reset Demo Database", use_container_width=True):
            reset_demo()

metric_cols = st.columns(4)
high_critical_count = 0
if not alerts_df.empty:
    high_critical_count = int(alerts_df["severity"].isin(["HIGH", "CRITICAL"]).sum())

ml_anomaly_count = 0
if not ml_df.empty:
    ml_anomaly_count = int(ml_df["anomaly_prediction"].sum())

metric_cols[0].metric("Total Security Events", len(events_df))
metric_cols[1].metric("Total Alerts", len(alerts_df))
metric_cols[2].metric("High/Critical Alerts", high_critical_count)
metric_cols[3].metric("ML Anomalies", ml_anomaly_count)

st.divider()

left, right = st.columns([1.4, 1])

with left:
    st.subheader("Recent Alerts")
    if alerts_df.empty:
        st.info("No alerts yet.")
    else:
        recent_alerts = alerts_df.sort_values(["timestamp", "id"], ascending=False).head(25)
        st.dataframe(
            recent_alerts[
                [
                    "timestamp",
                    "user_id",
                    "source_ip",
                    "alert_type",
                    "rule_risk",
                    "ml_risk",
                    "final_risk",
                    "severity",
                ]
            ].rename(
                columns={
                    "timestamp": "Timestamp",
                    "user_id": "User",
                    "source_ip": "IP",
                    "alert_type": "Alert Type",
                    "rule_risk": "Rule Risk",
                    "ml_risk": "ML Risk",
                    "final_risk": "Final Risk",
                    "severity": "Severity",
                }
            ),
            hide_index=True,
            use_container_width=True,
        )

        st.subheader("Alert Explanation")
        for _, row in recent_alerts.head(5).iterrows():
            with st.expander(f"{row['severity']} {row['alert_type']} for {row['user_id']}"):
                st.text(row["description"])

with right:
    st.subheader("Alerts by Type")
    if alerts_df.empty:
        st.info("No alert types to chart.")
    else:
        alert_types = alerts_df["alert_type"].value_counts().rename_axis("alert_type").to_frame("count")
        st.bar_chart(alert_types)

    st.subheader("Risk Distribution")
    if risk_df.empty:
        st.info("No risk distribution yet.")
    else:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        severity_counts = (
            risk_df["severity"]
            .value_counts()
            .reindex(order, fill_value=0)
            .rename_axis("severity")
            .to_frame("count")
        )
        st.bar_chart(severity_counts)

st.divider()

left, right = st.columns([1, 1.3])

with left:
    st.subheader("Suspicious Users")
    if risk_df.empty:
        st.info("No suspicious users yet.")
    else:
        suspicious_users = (
            risk_df.groupby("user_id")
            .agg(
                windows=("id", "count"),
                average_risk=("final_risk", "mean"),
                max_risk=("final_risk", "max"),
            )
            .sort_values(["max_risk", "average_risk"], ascending=False)
            .reset_index()
        )
        suspicious_users["average_risk"] = suspicious_users["average_risk"].round(2)
        st.dataframe(
            suspicious_users.rename(
                columns={
                    "user_id": "User",
                    "windows": "Windows",
                    "average_risk": "Average Risk",
                    "max_risk": "Max Risk",
                }
            ),
            hide_index=True,
            use_container_width=True,
        )

with right:
    st.subheader("Security Event Viewer")
    if events_df.empty:
        st.info("No security events yet.")
    else:
        recent_events = events_df.sort_values(["timestamp", "id"], ascending=False).head(100)
        st.dataframe(
            recent_events[
                [
                    "timestamp",
                    "user_id",
                    "role",
                    "source_ip",
                    "event_type",
                    "resource",
                    "success",
                    "bytes_transferred",
                ]
            ].rename(
                columns={
                    "timestamp": "Timestamp",
                    "user_id": "User",
                    "role": "Role",
                    "source_ip": "IP",
                    "event_type": "Event Type",
                    "resource": "Resource",
                    "success": "Success",
                    "bytes_transferred": "Bytes",
                }
            ),
            hide_index=True,
            use_container_width=True,
        )
