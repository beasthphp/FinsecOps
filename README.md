# FinSecOps

FinSecOps is a small cybersecurity monitoring prototype that combines deterministic threat-detection rules with an already-trained Isolation Forest model.

It is intentionally not a production SIEM. The goal is to demonstrate security event logging, feature aggregation, rule detection, behavioral anomaly detection, risk scoring, alert generation, and a Streamlit monitoring dashboard.

## Problem

Security teams receive large amounts of authentication, database, and file-access activity. Raw logs are useful, but they become much easier to triage when suspicious patterns are grouped, scored, and explained.

## Solution

FinSecOps combines:

```text
deterministic threat-detection rules
+
Isolation Forest behavioral anomaly detection
```

The rule engine catches known suspicious patterns. The Isolation Forest scores unusual one-hour user behavior without requiring attack labels. The final risk engine combines both signals into alert severity.

The ML risk score is anomaly severity, not an attack probability.
The demo alert threshold is `30`, so medium-risk suspicious behavior is visible while normal low-risk windows remain quiet.

## Architecture

```text
Security Events
      |
      v
SQLite Event Storage
      |
      +--> Rule Engine --------+
      |                        |
      +--> Feature Extractor   |
               |               |
               v               |
        Isolation Forest       |
               |               |
               +---------------+
                       |
                       v
                 Risk Engine
                       |
                       v
                 Alert Manager
                       |
                       v
              Streamlit Dashboard
```

## Current Detections

- Brute Force
- Suspicious Login
- Privilege Misuse
- Potential Data Exfiltration
- Behavioral Anomaly

## Project Layout

```text
app/
  alert_manager.py
  database.py
  event_store.py
  feature_extractor.py
  log_generator.py
  ml_detector.py
  risk_engine.py
  rule_engine.py
dashboard/
  dashboard.py
models/
  isolation_forest_pipeline.joblib
data/
  finsecops.db
scripts/
  run_simulation.py
tests/
  test_detection.py
```

The original training artifacts are kept at the project root for traceability. Runtime inference uses `models/isolation_forest_pipeline.joblib`.

## Run

Install dependencies:

```bash
pip install -r requirements.txt
```

Generate the full demo dataset and alerts:

```bash
python scripts/run_simulation.py
```

Run one scenario:

```bash
python scripts/run_simulation.py --reset --scenario brute_force
```

Start the dashboard:

```bash
streamlit run dashboard/dashboard.py
```

## Dashboard Demo

1. Generate normal traffic.
2. Confirm raw security events appear.
3. Simulate brute force.
4. Confirm failed-login events appear.
5. Confirm a high alert appears.
6. Repeat for suspicious login, privilege misuse, data exfiltration, behavioral anomaly, and mixed attack.

Each alert includes the rule and ML risk scores, final risk, severity, and an explanation of why the alert exists.
The default demo is calibrated to show a distribution: normal windows are low, the lighter suspicious-login scenario is medium, single-pattern attacks are high, and the mixed attack is critical.

## Testing

```bash
pytest
```

The tests cover normal behavior, brute force, privilege misuse, data exfiltration, a behavioral anomaly, and a combined attack.

## ML Notes

The Isolation Forest model was trained on normal synthetic one-hour user behavior rows. It receives features in this exact order:

```text
login_hour
failed_logins
successful_logins
unique_ips
new_ip_flag
file_access_count
files_downloaded
download_mb
db_queries
admin_access_count
unique_resources
```

Synthetic evaluation metrics are prototype validation only. They should not be presented as real-world cyberattack detection accuracy.

## Future Work

- Harder synthetic data generation
- More configurable detection thresholds
- Better alert deduplication
- User baseline management
- MITRE ATT&CK mapping
- Real log ingestion adapters

Out of scope for this prototype: Kafka, Redis, Elasticsearch, Kubernetes, deep learning, packet inspection, firewall blocking, automatic account disabling, distributed architecture, cloud deployment, and real-time threat intelligence.
