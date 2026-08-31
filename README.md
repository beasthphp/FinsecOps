# FinSecOps — Security Monitoring & Risk Detection Prototype

FinSecOps is a cybersecurity monitoring prototype that turns authentication, database, and file-access activity into explainable security alerts.

It combines two complementary detection approaches:

```text
Rule-based threat detection
        +
Isolation Forest anomaly detection
        |
        v
Combined risk scoring
        |
        v
Prioritized security alerts
        |
        v
Streamlit monitoring dashboard
```

The project is intentionally a **small, working security-monitoring prototype**, not a production SIEM. Its purpose is to demonstrate how logs can be aggregated, analyzed, scored, and surfaced for investigation.

## What It Detects

- **Brute-force behavior** — repeated failed login attempts
- **Suspicious logins** — unusual authentication behavior such as new-IP activity
- **Privilege misuse** — abnormal administrative access
- **Potential data exfiltration** — unusually large or frequent downloads
- **Behavioral anomalies** — user activity that differs from the model's learned normal patterns
- **Mixed attacks** — scenarios where multiple suspicious signals occur together

## Architecture

```text
Synthetic Security Events
          |
          v
   SQLite Event Store
          |
     +----+------------------+
     |                       |
     v                       v
 Rule Engine          Feature Extractor
                             |
                             v
                     Isolation Forest
     |                       |
     +-----------+-----------+
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

## Detection Strategy

### 1. Rule engine

The deterministic rule engine captures suspicious patterns that have clear security meaning. This makes alerts easy to explain because the system can state which behavior triggered the rule.

### 2. Behavioral anomaly model

An `IsolationForest` model from scikit-learn evaluates one-hour user-behavior windows using these features:

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

The model was trained on synthetic normal-behavior rows and is used to assign anomaly severity to new behavior windows.

The ML score is **not an attack probability**. It represents model-derived anomaly severity.

### 3. Risk engine

Rule severity and ML anomaly severity are combined into a final risk score. Alerts are then assigned a severity level so the most suspicious activity can be reviewed first.

Each generated alert includes:

- rule risk score
- ML anomaly score
- final risk score
- severity
- explanation of the suspicious behavior

## Prototype ML Evaluation

The committed synthetic training experiment contains:

| Metric | Value |
| --- | ---: |
| Dataset rows | 6,000 |
| Normal rows | 5,425 |
| Synthetic anomaly rows | 575 |
| Normal-only training rows | 4,340 |
| Test rows | 1,660 |
| Anomaly precision | 0.9504 |
| Anomaly recall | 0.9670 |
| Anomaly F1 | 0.9586 |

These metrics only measure performance on the project's **synthetic prototype dataset**. They must not be interpreted as real-world cyberattack detection accuracy.

## Tech Stack

| Area | Technology |
| --- | --- |
| Core language | Python |
| Data processing | pandas, NumPy |
| Machine learning | scikit-learn, Isolation Forest |
| Model persistence | joblib |
| Event storage | SQLite |
| Dashboard | Streamlit |
| Testing | pytest |

## Project Layout

```text
app/                         Security monitoring core
dashboard/                   Streamlit investigation UI
data/                        Synthetic datasets and experiment metadata
docs/                        Prototype and ML notes
models/                      Serialized Isolation Forest pipeline
scripts/                     Simulation and training entry points
tests/                       Detection and risk-pipeline tests
requirements.txt             Runtime and test dependencies
README.md                    Project overview
```

Training artifacts are grouped under `data/` and `models/` so the repository root stays focused on the application. Runtime inference loads `models/isolation_forest_pipeline.joblib`.

## Run the Prototype

Install dependencies:

```bash
pip install -r requirements.txt
```

Generate the full demonstration dataset and alerts:

```bash
python scripts/run_simulation.py
```

Run an individual attack scenario:

```bash
python scripts/run_simulation.py --reset --scenario brute_force
```

Start the dashboard:

```bash
streamlit run dashboard/dashboard.py
```

Retrain the prototype Isolation Forest from the committed synthetic dataset:

```bash
python scripts/train_isolation_forest.py
```

## Suggested Demo Flow

1. Generate normal activity.
2. Verify that events appear in the event store/dashboard.
3. Run the brute-force scenario.
4. Inspect the resulting failed-login events and security alert.
5. Compare the rule score, ML score, final risk, and explanation.
6. Repeat with privilege misuse, suspicious login, data exfiltration, behavioral anomaly, and mixed-attack scenarios.

The default demo is calibrated so normal windows remain low risk while increasingly suspicious scenarios rise through medium, high, and critical severity.

## Testing

```bash
pytest
```

Tests cover representative normal and suspicious scenarios including:

- normal behavior
- brute force
- privilege misuse
- data exfiltration
- behavioral anomaly
- combined attack activity

## Engineering Decisions

### Rules + ML instead of ML alone

Known suspicious patterns are better represented by deterministic security rules, while Isolation Forest is useful for behavior that is unusual but not covered by a predefined signature. Combining both gives the prototype explainability and anomaly sensitivity.

### Unsupervised anomaly detection

Isolation Forest does not require labeled attack examples for training. That makes it a practical prototype choice for demonstrating user-behavior anomaly detection when the normal baseline is easier to model than every possible attack.

### Explainable alerts

The final alert keeps the rule and ML components separate instead of exposing only one opaque score. This makes it easier to understand why an alert was created.

### Small local architecture

SQLite, local model files, and a Streamlit dashboard keep the project easy to run and inspect. Distributed ingestion and large-scale SIEM infrastructure are intentionally outside the current scope.

## Current Scope & Limitations

This repository is a learning and portfolio prototype. It does **not** claim production SOC or SIEM capability.

Current limitations include:

- synthetic event generation rather than production log ingestion
- synthetic ML training/evaluation data
- no packet inspection
- no threat-intelligence feeds
- no automatic firewall or account-blocking actions
- no distributed event pipeline
- no Elasticsearch/Kafka infrastructure
- no cloud deployment

## Future Work

- ingest real structured authentication and system logs
- add user-specific behavioral baselines
- map alerts to MITRE ATT&CK techniques
- improve alert deduplication and correlation
- make detection thresholds configurable
- add richer investigation timelines
- evaluate anomaly models on more realistic datasets

## Interview Summary

> I built a Python security-monitoring prototype that analyzes authentication, database, and file-access events using deterministic threat rules and an Isolation Forest behavioral-anomaly model. A risk engine combines both signals into explainable severity-ranked alerts that are displayed in a Streamlit dashboard.
