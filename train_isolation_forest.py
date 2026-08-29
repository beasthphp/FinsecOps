"""
FinSecOps Isolation Forest prototype.

Dataset convention:
- One row = one user's aggregated activity during one hour.
- scenario_label / is_anomaly exist ONLY so we can evaluate our synthetic prototype.
- The Isolation Forest is trained on normal rows only; it does NOT use attack labels.

Risk score:
- Isolation Forest decision_function > 0 => inlier / more normal
- decision_function < 0 => outlier / anomaly
- We map the boundary decision=0 to risk=70.
- Risk 0-100 is a project severity score, NOT a probability.
"""

from pathlib import Path
import csv
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix

BASE = Path(__file__).resolve().parent
DATASET = BASE / "finsecops_behavior_dataset.csv"
MODEL_OUT = BASE / "isolation_forest_pipeline.joblib"
PRED_OUT = BASE / "prototype_predictions_retrained.csv"

FEATURES = [
    "login_hour",
    "failed_logins",
    "successful_logins",
    "unique_ips",
    "new_ip_flag",
    "file_access_count",
    "files_downloaded",
    "download_mb",
    "db_queries",
    "admin_access_count",
    "unique_resources",
]

SEED = 42
rng = np.random.default_rng(SEED)

with DATASET.open("r", newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

X = np.array([[float(row[c]) for c in FEATURES] for row in rows], dtype=float)
y = np.array([int(row["is_anomaly"]) for row in rows], dtype=int)

normal_idx = np.where(y == 0)[0]
anomaly_idx = np.where(y == 1)[0]
rng.shuffle(normal_idx)
rng.shuffle(anomaly_idx)

split = int(len(normal_idx) * 0.80)
train_idx = normal_idx[:split]
test_idx = np.concatenate([normal_idx[split:], anomaly_idx])
rng.shuffle(test_idx)

X_train = X[train_idx]
X_test = X[test_idx]
y_test = y[test_idx]

pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("model", IsolationForest(
        n_estimators=250,
        contamination=0.03,
        random_state=SEED,
        n_jobs=-1,
    )),
])

pipeline.fit(X_train)

train_decision = pipeline.decision_function(X_train)
test_decision = pipeline.decision_function(X_test)
pred = (test_decision < 0).astype(int)

positive_train = train_decision[train_decision > 0]
risk_scale = float(np.percentile(positive_train, 90)) if len(positive_train) else 0.1
risk_scale = max(risk_scale, 1e-6)

def to_risk(decision):
    """Convert IF decision score to 0-100 severity; NOT a probability."""
    if decision >= 0:
        return float(np.clip(70 * (1 - decision / risk_scale), 0, 70))
    return float(np.clip(70 + 30 * ((-decision) / risk_scale), 70, 100))

risk = np.array([to_risk(d) for d in test_decision])

print("Confusion matrix [normal, anomaly]:")
print(confusion_matrix(y_test, pred))
print()
print(classification_report(y_test, pred, target_names=["normal", "anomaly"], zero_division=0))

joblib.dump({
    "pipeline": pipeline,
    "feature_columns": FEATURES,
    "risk_scale": risk_scale,
    "risk_note": "0-100 normalized anomaly severity; not a probability.",
}, MODEL_OUT)

fields = list(rows[0].keys()) + ["if_decision", "predicted_anomaly", "ml_risk_score"]
with PRED_OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for idx, d, p, r in zip(test_idx, test_decision, pred, risk):
        item = dict(rows[int(idx)])
        item["if_decision"] = round(float(d), 6)
        item["predicted_anomaly"] = int(p)
        item["ml_risk_score"] = round(float(r), 2)
        writer.writerow(item)

print(f"Saved model: {MODEL_OUT}")
print(f"Saved predictions: {PRED_OUT}")
