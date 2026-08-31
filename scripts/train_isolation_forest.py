"""Train and evaluate the FinSecOps Isolation Forest prototype.

Dataset convention:
- One row represents one user's aggregated activity during one hour.
- ``scenario_label`` and ``is_anomaly`` are synthetic evaluation labels only.
- The Isolation Forest is trained on normal rows and never uses attack labels.

Risk score:
- ``decision_function > 0`` means the sample is more inlier-like.
- ``decision_function < 0`` means the sample is more anomalous.
- The model boundary (decision = 0) maps to a project risk score of 70.
- The 0-100 score is anomaly severity, not an attack probability.
"""

from pathlib import Path
import csv

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET = PROJECT_ROOT / "data" / "finsecops_behavior_dataset.csv"
MODEL_OUT = PROJECT_ROOT / "models" / "isolation_forest_pipeline.joblib"
PRED_OUT = PROJECT_ROOT / "data" / "prototype_predictions_retrained.csv"

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

pipeline = Pipeline(
    [
        ("scaler", StandardScaler()),
        (
            "model",
            IsolationForest(
                n_estimators=250,
                contamination=0.03,
                random_state=SEED,
                n_jobs=-1,
            ),
        ),
    ]
)

pipeline.fit(X_train)

train_decision = pipeline.decision_function(X_train)
test_decision = pipeline.decision_function(X_test)
pred = (test_decision < 0).astype(int)

positive_train = train_decision[train_decision > 0]
risk_scale = float(np.percentile(positive_train, 90)) if len(positive_train) else 0.1
risk_scale = max(risk_scale, 1e-6)


def to_risk(decision: float) -> float:
    """Convert an Isolation Forest decision score to 0-100 anomaly severity."""
    if decision >= 0:
        return float(np.clip(70 * (1 - decision / risk_scale), 0, 70))
    return float(np.clip(70 + 30 * ((-decision) / risk_scale), 70, 100))


risk = np.array([to_risk(float(d)) for d in test_decision])

print("Confusion matrix [normal, anomaly]:")
print(confusion_matrix(y_test, pred))
print()
print(classification_report(y_test, pred, target_names=["normal", "anomaly"], zero_division=0))

MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
PRED_OUT.parent.mkdir(parents=True, exist_ok=True)

joblib.dump(
    {
        "pipeline": pipeline,
        "feature_columns": FEATURES,
        "risk_scale": risk_scale,
        "risk_note": "0-100 normalized anomaly severity; not a probability.",
    },
    MODEL_OUT,
)

fields = list(rows[0].keys()) + ["if_decision", "predicted_anomaly", "ml_risk_score"]
with PRED_OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for idx, decision, prediction, risk_score in zip(test_idx, test_decision, pred, risk):
        item = dict(rows[int(idx)])
        item["if_decision"] = round(float(decision), 6)
        item["predicted_anomaly"] = int(prediction)
        item["ml_risk_score"] = round(float(risk_score), 2)
        writer.writerow(item)

print(f"Saved model: {MODEL_OUT}")
print(f"Saved predictions: {PRED_OUT}")
