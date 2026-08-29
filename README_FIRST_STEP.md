# FinSecOps ML Prototype — First Dataset

## What this prototype represents

Each dataset row is **one user's activity aggregated over one hour**.

The ML model receives behavioral features such as:
- login hour
- failed/successful login counts
- unique IP count
- whether a new IP was observed
- file access/download counts
- total downloaded MB
- database query count
- admin-resource access count
- number of unique resources accessed

`scenario_label` and `is_anomaly` are **synthetic ground-truth columns for evaluation only**.
They are not ML input features.

## Synthetic scenarios

Normal behavior is the majority of the dataset. About 10% of rows contain a simulated:
- brute-force pattern
- data-exfiltration pattern
- privilege-misuse pattern
- suspicious-login pattern
- mixed anomaly

## Training

The Isolation Forest is trained on **normal rows only**.

This makes the problem closer to novelty/anomaly detection:
the model learns the shape of ordinary behavior and flags behavior that is unusually easy to isolate.

## Risk score

The model's `decision_function` is converted to a 0–100 **ML anomaly severity score**.

- decision > 0: model considers the row an inlier
- decision < 0: model considers the row an anomaly
- decision = 0 maps to risk score 70
- risk > 70 therefore means the model crossed its anomaly boundary

This risk score is **not a probability of attack**.

## Current generated dataset

- Total rows: 6000
- Normal rows: 5425
- Synthetic anomaly rows: 575
- Training rows (normal only): 4340
- Test rows: 1660

Prototype anomaly F1 on this synthetic test set: 0.9586

Do not treat this synthetic metric as real-world cybersecurity performance.
Its purpose is to verify that our pipeline works before we ingest real logs.

## Run it

```bash
pip install numpy scikit-learn joblib
python train_isolation_forest.py
```

## Next step

We should inspect the feature distributions and deliberately make the synthetic dataset harder.
After that, we can add a rule engine and combine:

`final risk = rule risk + ML anomaly contribution`

rather than relying on ML alone.
