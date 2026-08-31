# Data artifacts

This directory contains local prototype data used by FinSecOps.

- `finsecops_behavior_dataset.csv` — synthetic one-hour user behavior windows used for the Isolation Forest prototype.
- `prototype_predictions.csv` — saved prototype predictions from the committed experiment.
- `training_summary.json` — compact metadata and evaluation results for the synthetic training run.
- `finsecops.db` — generated locally by the monitoring demo and intentionally ignored by Git.

The committed dataset and metrics are **synthetic prototype artifacts**. They are useful for reproducing the project pipeline, but they should not be interpreted as real-world SOC or attack-detection performance.
