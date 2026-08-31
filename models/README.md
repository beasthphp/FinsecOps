# Model artifacts

`isolation_forest_pipeline.joblib` is the serialized scikit-learn pipeline used by the FinSecOps runtime.

The artifact stores the fitted preprocessing/model pipeline together with the feature ordering and anomaly-risk scaling metadata required for inference. It was trained on synthetic normal-behavior windows and is intended for this portfolio prototype only.

For reproducibility, the training entry point lives at `scripts/train_isolation_forest.py` and writes the model back into this directory.
