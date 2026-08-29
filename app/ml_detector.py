"""Isolation Forest inference for aggregated user behavior."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest_pipeline.joblib"


class MLDetector:
    """Loads the trained Isolation Forest pipeline once and scores feature rows."""

    def __init__(self, model_path: Path | str = DEFAULT_MODEL_PATH) -> None:
        self.model_path = Path(model_path)
        model_data = joblib.load(self.model_path)
        self.pipeline = model_data["pipeline"]
        self.feature_columns = list(model_data["feature_columns"])
        self.risk_scale = max(float(model_data["risk_scale"]), 1e-6)
        self.risk_note = model_data.get(
            "risk_note",
            "0-100 anomaly severity; not a probability.",
        )

    def analyze_behavior(self, features: dict[str, float]) -> dict[str, object]:
        row = np.array([[float(features[column]) for column in self.feature_columns]], dtype=float)
        decision_score = float(self.pipeline.decision_function(row)[0])
        ml_risk = self.to_risk(decision_score)
        return {
            "is_anomaly": decision_score < 0,
            "decision_score": decision_score,
            "ml_risk": ml_risk,
            "risk_note": self.risk_note,
        }

    def to_risk(self, decision_score: float) -> float:
        """Convert decision_function output to 0-100 anomaly severity."""

        if decision_score >= 0:
            return float(np.clip(70 * (1 - decision_score / self.risk_scale), 0, 70))
        return float(np.clip(70 + 30 * ((-decision_score) / self.risk_scale), 70, 100))

