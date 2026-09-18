"""
ML-based risk engine — loads the trained Random Forest model
(ai/model/risk_model.joblib) and uses it to predict a file's risk score.

Implements the exact same interface as RuleBasedRiskEngine
(`.score(file_record, key_record) -> RiskBreakdown`), so it's a drop-in
replacement — nothing in rotation.py or app.py needs to know which engine
is active.

For explainability on the dashboard, we still compute the same named
sub-factors (age risk, key-age risk, etc.) as reference "model inputs" —
these are the features the model actually saw, not an additive breakdown
of the ML score (a Random Forest isn't a simple sum of parts). The total
score is the model's prediction.
"""

import datetime
import os
import warnings

import joblib

from config import RISK_THRESHOLD
from ai.features import build_feature_vector, file_type_risk_level
from ai.risk_engine import RiskBreakdown, _level_for  # reuse level thresholds

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "risk_model.joblib")


class ModelNotTrainedError(RuntimeError):
    pass


class MLRiskEngine:
    """Random Forest risk predictor."""

    name = "ml-random-forest-v1"

    def __init__(self, model_path: str = MODEL_PATH):
        if not os.path.exists(model_path):
            try:
                from ai.train_model import train
                print(f"[MLRiskEngine] Model not found at {model_path}. Auto-training Random Forest model...")
                train()
            except Exception as e:
                raise ModelNotTrainedError(
                    f"No trained model found at {model_path} and auto-training failed: {e}."
                )

        if not os.path.exists(model_path):
            raise ModelNotTrainedError(
                f"No trained model found at {model_path}."
            )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            bundle = joblib.load(model_path)

        self.model = bundle["model"]
        self.feature_names = bundle["feature_names"]
        self.meta = {k: v for k, v in bundle.items() if k not in ("model",)}

    def score(self, file_record, key_record) -> RiskBreakdown:
        now = datetime.datetime.now()

        file_age_days = (now - file_record.created_at).days if file_record.created_at else 0
        key_age_days = (now - key_record.created_at).days if (key_record and key_record.created_at) else 0
        download_count = file_record.download_count or 0
        file_size_kb = (file_record.file_size or 0) / 1024.0

        features = build_feature_vector(
            file_age_days=file_age_days,
            key_age_days=key_age_days,
            file_type=file_record.file_type,
            download_count=download_count,
            file_size_kb=file_size_kb,
        )

        predicted = float(self.model.predict([features])[0])
        predicted = max(0.0, min(100.0, predicted))
        # 6. Failed login attempts
        failed_logins = file_record.owner.failed_login_attempts if file_record.owner else 0
        failed_login_risk = min(failed_logins * 10.0, 30.0)
        
        # 7. Unusual access time (e.g., outside 6 AM - 11 PM local time)
        local_hour = datetime.datetime.now().hour
        time_risk = 0.0
        if local_hour < 6 or local_hour >= 23:
            time_risk = 15.0

        # 8. Cryptographic Rotation Mitigation:
        # When a key is rotated (v2, v3, etc.), active threat mitigation takes effect.
        # Freshly rotated keys receive up to -15 points mitigation credit that decays as the key ages.
        rotation_mitigation = 0.0
        if key_record is not None and getattr(key_record, "version", 1) > 1:
            rotation_mitigation = max(0.0, 15.0 - (key_age_days * 1.5))

        # Combine Random Forest ML prediction with active context & rotation mitigation
        adjusted_predicted = min(100.0, max(0.0, predicted + failed_login_risk + time_risk - rotation_mitigation))
        level = _level_for(adjusted_predicted)
        
        explanations = []

        if rotation_mitigation > 0:
            explanations.append(
                f"Key rotated to v{key_record.version}: threat mitigated (-{rotation_mitigation:.0f} risk)"
            )

        if file_type_risk_level(file_record.file_type) > 1:
            explanations.append("Sensitive file type accessed")

        if download_count > 5:
            explanations.append("High file access frequency")

        if failed_logins > 0:
            explanations.append("Multiple failed logins detected on owner account")

        if time_risk > 0:
            explanations.append("Unusual access time (outside business hours)")

        if adjusted_predicted > RISK_THRESHOLD:
            explanations.append(
                f"ML predicted risk {adjusted_predicted:.0f} exceeds "
                f"rotation threshold {RISK_THRESHOLD}"
            )

        if len(explanations) == 0:
            explanations.append("Standard risk factors")
        # Reference sub-factors (for the "model inputs" panel in the UI)
        type_level = file_type_risk_level(file_record.file_type)
        breakdown = RiskBreakdown(
            encryption_risk=8.0,
            file_type_risk=type_level * 10.0,
            age_risk=min(file_age_days * 1.0, 25.0),
            key_age_risk=min(key_age_days * 1.5, 30.0),
            access_risk=min(download_count * 3.0, 15.0),
            failed_login_risk=failed_login_risk,
            time_risk=time_risk,
            rotation_mitigation=rotation_mitigation,
            total=adjusted_predicted,
            level=level,
            threshold=30,
            rotation_required=adjusted_predicted > 30,
            explanations=explanations
        )
        return breakdown

    def feature_importances(self) -> dict:
        return dict(zip(self.feature_names, [round(float(x), 4) for x in self.model.feature_importances_]))

    def model_info(self) -> dict:
        return {
            "engine": self.name,
            "trained_on": self.meta.get("trained_on"),
            "n_samples": self.meta.get("n_samples"),
            "mae": round(self.meta.get("mae", 0), 2),
            "r2": round(self.meta.get("r2", 0), 3),
        }
