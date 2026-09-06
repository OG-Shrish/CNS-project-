"""
Risk scoring engine.

Current implementation: rule-based (deterministic, explainable — good for a
viva/demo since every point of the score can be justified).

Design note: this module is intentionally the ONLY place that knows how to
score risk. A future ML model (e.g. RandomForestRegressor) can be dropped in
by implementing the same `score(file_record, key_record)` interface and
swapping `get_active_engine()` — the rest of the app (rotation.py, app.py)
never needs to change. This keeps ML strictly optional/plug-in, matching the
project requirement that the deterministic pipeline must work without it.
"""

import datetime
from dataclasses import dataclass, field

from config import RISK_WEIGHTS, RISK_THRESHOLD

HIGH_RISK_EXTENSIONS = {"exe", "zip", "sql", "env", "pem", "key", "bak", "db"}
MEDIUM_RISK_EXTENSIONS = {"docx", "xlsx", "pdf", "pptx", "csv"}
# anything else (txt, png, jpg, md, ...) is treated as low risk


@dataclass
class RiskBreakdown:
    encryption_risk: float = 0.0
    file_type_risk: float = 0.0
    age_risk: float = 0.0
    key_age_risk: float = 0.0
    access_risk: float = 0.0
    failed_login_risk: float = 0.0
    time_risk: float = 0.0
    total: float = 0.0
    level: str = "LOW"
    threshold: int = RISK_THRESHOLD
    rotation_required: bool = False
    components: dict = field(default_factory=dict)
    explanations: list = field(default_factory=list)

    def as_dict(self):
        return {
            "encryption_risk": round(self.encryption_risk, 2),
            "file_type_risk": round(self.file_type_risk, 2),
            "age_risk": round(self.age_risk, 2),
            "key_age_risk": round(self.key_age_risk, 2),
            "access_risk": round(self.access_risk, 2),
            "failed_login_risk": round(self.failed_login_risk, 2),
            "time_risk": round(self.time_risk, 2),
            "total": round(self.total, 2),
            "level": self.level,
            "threshold": self.threshold,
            "rotation_required": self.rotation_required,
            "explanations": self.explanations,
        }


def _file_type_bucket(file_type: str) -> str:
    ext = (file_type or "").lower().lstrip(".")
    if ext in HIGH_RISK_EXTENSIONS:
        return "high"
    if ext in MEDIUM_RISK_EXTENSIONS:
        return "medium"
    return "low"


def _level_for(score: float) -> str:
    if score >= RISK_THRESHOLD:
        return "HIGH"
    if score >= RISK_THRESHOLD * 0.5:
        return "MEDIUM"
    return "LOW"


class RuleBasedRiskEngine:
    """Deterministic, explainable risk scoring."""

    name = "rule-based-v1"

    def score(self, file_record, key_record) -> RiskBreakdown:
        now = datetime.datetime.utcnow()
        w = RISK_WEIGHTS
        explanations = []

        # 1. Baseline risk for holding an encrypted secret at all.
        encryption_risk = w["encryption_risk"]

        # 2. File type risk — some file types are more sensitive/valuable.
        bucket = _file_type_bucket(file_record.file_type)
        file_type_risk = w["file_type_risk"][bucket]
        if bucket == "high":
            explanations.append("Sensitive file type accessed")

        # 3. File age risk — older files have had more time to be discovered/targeted.
        file_age_days = (now - file_record.created_at).days if file_record.created_at else 0
        age_risk = min(file_age_days * w["age_risk_per_day"], w["age_risk_cap"])

        # 4. Key age risk
        key_age_days = 0
        if key_record is not None and key_record.created_at:
            key_age_days = (now - key_record.created_at).days
        key_age_risk = min(key_age_days * w["key_age_risk_per_day"], w["key_age_risk_cap"])

        # 5. Access risk
        download_count = file_record.download_count or 0
        access_risk = min(download_count * w["access_risk_per_download"], w["access_risk_cap"])
        if download_count > 5:
            explanations.append("High file access frequency")

        # 6. Failed login attempts
        failed_logins = file_record.owner.failed_login_attempts if file_record.owner else 0
        failed_login_risk = min(failed_logins * 10.0, 30.0)
        if failed_logins > 0:
            explanations.append("Multiple failed logins detected on owner account")

        # 7. Unusual access time (e.g., outside 6 AM - 11 PM local time)
        local_hour = datetime.datetime.now().hour
        time_risk = 0.0
        if local_hour < 6 or local_hour >= 23:
            time_risk = 15.0
            explanations.append("Unusual access time (outside business hours)")

        total = encryption_risk + file_type_risk + age_risk + key_age_risk + access_risk + failed_login_risk + time_risk
        total = min(total, 100.0)

        level = _level_for(total)
        if len(explanations) == 0:
            explanations.append("Standard risk factors")

        breakdown = RiskBreakdown(
            encryption_risk=encryption_risk,
            file_type_risk=file_type_risk,
            age_risk=age_risk,
            key_age_risk=key_age_risk,
            access_risk=access_risk,
            failed_login_risk=failed_login_risk,
            time_risk=time_risk,
            total=total,
            level=level,
            threshold=RISK_THRESHOLD,
            rotation_required=total > RISK_THRESHOLD,
            explanations=explanations
        )
        return breakdown


# --- Engine selection --------------------------------------------------
#
# ai/ml_risk_engine.py implements a trained Random Forest model behind the
# exact same .score(file_record, key_record) interface as
# RuleBasedRiskEngine. Whichever engine is active, rotation.py and app.py
# never need to change — they just call analyze()/get_active_engine().
#
# If a trained model exists (ai/model/risk_model.joblib, produced by
# `python -m ai.train_model`), we use it. Otherwise we fall back to the
# deterministic rule-based engine, so the app always works out of the box
# even before training has been run.

_ACTIVE_ENGINE = None
_ENGINE_INIT_ERROR = None


def _init_engine():
    global _ACTIVE_ENGINE, _ENGINE_INIT_ERROR
    try:
        from ai.ml_risk_engine import MLRiskEngine
        _ACTIVE_ENGINE = MLRiskEngine()
    except Exception as e:  # model not trained yet, or ML deps missing
        _ENGINE_INIT_ERROR = str(e)
        _ACTIVE_ENGINE = RuleBasedRiskEngine()


_init_engine()


def get_active_engine():
    return _ACTIVE_ENGINE


def engine_status() -> dict:
    """For display in the UI — which engine is actually running right now."""
    return {
        "active_engine": _ACTIVE_ENGINE.name,
        "is_ml": _ACTIVE_ENGINE.name != RuleBasedRiskEngine.name,
        "fallback_reason": _ENGINE_INIT_ERROR,
    }


def analyze(file_record, key_record) -> RiskBreakdown:
    return get_active_engine().score(file_record, key_record)
