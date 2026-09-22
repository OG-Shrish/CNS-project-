"""
Adaptive, risk-aware key rotation orchestration.

This is the core innovation of the project: instead of rotating keys on a
fixed schedule (e.g. every 30 days), we compute a risk score for the file
and only rotate when that score crosses RISK_THRESHOLD.

Flow:

    Analyze Risk
        |
    Risk > Threshold?
        |
       YES
        |
    Check State Machine (Already rotated for this event?)
        |
       NO
        |
    Decrypt with old key
    Generate new key
    Encrypt with new key
    Old key -> INACTIVE
    New key -> ACTIVE
    DB updated
    Audit log created
"""

import datetime

from sqlalchemy.orm import Session

from ai.risk_engine import analyze, RiskBreakdown
from crypto import key_manager
from crypto.file_crypto import decrypt_file, encrypt_bytes_to_disk
from logs.audit import log_event
from models.models import FileRecord, KeyRecord, AuditLog


def analyze_risk(
    db: Session, file_record: FileRecord, log_audit: bool = True
) -> RiskBreakdown:
    """Compute current risk for a file, cache it on the record, and log the analysis."""
    active_key = file_record.active_key()
    breakdown = analyze(file_record, active_key)

    file_record.last_risk_score = breakdown.total
    file_record.last_risk_level = breakdown.level

    db.add(file_record)
    db.commit()

    if log_audit:
        log_event(
            db,
            file_id=file_record.id,
            action="RISK_ANALYSIS",
            old_version=file_record.active_key_version,
            new_version=file_record.active_key_version,
            risk_score=breakdown.total,
            details=(
                f"encryption={breakdown.encryption_risk}, "
                f"file_type={breakdown.file_type_risk}, "
                f"age={breakdown.age_risk}, "
                f"key_age={breakdown.key_age_risk}, "
                f"access={breakdown.access_risk} "
                f"-> total={breakdown.total:.2f} ({breakdown.level})"
            ),
        )

    return breakdown


def is_rotation_eligible(db: Session, file_record: FileRecord, threshold: float = 30.0) -> bool:
    """
    Determine whether the current active key is eligible for rotation.

    State Machine Rules:
    1. If current active key is v1 (initial key), it has never been rotated -> ELIGIBLE.
    2. If current active key is v > 1, find the rotation that activated this key version (last_rotation).
    3. If no last_rotation record exists in audit logs -> ELIGIBLE.
    4. If the active key has experienced a SAFE state (risk <= threshold) at or after activation,
       then any subsequent risk > threshold is a NEW eligible high-risk event -> ELIGIBLE.
       A safe state is recognized if:
         a) last_rotation.risk_score <= threshold (key started in safe band), OR
         b) any audit log on or after last_rotation.id has risk_score <= threshold, OR
         c) file_record.last_risk_score <= threshold prior to crossing.
    5. Old key / historical rotation protection:
       If the key was created/rotated in a previous session or more than 1 hour ago,
       historical rotation records do not permanently block legitimate rotations -> ELIGIBLE.
    6. Otherwise, if the key was recently activated to handle a high-risk event and risk has
       continuously remained > threshold without returning to safe -> NOT ELIGIBLE (already handled; prevent loops).
    """
    active_key = file_record.active_key()
    if active_key is None or active_key.version <= 1:
        return True

    # Find the rotation event that created this current active key version
    last_rotation = (
        db.query(AuditLog)
        .filter(
            AuditLog.file_id == file_record.id,
            AuditLog.action == "KEY_ROTATION",
            AuditLog.new_version == active_key.version,
        )
        .order_by(AuditLog.id.desc())
        .first()
    )

    if last_rotation is None:
        return True

    # 1. Did this key version start in the safe range when rotated?
    if last_rotation.risk_score is not None and last_rotation.risk_score <= threshold:
        return True

    # 2. Was there any audit log on or after last_rotation with a safe score?
    safe_log = (
        db.query(AuditLog)
        .filter(
            AuditLog.file_id == file_record.id,
            AuditLog.id >= last_rotation.id,
            AuditLog.risk_score.isnot(None),
            AuditLog.risk_score <= threshold,
        )
        .first()
    )
    if safe_log is not None:
        return True

    # 3. Was the last recorded risk score on the file safe?
    if file_record.last_risk_score is not None and file_record.last_risk_score <= threshold:
        return True

    # 4. Old key / historical rotation protection:
    # If the key was created/rotated in a previous session or more than 1 hour ago,
    # historical rotation records do not permanently block legitimate rotations.
    now_dt = datetime.datetime.now()
    ref_time = last_rotation.created_at or active_key.created_at
    if ref_time:
        age_seconds = (now_dt - ref_time).total_seconds()
        if age_seconds > 3600:
            return True

    # Key was recently created for this high-risk event and threat has not subsided
    return False


def rotate_key(
    db: Session,
    file_record: FileRecord,
    forced: bool = False,
    breakdown: RiskBreakdown | None = None,
) -> dict:
    """
    Perform a full key rotation for a file.

    Automatic rotation happens only when:
        1. Current risk exceeds the threshold.
        2. The current high-risk condition has not already been handled.

    If risk returns to the safe range and later crosses the threshold again,
    another rotation is allowed (state machine behavior).

    Manual forced rotation bypasses the automatic risk-condition check.
    """
    old_key_record: KeyRecord = file_record.active_key()

    if old_key_record is None:
        raise ValueError("File has no active key to rotate from")

    # If breakdown wasn't precomputed by caller, compute it now
    if breakdown is None:
        breakdown = analyze(file_record, old_key_record)
        file_record.last_risk_score = breakdown.total
        file_record.last_risk_level = breakdown.level
        db.add(file_record)
        db.commit()

    # If risk is within the safe range, no automatic rotation is needed.
    if not forced and not breakdown.rotation_required:
        return {
            "rotated": False,
            "reason": "Risk below threshold — rotation not required.",
            "risk": breakdown.as_dict(),
        }

    # ---------------------------------------------------------------
    # State Machine: Prevent repeated rotations for the SAME high-risk condition.
    # ---------------------------------------------------------------
    if not forced and breakdown.rotation_required:
        if not is_rotation_eligible(db, file_record, breakdown.threshold):
            return {
                "rotated": False,
                "reason": (
                    "High-risk condition already handled. "
                    "Waiting for risk to return to the safe range "
                    "before allowing another automatic rotation."
                ),
                "risk": breakdown.as_dict(),
            }

    # ---------------------------------------------------------------
    # 1. Load and decrypt using the currently active key
    # ---------------------------------------------------------------
    old_key_bytes = key_manager.load_key(old_key_record.key_filename)
    old_nonce = bytes.fromhex(old_key_record.nonce_hex)
    plaintext = decrypt_file(
        file_record.stored_filename,
        old_key_bytes,
        old_nonce,
    )

    # ---------------------------------------------------------------
    # 2. Generate the next key version
    # ---------------------------------------------------------------
    new_version = old_key_record.version + 1
    new_key_bytes, new_key_filename = key_manager.save_new_key(
        file_record.id,
        new_version,
    )

    # ---------------------------------------------------------------
    # 3. Re-encrypt the file using the new key
    # ---------------------------------------------------------------
    new_nonce, ciphertext_size = encrypt_bytes_to_disk(
        plaintext,
        file_record.stored_filename,
        new_key_bytes,
    )

    # ---------------------------------------------------------------
    # 4. Update key lifecycle
    # ---------------------------------------------------------------
    old_key_record.status = "INACTIVE"

    new_key_record = KeyRecord(
        file=file_record,
        file_id=file_record.id,
        version=new_version,
        key_filename=new_key_filename,
        fingerprint=key_manager.fingerprint(new_key_bytes),
        nonce_hex=new_nonce.hex(),
        status="ACTIVE",
    )

    db.add(old_key_record)
    db.add(new_key_record)

    file_record.active_key_version = new_version
    file_record.file_size = ciphertext_size

    # Reset access threat counter after mitigation
    file_record.download_count = 0
    if file_record.owner:
        file_record.owner.failed_login_attempts = 0
        db.add(file_record.owner)

    db.add(file_record)
    db.commit()
    db.refresh(file_record)
    db.refresh(new_key_record)

    # ---------------------------------------------------------------
    # 5. Fresh post-rotation ML risk analysis using current state and new active key
    # ---------------------------------------------------------------
    post_breakdown = analyze(file_record, new_key_record)
    file_record.last_risk_score = post_breakdown.total
    file_record.last_risk_level = post_breakdown.level

    db.add(file_record)
    db.commit()
    db.refresh(file_record)

    # ---------------------------------------------------------------
    # 6. Audit trail (never log raw keys, use fingerprints only)
    # ---------------------------------------------------------------
    log_event(
        db,
        file_id=file_record.id,
        action="KEY_ROTATION",
        old_version=old_key_record.version,
        new_version=new_version,
        risk_score=post_breakdown.total,
        details=(
            f"Key rotated from v{old_key_record.version} to v{new_version}. "
            f"New key fingerprint: {key_manager.short_fingerprint(new_key_bytes)}"
        ),
    )

    log_event(
        db,
        file_id=file_record.id,
        action="RE_ENCRYPTION",
        old_version=old_key_record.version,
        new_version=new_version,
        risk_score=post_breakdown.total,
        details="File re-encrypted under new active key",
    )

    return {
        "rotated": True,
        "old_version": old_key_record.version,
        "new_version": new_version,
        "old_fingerprint": key_manager.short_fingerprint(old_key_bytes),
        "new_fingerprint": key_manager.short_fingerprint(new_key_bytes),
        "risk": post_breakdown.as_dict(),
    }


def check_all_files_background():
    """
    Background job executed by scheduler.
    Monitors risk for all files, logs significant transitions, and triggers
    automatic key rotation if high-risk thresholds are exceeded.
    """
    from database import SessionLocal

    db = SessionLocal()
    try:
        files = db.query(FileRecord).all()
        for file_record in files:
            active_key = file_record.active_key()
            if not active_key:
                continue

            breakdown = analyze(file_record, active_key)

            # Check if risk score or risk level has changed meaningfully, or crossed threshold
            old_score = file_record.last_risk_score
            old_level = file_record.last_risk_level
            score_diff = abs((old_score or 0.0) - breakdown.total)
            level_changed = old_level != breakdown.level
            threshold_crossed = (
                (old_score is not None) and (
                    (old_score > breakdown.threshold and breakdown.total <= breakdown.threshold) or
                    (old_score <= breakdown.threshold and breakdown.total > breakdown.threshold)
                )
            )

            if old_score is None or score_diff >= 0.5 or level_changed or threshold_crossed:
                file_record.last_risk_score = breakdown.total
                file_record.last_risk_level = breakdown.level
                db.add(file_record)
                db.commit()

                log_event(
                    db,
                    file_id=file_record.id,
                    action="RISK_ANALYSIS",
                    old_version=file_record.active_key_version,
                    new_version=file_record.active_key_version,
                    risk_score=breakdown.total,
                    details=(
                        f"Background risk assessment: "
                        f"total={breakdown.total:.2f} ({breakdown.level}) "
                        f"threshold={breakdown.threshold}"
                    ),
                )

            if breakdown.rotation_required:
                rotate_key(db, file_record, forced=False, breakdown=breakdown)
    except Exception as e:
        print(f"[Scheduler] Background monitoring error: {e}")
    finally:
        db.close()