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
    #
    # A new automatic rotation is allowed only after the risk has
    # previously returned to the safe range since the last rotation.
    # We check by monotonic AuditLog.id to prevent clock skew issues.
    # ---------------------------------------------------------------
    if not forced and breakdown.rotation_required:
        last_rotation = (
            db.query(AuditLog)
            .filter(
                AuditLog.file_id == file_record.id,
                AuditLog.action == "KEY_ROTATION",
            )
            .order_by(AuditLog.id.desc())
            .first()
        )

        if last_rotation:
            safe_analysis_exists = (
                db.query(AuditLog)
                .filter(
                    AuditLog.file_id == file_record.id,
                    AuditLog.action == "RISK_ANALYSIS",
                    AuditLog.id > last_rotation.id,
                    AuditLog.risk_score <= breakdown.threshold,
                )
                .first()
            )

            if safe_analysis_exists is None:
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

            # Check if risk score or risk level has changed meaningfully
            old_score = file_record.last_risk_score
            old_level = file_record.last_risk_level
            score_diff = abs((old_score or 0.0) - breakdown.total)
            level_changed = old_level != breakdown.level

            if old_score is None or score_diff >= 0.5 or level_changed:
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