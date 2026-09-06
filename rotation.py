"""
Adaptive, risk-aware key rotation orchestration.

This is the core innovation of the project: instead of rotating keys on a
fixed schedule (e.g. every 30 days), we compute a risk score for the file
and only rotate when that score crosses RISK_THRESHOLD.

Flow (mirrors the project brief):

    Analyze Risk
        |
    Risk > Threshold?
        |
       YES
        |
    Decrypt with old key (v_n)
    Generate new key (v_n+1)
    Encrypt with new key
    Old key -> INACTIVE   (kept on disk + in DB for history, never deleted)
    New key -> ACTIVE
    DB updated
    Audit log created
"""

from sqlalchemy.orm import Session

from ai.risk_engine import analyze
from crypto import key_manager
from crypto.file_crypto import decrypt_file, encrypt_bytes_to_disk
from logs.audit import log_event
from models.models import FileRecord, KeyRecord


def analyze_risk(db: Session, file_record: FileRecord) -> "RiskBreakdown":  # noqa: F821
    """Compute current risk for a file, cache it on the record, and log the analysis."""
    active_key = file_record.active_key()
    breakdown = analyze(file_record, active_key)

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
            f"encryption={breakdown.encryption_risk}, file_type={breakdown.file_type_risk}, "
            f"age={breakdown.age_risk}, key_age={breakdown.key_age_risk}, "
            f"access={breakdown.access_risk} -> total={breakdown.total} ({breakdown.level})"
        ),
    )
    return breakdown


def rotate_key(db: Session, file_record: FileRecord, forced: bool = False) -> dict:
    """
    Perform a full key rotation for a file:
      1. Re-check risk (unless forced).
      2. Decrypt file with the currently active key.
      3. Generate + persist a brand-new key (next version).
      4. Re-encrypt the file under the new key.
      5. Flip active/inactive status, bump file_record.active_key_version.
      6. Write RE_ENCRYPTION and KEY_ROTATION audit entries.

    Returns a dict summarising what happened, for the UI to display.
    """
    old_key_record: KeyRecord = file_record.active_key()
    if old_key_record is None:
        raise ValueError("File has no active key to rotate from")

    breakdown = analyze_risk(db, file_record)

    if not forced and not breakdown.rotation_required:
        return {
            "rotated": False,
            "reason": "Risk below threshold — rotation not required.",
            "risk": breakdown.as_dict(),
        }

    # 1. Load + decrypt with old key
    old_key_bytes = key_manager.load_key(old_key_record.key_filename)
    old_nonce = bytes.fromhex(old_key_record.nonce_hex)
    plaintext = decrypt_file(file_record.stored_filename, old_key_bytes, old_nonce)

    # 2. Generate new key (next version)
    new_version = old_key_record.version + 1
    new_key_bytes, new_key_filename = key_manager.save_new_key(file_record.id, new_version)

    # 3. Re-encrypt file under the new key (same stored_filename — file replaced in place)
    new_nonce, ciphertext_size = encrypt_bytes_to_disk(
        plaintext, file_record.stored_filename, new_key_bytes
    )

    # 4. Persist new KeyRecord, flip old one inactive
    old_key_record.status = "INACTIVE"
    new_key_record = KeyRecord(
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
    file_record.download_count = 0  # Reset threat counter after mitigating
    if file_record.owner:
        file_record.owner.failed_login_attempts = 0
        db.add(file_record.owner)
        
    db.add(file_record)
    db.commit()
    db.refresh(new_key_record)

    # 5. Audit trail
    log_event(
        db,
        file_id=file_record.id,
        action="KEY_ROTATION",
        old_version=old_key_record.version,
        new_version=new_version,
        risk_score=breakdown.total,
        details=f"Key rotated from v{old_key_record.version} to v{new_version}. New Key: {new_key_bytes.hex().upper()}",
    )
    log_event(
        db,
        file_id=file_record.id,
        action="RE_ENCRYPTION",
        old_version=old_key_record.version,
        new_version=new_version,
        risk_score=breakdown.total,
        details="File re-encrypted under new active key",
    )

    return {
        "rotated": True,
        "old_version": old_key_record.version,
        "new_version": new_version,
        "old_fingerprint": key_manager.short_fingerprint(old_key_bytes),
        "new_fingerprint": key_manager.short_fingerprint(new_key_bytes),
        "risk": breakdown.as_dict(),
    }
