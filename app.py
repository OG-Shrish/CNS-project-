import os
import shutil
import uuid

from fastapi import FastAPI, Request, Depends, UploadFile, File, Form
from fastapi.responses import RedirectResponse, StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
import io

from config import UPLOAD_DIR, SESSION_SECRET, DEMO_MODE_SHOW_KEY_EVIDENCE
from database import get_db, init_db
from models.models import User, FileRecord, KeyRecord, AuditLog
from auth.auth import hash_password, verify_password, get_current_user
from crypto import key_manager
from crypto.file_crypto import encrypt_file, decrypt_file
from ai.risk_engine import analyze, engine_status, get_active_engine
from logs.audit import log_event
from rotation import rotate_key, analyze_risk

from apscheduler.schedulers.background import BackgroundScheduler

app = FastAPI(title="Adaptive AI-Based Risk-Aware Key Rotation Framework")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def check_all_files_background():
    from database import SessionLocal
    db = SessionLocal()
    try:
        from models.models import FileRecord
        from rotation import analyze_risk, rotate_key
        files = db.query(FileRecord).all()
        for file_record in files:
            # Re-evaluate risk
            breakdown = analyze_risk(db, file_record)
            # If Medium, High, or Critical, rotate automatically
            if breakdown.rotation_required:
                rotate_key(db, file_record, forced=False)
    except Exception as e:
        print(f"Background monitoring error: {e}")
    finally:
        db.close()

@app.on_event("startup")
def on_startup():
    init_db()
    # Start the background risk monitoring job
    scheduler = BackgroundScheduler()
    scheduler.add_job(check_all_files_background, 'interval', minutes=1)
    scheduler.start()


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Username already taken."}
        )
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}
        )
    
    if not verify_password(password, user.password_hash):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        db.add(user)
        db.commit()
        log_event(db, action="FAILED_LOGIN", user_id=user.id, details="Invalid password attempt")
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}
        )

    user.failed_login_attempts = 0
    db.add(user)
    db.commit()
    
    log_event(db, action="LOGIN", user_id=user.id, details="Successful login")
    
    request.session["user_id"] = user.id
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    files = (
        db.query(FileRecord)
        .filter(FileRecord.owner_id == user.id)
        .order_by(FileRecord.created_at.desc())
        .all()
    )
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "files": files, "engine_status": engine_status()},
    )


# --------------------------------------------------------------------------
# Security Activity
# --------------------------------------------------------------------------

@app.get("/activity", response_class=HTMLResponse)
def activity_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # Fetch logs for user's files OR actions directly tied to user (like login)
    logs = (
        db.query(AuditLog)
        .outerjoin(FileRecord, AuditLog.file_id == FileRecord.id)
        .filter((AuditLog.user_id == user.id) | (FileRecord.owner_id == user.id))
        .order_by(AuditLog.created_at.desc())
        .limit(100)
        .all()
    )

    return templates.TemplateResponse(
        "activity_dashboard.html",
        {"request": request, "user": user, "logs": logs},
    )


# --------------------------------------------------------------------------
# Upload
# --------------------------------------------------------------------------

@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("upload.html", {"request": request, "user": user})


@app.post("/upload")
def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    original_filename = file.filename
    ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else ""
    stored_filename = f"{uuid.uuid4().hex}.enc"

    # save incoming file to a temp path first
    tmp_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{original_filename}")
    with open(tmp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    file_size = os.path.getsize(tmp_path)

    # create FileRecord first so we have an id for key naming
    file_record = FileRecord(
        owner_id=user.id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_type=ext,
        file_size=file_size,
        algorithm="ChaCha20-Poly1305",
        active_key_version=1,
    )
    db.add(file_record)
    db.commit()
    db.refresh(file_record)

    # generate v1 key, encrypt file
    key_bytes, key_filename = key_manager.save_new_key(file_record.id, version=1)
    nonce, ciphertext_size = encrypt_file(tmp_path, stored_filename, key_bytes)

    key_record = KeyRecord(
        file_id=file_record.id,
        version=1,
        key_filename=key_filename,
        fingerprint=key_manager.fingerprint(key_bytes),
        nonce_hex=nonce.hex(),
        status="ACTIVE",
    )
    db.add(key_record)

    file_record.file_size = ciphertext_size
    db.add(file_record)
    db.commit()

    os.remove(tmp_path)  # never keep unencrypted plaintext lying around

    log_event(
        db,
        file_id=file_record.id,
        user_id=user.id,
        action="UPLOAD",
        old_version=None,
        new_version=1,
        details=f"File '{original_filename}' uploaded. Key: {key_bytes.hex().upper()}",
    )

    # run an initial risk analysis so the dashboard has a score right away
    analyze_risk(db, file_record)

    return RedirectResponse(f"/file/{file_record.id}", status_code=303)


# --------------------------------------------------------------------------
# File detail (encryption details, risk analysis, rotation, audit log)
# --------------------------------------------------------------------------

@app.get("/file/{file_id}", response_class=HTMLResponse)
def file_detail(request: Request, file_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    file_record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.owner_id == user.id)
        .first()
    )
    if not file_record:
        return RedirectResponse("/dashboard", status_code=303)

    active_key = file_record.active_key()
    breakdown = analyze(file_record, active_key)

    active_key_bytes = key_manager.load_key(active_key.key_filename) if active_key else None

    audit_logs = (
        db.query(AuditLog)
        .filter_by(file_id=file_record.id)
        .order_by(AuditLog.created_at.desc())
        .all()
    )

    keys = sorted(file_record.keys, key=lambda k: k.version, reverse=True)
    for k in keys:
        try:
            k.raw_key_hex = key_manager.load_key(k.key_filename).hex().upper()
        except Exception:
            k.raw_key_hex = "UNAVAILABLE"

    status = engine_status()
    feature_importances = None
    model_info = None
    if status["is_ml"]:
        engine = get_active_engine()
        feature_importances = sorted(
            engine.feature_importances().items(), key=lambda kv: -kv[1]
        )
        model_info = engine.model_info()

    return templates.TemplateResponse(
        "file_detail.html",
        {
            "request": request,
            "user": user,
            "file": file_record,
            "active_key": active_key,
            "breakdown": breakdown,
            "audit_logs": audit_logs,
            "keys": keys,
            "engine_status": status,
            "feature_importances": feature_importances,
            "model_info": model_info,
        },
    )


@app.post("/file/{file_id}/analyze")
def trigger_analysis(request: Request, file_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    file_record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.owner_id == user.id)
        .first()
    )
    if file_record:
        analyze_risk(db, file_record)
    return RedirectResponse(f"/file/{file_id}", status_code=303)


@app.post("/file/{file_id}/rotate")
def trigger_rotation(
    request: Request,
    file_id: int,
    force: bool = Form(False),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    file_record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.owner_id == user.id)
        .first()
    )
    if file_record:
        rotate_key(db, file_record, forced=force)
    return RedirectResponse(f"/file/{file_id}", status_code=303)


@app.get("/file/{file_id}/download")
def download_file(request: Request, file_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    file_record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.owner_id == user.id)
        .first()
    )
    if not file_record:
        return RedirectResponse("/dashboard", status_code=303)

    active_key = file_record.active_key()
    key_bytes = key_manager.load_key(active_key.key_filename)
    nonce = bytes.fromhex(active_key.nonce_hex)
    plaintext = decrypt_file(file_record.stored_filename, key_bytes, nonce)

    file_record.download_count = (file_record.download_count or 0) + 1
    db.add(file_record)
    db.commit()

    log_event(
        db,
        file_id=file_record.id,
        user_id=user.id,
        action="DOWNLOAD",
        old_version=file_record.active_key_version,
        new_version=file_record.active_key_version,
        details="File decrypted and downloaded",
    )

    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{file_record.original_filename}"'},
    )


@app.post("/file/{file_id}/delete")
def delete_file(request: Request, file_id: int, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    file_record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.owner_id == user.id)
        .first()
    )
    if not file_record:
        return RedirectResponse("/dashboard", status_code=303)

    # 1. Delete encrypted file from disk
    from config import ENCRYPTED_DIR, KEYS_DIR
    encrypted_path = os.path.join(ENCRYPTED_DIR, file_record.stored_filename)
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
        
    # 2. Delete all associated key files from disk
    for key_record in file_record.keys:
        key_path = os.path.join(KEYS_DIR, key_record.key_filename)
        if os.path.exists(key_path):
            os.remove(key_path)

    original_name = file_record.original_filename

    # 3. Delete from database
    db.delete(file_record)
    db.commit()

    # 4. Log the deletion as a global action
    log_event(
        db,
        file_id=None,
        user_id=user.id,
        action="DELETE",
        details=f"Deleted file '{original_name}' permanently",
    )

    return RedirectResponse("/dashboard", status_code=303)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
