# Adaptive AI-Based Risk-Aware Key Rotation Framework

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![Encryption](https://img.shields.io/badge/Cipher-ChaCha20--Poly1305-blueviolet.svg)](https://cryptography.io/)
[![ML Model](https://img.shields.io/badge/Model-Random%20Forest%20Regressor-brightgreen.svg)](https://scikit-learn.org/)

An enterprise-grade, intelligent cryptographic file storage framework. Instead of rotating encryption keys on arbitrary calendar schedules (e.g., every 30–90 days), the system continuously computes multi-factor exposure risk using an integrated **Random Forest Machine Learning model** and orchestrates **automatic key rotation and file re-encryption** the moment risk exceeds defined security thresholds.

---

## Key Highlights

- **Adaptive Key Rotation**: Keys rotate when threat conditions demand it, not on rigid fixed clocks.
- **Modern Authenticated Encryption**: Implements **ChaCha20-Poly1305 AEAD** (256-bit key, 96-bit nonce) offering both integrity and confidentiality.
- **Real Random Forest ML Engine**: Evaluates file metadata, access frequency, credential anomalies, and key aging (trained on 6,000 samples; MAE ≈ 3.3, R² ≈ 0.94).
- **Autonomous Background Monitoring**: Built-in APScheduler constantly surveys assets and executes rotations without manual intervention or browser dependencies.
- **State-Machine Rotation Control**: Enforces single-rotation transitions ($v_1 \rightarrow v_2$) for sustained threats, avoiding cascading re-encryption loops.
- **Active Post-Rotation Mitigation**: Automatically recalculates risk with fresh active keys, visibly reducing the risk score (e.g., from 43 to 27 / LOW) upon mitigation.
- **Zero-Exposure Cryptographic Hygiene**: Secret key bytes and hex strings are never displayed on the UI or written to audit logs; keys are tracked strictly via truncated SHA-256 fingerprints.

---

## Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/ANISHASHARMA0307/adaptive-ai-key-rotation.git
cd adaptive-ai-key-rotation

# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate      # Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt -r requirements-ml.txt
```

### 2. Run Application
```bash
python app.py
```

### 3. Access Dashboard
Open **[http://localhost:8000](http://localhost:8000)** (or `http://127.0.0.1:8000`) in your browser:
- Register an account or log in.
- The ML engine initializes automatically on boot—no separate training or worker processes are required.

---

## System Architecture & Execution Flow

```text
 Upload File (.zip, .pdf, etc.)
       │
       ▼
 Encrypt with ChaCha20-Poly1305 (Key v1 ACTIVE)
       │
       ▼
 Random Forest ML Risk Assessment
       │
       ├────────────────────────────────────────┐
       ▼                                        ▼
 Risk ≤ 30 (LOW)                        Risk > 30 (MEDIUM / HIGH)
 (e.g., PDF ≈ 29.7)                     (e.g., ZIP ≈ 42.0)
       │                                        │
 [Safe Range]                                   ▼
 Key v1 remains ACTIVE                  Background Scheduler Triggered
 No rotation required                           │
                                                ▼
                                        Decrypt with v1 Key
                                                │
                                                ▼
                                        Generate Key v2 (256-bit)
                                                │
                                                ▼
                                        Re-encrypt File Blob
                                                │
                                                ▼
                                        v1 ➔ INACTIVE | v2 ➔ ACTIVE
                                                │
                                                ▼
                                        Fresh Post-Rotation ML Analysis
                                        (Threat mitigated: Score drops to 27 LOW)
                                                │
                                                ▼
                                        Audit Logs Recorded (Fingerprints only)
                                                │
                                                ▼
                                        Live UI Updates Automatically (v2 ACTIVE)
```

---

## Risk Scoring & Mitigation Model

Risk is evaluated on a **0–100 scale** with a **Threshold of 30**:

| Score Tier | Level | Action Taken |
|---|---|---|
| **0 – 30** | `LOW` | **Safe**: Key remains active; monitoring continues. |
| **31 – 60** | `MEDIUM` | **Rotation Required**: Background scheduler automatically rotates active key. |
| **61 – 80** | `HIGH` | **High Threat**: Rapid rotation + mitigation logging. |
| **81 – 100** | `CRITICAL` | **Severe Threat**: Compromised access indicators (multiple failed logins, abnormal hours). |

### Contributing Factors
- **Intrinsic Sensitivity**: Extension categorization (e.g., high-exposure `.zip`, `.exe`, `.sql` vs standard `.pdf`, `.docx`).
- **Cryptographic Key Age**: Aging keys compound exposure over time.
- **Access Anomaly**: Spike in download frequency.
- **Authentication Anomalies**: Failed login attempts tied to the file owner's account.
- **Temporal Anomalies**: Access outside standard business hours (e.g., late-night queries).
- **Rotation Mitigation**: Active cryptographic mitigation grants **-15 risk credit** upon key renewal, returning scores to the safe band.

---

## Verification & Testing Guide

### Test 1: Low-Risk File (PDF)
1. Upload a standard `.pdf` document.
2. Initial ML score produces $\approx \mathbf{29.7}$ (`LOW`).
3. Key remains **`v1 ACTIVE`**; scheduler cycles confirm no rotation occurs.

### Test 2: High-Risk Automatic Rotation (ZIP)
1. Upload a `.zip` archive.
2. ML predicts $\approx \mathbf{42.0}$ (`MEDIUM` $\rightarrow$ **ROTATION REQUIRED**).
3. Without refreshing or clicking buttons, wait **15–30 seconds**.
4. The background scheduler rotates key:
   - `v1` $\rightarrow$ `INACTIVE`
   - `v2` $\rightarrow$ `ACTIVE`
   - Risk score automatically updates to $\approx \mathbf{27.0}$ (`LOW`).
   - Audit trail registers `KEY_ROTATION` and `RE_ENCRYPTION`.
5. Subsequent cycles keep `v2` steady without infinite rotation loops.

### Test 3: Account Threat Simulation & Reset
1. Attempt invalid logins to trigger `failed_login_attempts`.
2. File risk spikes beyond threshold.
3. System rotates to the next key version (`v3`), resets failed login penalties, and brings the asset back to safety.

---

## Project Directory Layout

```text
adaptive-ai-key-rotation/
├── app.py                     # FastAPI application, auth, file routes & API
├── rotation.py                # State-machine rotation orchestration & monitoring
├── config.py                  # Cryptographic & scheduler configurations
├── database.py                # SQLAlchemy SQLite session manager
│
├── ai/
│   ├── risk_engine.py         # Unified risk scoring interface & baseline engine
│   ├── ml_risk_engine.py      # Random Forest ML model loader & feature evaluator
│   ├── features.py            # Feature vector extractor (train & inference parity)
│   ├── train_model.py         # Random Forest training script (6,000 synthetic samples)
│   └── model/
│       └── risk_model.joblib  # Pre-trained Random Forest model artifact
│
├── crypto/
│   ├── chacha.py              # Low-level ChaCha20-Poly1305 encryption primitives
│   ├── file_crypto.py         # File read/write/re-encryption handler
│   └── key_manager.py         # 256-bit key generator & SHA-256 fingerprinting
│
├── models/
│   └── models.py              # User, FileRecord, KeyRecord, and AuditLog schemas
├── logs/
│   └── audit.py               # Cryptographically sanitized security event logger
│
├── templates/                 # Jinja2 HTML templates (Dashboard, File Detail, Auth)
└── static/                    # Responsive CSS stylesheet
```

---

## Security & Compliance Considerations

- **Fingerprints Only**: Keys are identified in the UI and database exclusively by their truncated SHA-256 fingerprint (e.g., `7A8087A1998F...`).
- **Immutable Key History**: Prior keys are never deleted; they are preserved as `INACTIVE` to ensure forensic auditability and historical decryption verification.
- **Ephemeral Plaintext**: Uploaded plaintext files are unlinked from disk immediately following encryption; only ciphertext blobs persist.
- **Bcrypt Password Storage**: Passwords are cryptographically salted and hashed using `passlib[bcrypt]`.
