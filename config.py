"""
Central configuration for the Adaptive AI-Based Risk-Aware Key Rotation Framework.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

for d in (UPLOAD_DIR, ENCRYPTED_DIR, KEYS_DIR, LOGS_DIR):
    os.makedirs(d, exist_ok=True)

DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}"

# --- Crypto ---
KEY_SIZE = 32       # 256-bit key
NONCE_SIZE = 12      # 96-bit nonce for ChaCha20-Poly1305

# --- Risk engine ---
RISK_THRESHOLD = 30  # score above this triggers rotation

# Prevent repeated automatic rotations while the same high-risk condition persists.
ROTATION_COOLDOWN_MINUTES = 5

RISK_WEIGHTS = {
    "encryption_risk": 10,   
    "file_type_risk": {
        "high": 15,   # e.g. .exe, .zip, .sql, .env, .pem
        "medium": 10,  # e.g. .docx, .xlsx, .pdf
        "low": 5,     # e.g. .txt, .csv, .png
    },
    "age_risk_per_day": 1,       
    "age_risk_cap": 25,
    "key_age_risk_per_day": 1.5,  
    "key_age_risk_cap": 30,
    "access_risk_per_download": 5,  # Increased from 3 to 5 to trigger risk faster
    "access_risk_cap": 25,
}

# session secret (demo only — in production load from env/secret manager)
SESSION_SECRET = os.environ.get("APP_SESSION_SECRET", "dev-secret-change-me-in-production")

# Background monitoring interval (in seconds)
MONITORING_INTERVAL_SECONDS = 30

# Demo mode: Production and security requirements forbid exposing secret key material.
DEMO_MODE_SHOW_KEY_EVIDENCE = False
