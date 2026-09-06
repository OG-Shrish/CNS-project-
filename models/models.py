import datetime

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Float, Text
)
from sqlalchemy.orm import relationship

from database import Base


def now():
    return datetime.datetime.now()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    failed_login_attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=now)

    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)   # name on disk under encrypted/
    file_type = Column(String(32), nullable=False)          # extension, e.g. "pdf"
    file_size = Column(Integer, default=0)

    algorithm = Column(String(64), default="ChaCha20-Poly1305")
    active_key_version = Column(Integer, default=1)

    download_count = Column(Integer, default=0)

    # last computed risk snapshot (cached for dashboard display)
    last_risk_score = Column(Float, default=0.0)
    last_risk_level = Column(String(16), default="LOW")

    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)

    owner = relationship("User", back_populates="files")
    keys = relationship("KeyRecord", back_populates="file", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="file", cascade="all, delete-orphan")

    def active_key(self):
        for k in self.keys:
            if k.version == self.active_key_version:
                return k
        return None


class KeyRecord(Base):
    __tablename__ = "keys"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)

    version = Column(Integer, nullable=False)
    key_filename = Column(String(255), nullable=False)   # path under keys/
    fingerprint = Column(String(64), nullable=False)      # sha256 hex, truncated for display
    nonce_hex = Column(String(64), nullable=False)        # nonce used to encrypt file with this key
    status = Column(String(16), default="INACTIVE")       # ACTIVE / INACTIVE

    created_at = Column(DateTime, default=now)

    file = relationship("FileRecord", back_populates="keys")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=True)

    action = Column(String(32), nullable=False)   # LOGIN, FAILED_LOGIN, UPLOAD, DOWNLOAD, KEY_ROTATION, etc.
    old_version = Column(Integer, nullable=True)
    new_version = Column(Integer, nullable=True)
    risk_score = Column(Float, nullable=True)
    details = Column(Text, nullable=True)

    created_at = Column(DateTime, default=now)

    file = relationship("FileRecord", back_populates="audit_logs")
    user = relationship("User")
