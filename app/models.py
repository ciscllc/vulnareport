import enum
import hashlib
import secrets
from datetime import datetime, timedelta

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


class DomainStatus(str, enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    BLACKLISTED = "blacklisted"
    REJECTED = "rejected"


class VerificationMethod(str, enum.Enum):
    EMAIL = "email"
    FILE = "file"
    ADMIN_QUEUE = "admin_queue"


class Role(str, enum.Enum):
    ADMIN = "admin"
    SYSADMIN = "sysadmin"


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(Role), default=Role.SYSADMIN, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    domains = db.relationship("Domain", back_populates="owner", lazy="dynamic")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN


class Domain(db.Model):
    __tablename__ = "domains"

    id = db.Column(db.Integer, primary_key=True)
    fqdn = db.Column(db.String(255), unique=True, nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    contact_email = db.Column(db.String(255), nullable=True)  # für Reports, falls abweichend
    verification_method = db.Column(db.Enum(VerificationMethod), nullable=False)
    status = db.Column(db.Enum(DomainStatus), default=DomainStatus.PENDING, nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified_at = db.Column(db.DateTime, nullable=True)
    blacklisted_at = db.Column(db.DateTime, nullable=True)
    last_scanned_at = db.Column(db.DateTime, nullable=True)
    admin_note = db.Column(db.Text, nullable=True)  # für Admin-Queue Begründung

    owner = db.relationship("User", back_populates="domains")
    tokens = db.relationship("VerificationToken", back_populates="domain", cascade="all, delete-orphan")
    findings = db.relationship("ScanResult", back_populates="domain", cascade="all, delete-orphan")
    mail_logs = db.relationship("MailLog", back_populates="domain", cascade="all, delete-orphan")

    def is_scannable(self) -> bool:
        return self.status == DomainStatus.VERIFIED

    def blacklist(self):
        self.status = DomainStatus.BLACKLISTED
        self.blacklisted_at = datetime.utcnow()


class VerificationToken(db.Model):
    __tablename__ = "verification_tokens"

    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id"), nullable=False)
    method = db.Column(db.Enum(VerificationMethod), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(32))
    target_email = db.Column(db.String(255), nullable=True)  # bei EMAIL-Methode
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(
        db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24)
    )
    confirmed_at = db.Column(db.DateTime, nullable=True)

    domain = db.relationship("Domain", back_populates="tokens")

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_confirmed(self) -> bool:
        return self.confirmed_at is not None


class Plugin(db.Model):
    __tablename__ = "plugins"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    version = db.Column(db.String(20), default="1.0")
    description = db.Column(db.Text, nullable=True)
    module_path = db.Column(db.String(255), nullable=False)  # Dateiname in PLUGIN_DIR
    checksum = db.Column(db.String(64), nullable=True)  # sha256 der Datei bei Aktivierung
    enabled = db.Column(db.Boolean, default=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    findings = db.relationship("ScanResult", back_populates="plugin")


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id"), nullable=False)
    plugin_id = db.Column(db.Integer, db.ForeignKey("plugins.id"), nullable=False)
    severity = db.Column(db.Enum(Severity), default=Severity.MEDIUM)
    title = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(500), nullable=True)
    detail = db.Column(db.Text, nullable=True)
    dedup_hash = db.Column(db.String(64), index=True, nullable=False)
    found_at = db.Column(db.DateTime, default=datetime.utcnow)
    mailed_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    domain = db.relationship("Domain", back_populates="findings")
    plugin = db.relationship("Plugin", back_populates="findings")

    @staticmethod
    def make_dedup_hash(domain_fqdn: str, plugin_name: str, path: str) -> str:
        raw = f"{domain_fqdn}|{plugin_name}|{path or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()


class MailLog(db.Model):
    __tablename__ = "mail_logs"

    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id"), nullable=False)
    scan_result_id = db.Column(db.Integer, db.ForeignKey("scan_results.id"), nullable=True)
    recipient = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending, sent, failed
    error = db.Column(db.Text, nullable=True)
    sent_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    domain = db.relationship("Domain", back_populates="mail_logs")
