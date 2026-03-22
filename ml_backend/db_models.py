import uuid
from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    Numeric,
    Boolean,
    ForeignKey,
    UniqueConstraint,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email"),)

    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True))

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "user_id": str(self.user_id),
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index('idx_scan_user_file', 'user_id', 'file_name'),
    )

    scan_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), default=uuid.UUID("356721c8-1559-4c00-9aec-8be06d861028"))
    generated_at = Column(TIMESTAMP(timezone=True))
    file_name = Column(String(255))
    total_logs = Column(Integer, nullable=False)
    total_threats = Column(Integer, nullable=False)
    risk_score = Column(Integer, nullable=False)
    threat_density = Column(Numeric(10, 2))
    normalized_density = Column(Numeric(10, 2))
    active_rules = Column(Integer)
    rule_ml_agreement = Column(Numeric(5, 2))
    terminal_summary = Column(Text)
    ai_briefing = Column(Text)
    # windows | android | NULL (legacy scans)
    log_platform = Column(String(16))

    user = relationship("User", back_populates="scans")
    categories = relationship("AnomalyCategory", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("AnomalousEvent", back_populates="scan", cascade="all, delete-orphan")
    android_logs = relationship("AndroidLog", back_populates="scan", cascade="all, delete-orphan")
    chains = relationship("AttackChain", back_populates="scan", cascade="all, delete-orphan")
    travels = relationship("ImpossibleTravel", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "scan_id": str(self.scan_id),
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "file_name": self.file_name,
            "total_logs": self.total_logs,
            "total_threats": self.total_threats,
            "risk_score": self.risk_score,
            "threat_density": float(self.threat_density) if self.threat_density else None,
            "normalized_density": float(self.normalized_density) if self.normalized_density else None,
            "active_rules": self.active_rules,
            "rule_ml_agreement": float(self.rule_ml_agreement) if self.rule_ml_agreement else None,
            "log_platform": self.log_platform,
        }


class AnomalyCategory(Base):
    __tablename__ = "anomaly_categories"
    __table_args__ = (
        UniqueConstraint("scan_id", "category_name"),
        Index('idx_category_scan', 'scan_id'),
    )

    category_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"))
    category_name = Column(String(100), nullable=False)
    mitre_id = Column(String(20))
    tactic = Column(String(100))
    risk_score = Column(Integer, nullable=False)
    event_count = Column(Integer, nullable=False)
    ai_summary = Column(Text)

    scan = relationship("Scan", back_populates="categories")
    events = relationship("AnomalousEvent", back_populates="category", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "category_id": str(self.category_id),
            "category_name": self.category_name,
            "mitre_id": self.mitre_id,
            "tactic": self.tactic,
            "risk_score": self.risk_score,
            "event_count": self.event_count,
            "ai_summary": self.ai_summary,
        }


class AndroidLog(Base):
    """ORM for ``android_logs`` — matches the Supabase DDL you applied (same as create_android_logs.sql)."""

    __tablename__ = "android_logs"
    __table_args__ = (
        Index("ix_android_logs_scan_logged", "scan_id", "logged_at"),
        Index("ix_android_logs_package_r", "package_r"),
        Index(
            "ix_android_logs_anomalous",
            "scan_id",
            postgresql_where=text("is_anomalous = TRUE"),
        ),
    )

    android_log_id = Column(
        "android_log_id",
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.scan_id", ondelete="CASCADE"),
        nullable=False,
    )

    logged_at = Column(TIMESTAMP(timezone=True), nullable=False)
    pid = Column(Integer)
    tid = Column(Integer)
    level = Column(Text)
    tag = Column(Text)
    package_r = Column(Text)
    detail = Column(Text)

    score = Column(Integer)
    penalty = Column(Integer)
    root = Column(Integer)
    selinux = Column(Integer)
    adb = Column(Integer)
    devopts = Column(Integer)
    mock = Column(Integer)
    temp = Column(Integer)
    ram = Column(Integer)
    net = Column(Text)

    label = Column(Text)
    is_anomalous = Column(Boolean, nullable=False, default=False)
    attack_category = Column(Text, nullable=False, default="Normal")

    scan = relationship("Scan", back_populates="android_logs")

    def to_dict(self):
        return {
            "android_log_id": str(self.android_log_id),
            "scan_id": str(self.scan_id),
            "logged_at": self.logged_at.isoformat() if self.logged_at else None,
            "pid": self.pid,
            "tid": self.tid,
            "level": self.level,
            "tag": self.tag,
            "package_r": self.package_r,
            "detail": self.detail,
            "score": self.score,
            "penalty": self.penalty,
            "root": self.root,
            "selinux": self.selinux,
            "adb": self.adb,
            "devopts": self.devopts,
            "mock": self.mock,
            "temp": self.temp,
            "ram": self.ram,
            "net": self.net,
            "label": self.label,
            "is_anomalous": self.is_anomalous,
            "attack_category": self.attack_category,
        }


class AnomalousEvent(Base):
    __tablename__ = "anomalous_events"
    __table_args__ = (
        Index('idx_event_scan', 'scan_id'),
    )

    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"))
    category_id = Column(UUID(as_uuid=True), ForeignKey("anomaly_categories.category_id", ondelete="CASCADE"))
    time_logged = Column(TIMESTAMP(timezone=True), nullable=False)
    windows_event_id = Column(Integer)
    user_account = Column(String(255))
    computer = Column(String(255), nullable=False)
    task_category = Column(String(100))

    scan = relationship("Scan", back_populates="events")
    category = relationship("AnomalyCategory", back_populates="events")

    def to_dict(self, category_name: str = None):
        return {
            "event_id": str(self.event_id),
            "category": category_name,
            "time_logged": self.time_logged.isoformat() if self.time_logged else None,
            "windows_event_id": self.windows_event_id,
            "user_account": self.user_account,
            "computer": self.computer,
            "task_category": self.task_category,
        }


class ImpossibleTravel(Base):
    __tablename__ = "impossible_travels"
    __table_args__ = (
        Index('idx_travel_scan', 'scan_id'),
    )

    travel_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"))
    user_account = Column(String(255), nullable=False)
    host_a = Column(String(255), nullable=False)
    time_a = Column(TIMESTAMP(timezone=True), nullable=False)
    host_b = Column(String(255), nullable=False)
    time_b = Column(TIMESTAMP(timezone=True), nullable=False)
    gap_minutes = Column(Numeric(8, 2), nullable=False)

    scan = relationship("Scan", back_populates="travels")

    def to_dict(self):
        return {
            "travel_id": str(self.travel_id),
            "user_account": self.user_account,
            "host_a": self.host_a,
            "time_a": self.time_a.isoformat() if self.time_a else None,
            "host_b": self.host_b,
            "time_b": self.time_b.isoformat() if self.time_b else None,
            "gap_minutes": float(self.gap_minutes) if self.gap_minutes else None,
        }


class AttackChain(Base):
    __tablename__ = "attack_chains"
    __table_args__ = (
        Index('idx_chain_scan', 'scan_id'),
    )

    chain_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"))
    computer = Column(String(255), nullable=False)
    chain_sequence = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="chains")

    def to_dict(self):
        return {
            "chain_id": str(self.chain_id),
            "computer": self.computer,
            "chain_sequence": self.chain_sequence,
        }
