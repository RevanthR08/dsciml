import uuid
from sqlalchemy import (
    Column, String, Integer, BigInteger, Text, Numeric, Boolean,
    ForeignKey, UniqueConstraint, Index, text,
)
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.orm import relationship
from database import Base


class Scan(Base):
    __tablename__ = "scans"

    scan_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
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

    categories = relationship("AnomalyCategory", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("AnomalousEvent", back_populates="scan", cascade="all, delete-orphan")
    ingested_logs = relationship("IngestedLog", back_populates="scan", cascade="all, delete-orphan")
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
    __table_args__ = (UniqueConstraint("scan_id", "category_name"),)

    category_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"))
    category_name = Column(String(100), nullable=False)
    mitre_id = Column(String(20))
    tactic = Column(String(100))
    risk_score = Column(Integer, nullable=False)
    event_count = Column(Integer, nullable=False)

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
        }


class IngestedLog(Base):
    """
    Full source log row for a scan (normal + anomalous). Segregation uses *label*
    from the dataset (e.g. normal / suspicious); this is separate from AnomalousEvent.
    """
    __tablename__ = "ingested_logs"
    __table_args__ = (
        Index("ix_ingested_logs_scan_label", "scan_id", "label"),
    )

    log_row_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)

    logged_at = Column(TIMESTAMP(timezone=True), nullable=False)
    windows_event_id = Column(Integer)
    user_account = Column(String(512))
    opcode = Column(String(255))
    opcode_numeric = Column(Integer)
    task_category = Column(String(255))
    computer = Column(String(255))
    source = Column(String(255))
    detail = Column(Text)
    message = Column(Text)
    brief = Column(Text)

    windows_internal_id = Column(Integer)
    version = Column(String(64))
    qualifiers = Column(Text)
    level = Column(Integer)
    windows_task_id = Column(Integer)
    keywords = Column(Text)
    record_id = Column(BigInteger)
    provider_name = Column(String(512))
    provider_id = Column(String(255))
    log_name = Column(String(255))
    process_id = Column(Integer)
    thread_id = Column(Integer)
    machine_name = Column(String(255))
    user_sid = Column(String(255))
    time_created = Column(TIMESTAMP(timezone=True))
    activity_id = Column(String(255))
    related_activity_id = Column(String(255))
    container_log = Column(Text)
    matched_query_ids = Column(Text)
    bookmark = Column(Text)
    level_display_name = Column(String(255))
    opcode_display_name = Column(String(255))
    task_display_name = Column(String(255))
    keywords_display_names = Column(Text)
    properties = Column(Text)
    security_id = Column(String(255))
    account_name = Column(String(255))
    account_domain = Column(String(255))
    logon_id = Column(String(128))
    read_operation = Column(String(255))
    ip = Column(String(128))
    label = Column(String(64))

    scan = relationship("Scan", back_populates="ingested_logs")

    def to_dict(self):
        return {
            "log_row_id": str(self.log_row_id),
            "scan_id": str(self.scan_id),
            "logged_at": self.logged_at.isoformat() if self.logged_at else None,
            "windows_event_id": self.windows_event_id,
            "user_account": self.user_account,
            "opcode": self.opcode,
            "opcode_numeric": self.opcode_numeric,
            "task_category": self.task_category,
            "computer": self.computer,
            "source": self.source,
            "detail": self.detail,
            "message": self.message,
            "brief": self.brief,
            "windows_internal_id": self.windows_internal_id,
            "version": self.version,
            "qualifiers": self.qualifiers,
            "level": self.level,
            "windows_task_id": self.windows_task_id,
            "keywords": self.keywords,
            "record_id": int(self.record_id) if self.record_id is not None else None,
            "provider_name": self.provider_name,
            "provider_id": self.provider_id,
            "log_name": self.log_name,
            "process_id": self.process_id,
            "thread_id": self.thread_id,
            "machine_name": self.machine_name,
            "user_sid": self.user_sid,
            "time_created": self.time_created.isoformat() if self.time_created else None,
            "activity_id": self.activity_id,
            "related_activity_id": self.related_activity_id,
            "container_log": self.container_log,
            "matched_query_ids": self.matched_query_ids,
            "bookmark": self.bookmark,
            "level_display_name": self.level_display_name,
            "opcode_display_name": self.opcode_display_name,
            "task_display_name": self.task_display_name,
            "keywords_display_names": self.keywords_display_names,
            "properties": self.properties,
            "security_id": self.security_id,
            "account_name": self.account_name,
            "account_domain": self.account_domain,
            "logon_id": self.logon_id,
            "read_operation": self.read_operation,
            "ip": self.ip,
            "label": self.label,
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
