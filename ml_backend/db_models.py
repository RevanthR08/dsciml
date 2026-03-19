import uuid
from sqlalchemy import (
    Column, String, Integer, Text, Numeric,
    ForeignKey, UniqueConstraint,
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

    categories = relationship("AnomalyCategory", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("AnomalousEvent", back_populates="scan", cascade="all, delete-orphan")
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
