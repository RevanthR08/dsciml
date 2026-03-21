"""
Reads a forensic report JSON (produced by forensic_report.py) and persists
all data into the Neon PostgreSQL database.
"""

import json
import os
import uuid
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import insert

from db_models import (
    Scan, AnomalyCategory, AnomalousEvent, AttackChain, ImpossibleTravel,
)


def _parse_agreement(raw: str | None) -> float:
    """'37.8%' → 37.8"""
    if not raw:
        return 0.0
    return float(str(raw).replace("%", "").strip() or 0)


def _safe_int(val, default=None) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def persist_scan_report(
    db: Session,
    json_path: str | None = None,
    source_file_name: str | None = None,
    user_id: str | None = None,
    data_dict: dict | None = None,
) -> Scan:
    """
    Persist forensic analysis results to database.
    
    Args:
        db: SQLAlchemy session
        json_path: Path to JSON file (deprecated; for backward compat only)
        source_file_name: Original uploaded filename
        user_id: UUID of user who owns this scan
        data_dict: Analysis dict from forensic_report.run_forensic_analysis() (preferred)
    
    Returns:
        Created Scan ORM object with scan_id populated
    """
    # Accept either dict or file path (backward compat)
    if data_dict is not None:
        data = data_dict
    elif json_path:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        raise ValueError("Either json_path or data_dict must be provided")

    meta = data.get("_meta", {})

    # ── 1. Scan row ──────────────────────────────────────────────────────
    scan = Scan(
        generated_at=(
            datetime.fromisoformat(meta["generated_at"])
            if meta.get("generated_at")
            else datetime.utcnow()
        ),
        user_id=user_id,
        file_name=source_file_name or os.path.basename(json_path),
        total_logs=meta.get("total_logs", 0),
        total_threats=meta.get("total_threats", 0),
        risk_score=meta.get("risk_score", 0),
        threat_density=meta.get("threat_density", 0),
        normalized_density=meta.get("normalized_density", 0),
        active_rules=meta.get("active_rules", 0),
        rule_ml_agreement=_parse_agreement(meta.get("rule_ml_agreement")),
        terminal_summary=data.get("_terminal_summary", ""),
        ai_briefing=None,
    )
    db.add(scan)
    db.flush()

    # ── 2. Categories + Events ───────────────────────────────────────────
    event_rows: list[dict] = []

    for key, val in data.items():
        if key.startswith("_"):
            continue

        cat_id = uuid.uuid4()
        cat = AnomalyCategory(
            category_id=cat_id,
            scan_id=scan.scan_id,
            category_name=key,
            mitre_id=val.get("mitre_id"),
            tactic=val.get("tactic"),
            risk_score=val.get("risk_score", 0),
            event_count=val.get("count", 0),
        )
        db.add(cat)

        for evt in val.get("events", []):
            event_rows.append(
                {
                    "event_id": uuid.uuid4(),
                    "scan_id": scan.scan_id,
                    "category_id": cat_id,
                    "time_logged": evt.get("logged"),
                    "windows_event_id": _safe_int(evt.get("event ID")),
                    "user_account": evt.get("User", ""),
                    "computer": evt.get("computer", ""),
                    "task_category": evt.get("task Category", ""),
                }
            )

    # Ensure all categories are inserted into the DB before bulk inserting events
    db.flush()

    if event_rows:
        db.execute(insert(AnomalousEvent), event_rows)

    # ── 3. Attack Chains ─────────────────────────────────────────────────
    for chain in data.get("_attack_chains", []):
        db.add(
            AttackChain(
                scan_id=scan.scan_id,
                computer=chain.get("computer", ""),
                chain_sequence=chain.get("chain", ""),
            )
        )

    # ── 4. Impossible Travels ────────────────────────────────────────────
    for travel in data.get("_impossible_travel", []):
        db.add(
            ImpossibleTravel(
                scan_id=scan.scan_id,
                user_account=travel.get("user", ""),
                host_a=travel.get("host_a", ""),
                time_a=travel.get("time_a"),
                host_b=travel.get("host_b", ""),
                time_b=travel.get("time_b"),
                gap_minutes=travel.get("gap_min", 0),
            )
        )

    db.commit()
    db.refresh(scan)
    return scan
