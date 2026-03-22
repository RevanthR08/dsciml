"""
Reads a forensic report JSON (produced by forensic_report.py) and persists
all data into the Neon PostgreSQL database.
"""

import json
import os
import tempfile
import uuid
from datetime import datetime

import pandas as pd
from sqlalchemy.orm import Session
from sqlalchemy import insert

from db_models import (
    Scan,
    AnomalyCategory,
    AnomalousEvent,
    AttackChain,
    ImpossibleTravel,
    AndroidLog,
)

# PostgreSQL ~65535 bind params per statement
_ANOMALOUS_EVENT_BATCH = 4000  # 8 cols × 4000 = 32k
_ANDROID_LOG_BATCH = 400  # ~20 cols × 400


def _parse_agreement(raw: str | None) -> float:
    """'37.8%' → 37.8"""
    if not raw:
        return 0.0
    return float(str(raw).replace("%", "").strip() or 0)


def _safe_int(val, default=None) -> int | None:
    try:
        if val is None or (isinstance(val, float) and pd.isna(val)):
            return default
        return int(float(str(val).strip()))
    except (TypeError, ValueError):
        return default


def _parse_dt(val):
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=None)
    ts = pd.to_datetime(val, errors="coerce")
    if pd.isna(ts):
        return None
    t = ts.to_pydatetime()
    return t


def persist_android_logs_from_csv(db: Session, scan_id, csv_path: str) -> int:
    """
    Load Android CSV, run the same rule engine as forensic_android, and bulk-insert
    into android_logs (native columns + attack_category / is_anomalous).
    """
    from forensic_android import load_android_csv_for_db, apply_threats

    if not csv_path or not os.path.isfile(csv_path):
        return 0
    if os.path.splitext(csv_path)[1].lower() != ".csv":
        return 0

    df = load_android_csv_for_db(csv_path)
    if df is None or df.empty:
        return 0

    df = apply_threats(df)
    suspicious_labels = {"suspicious", "anomalous", "attack", "malware"}

    def _nz_int(row, key, default=0) -> int:
        v = row.get(key)
        if v is None or (isinstance(v, float) and pd.isna(v)):
            return default
        n = _safe_int(v, default=None)
        return n if n is not None else default

    def _txt(row, key, default=None, maxlen=None):
        v = row.get(key)
        if v is None or (isinstance(v, float) and pd.isna(v)):
            return default
        s = str(v).strip()
        if not s or s.lower() == "nan":
            return default
        if maxlen:
            s = s[:maxlen]
        return s

    batch: list[dict] = []
    total = 0

    for _, row in df.iterrows():
        ts = row.get("logged")
        if ts is None or (isinstance(ts, float) and pd.isna(ts)):
            continue
        logged_at = pd.Timestamp(ts).to_pydatetime()

        lbl = _txt(row, "label", "") or ""
        lbl_l = lbl.lower()
        cat = str(row.get("AttackCategory", "Normal"))
        is_ano = (cat != "Normal") or (lbl_l in suspicious_labels)

        batch.append(
            {
                "android_log_id": uuid.uuid4(),
                "scan_id": scan_id,
                "logged_at": logged_at,
                "pid": _safe_int(row.get("pid")),
                "tid": _safe_int(row.get("tid")),
                "level": _txt(row, "level", None, 16),
                "tag": _txt(row, "tag", None),
                "package_r": _txt(row, "package_r", None),
                "detail": _txt(row, "detail", None),
                "score": _nz_int(row, "score", 0),
                "penalty": _nz_int(row, "penalty", 0),
                "root": _nz_int(row, "root", 0),
                "selinux": _nz_int(row, "selinux", 0),
                "adb": _nz_int(row, "adb", 0),
                "devopts": _nz_int(row, "devOpts", _nz_int(row, "devopts", 0)),
                "mock": _nz_int(row, "mock", 0),
                "temp": _nz_int(row, "temp", 0),
                "ram": _nz_int(row, "ram", 0),
                "net": _txt(row, "net", None, 64),
                "label": lbl_l or None,
                "is_anomalous": is_ano,
                "attack_category": cat,
            }
        )

        if len(batch) >= _ANDROID_LOG_BATCH:
            db.execute(insert(AndroidLog), batch)
            db.flush()
            total += len(batch)
            batch.clear()

    if batch:
        db.execute(insert(AndroidLog), batch)
        db.flush()
        total += len(batch)

    return total


def persist_scan_report(
    db: Session,
    json_path: str | None = None,
    source_file_name: str | None = None,
    user_id: str | None = None,
    data_dict: dict | None = None,
    source_csv_path: str | None = None,
    android_raw_csv_bytes: bytes | None = None,
    log_platform: str | None = None,
) -> Scan:
    """
    Persist forensic analysis into scans, categories, events, chains, travels.
    For Android, pass *android_raw_csv_bytes* or *source_csv_path* to populate android_logs.
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
    platform = log_platform or meta.get("log_platform")

    # ── 1. Scan row ──────────────────────────────────────────────────────
    scan = Scan(
        generated_at=(
            datetime.fromisoformat(meta["generated_at"])
            if meta.get("generated_at")
            else datetime.utcnow()
        ),
        user_id=user_id,
        file_name=source_file_name
        or (os.path.basename(json_path) if json_path else None),
        total_logs=meta.get("total_logs", 0),
        total_threats=meta.get("total_threats", 0),
        risk_score=meta.get("risk_score", 0),
        threat_density=meta.get("threat_density", 0),
        normalized_density=meta.get("normalized_density", 0),
        active_rules=meta.get("active_rules", 0),
        rule_ml_agreement=_parse_agreement(meta.get("rule_ml_agreement")),
        terminal_summary=data.get("_terminal_summary", ""),
        ai_briefing=None,
        log_platform=platform,
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
        for i in range(0, len(event_rows), _ANOMALOUS_EVENT_BATCH):
            chunk = event_rows[i : i + _ANOMALOUS_EVENT_BATCH]
            db.execute(insert(AnomalousEvent), chunk)
            db.flush()

    plat = (platform or "").lower()
    if plat == "android":
        if source_csv_path:
            persist_android_logs_from_csv(db, scan.scan_id, source_csv_path)
        elif android_raw_csv_bytes:
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".csv", delete=False) as tf:
                tf.write(android_raw_csv_bytes)
                tmp = tf.name
            try:
                persist_android_logs_from_csv(db, scan.scan_id, tmp)
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

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
