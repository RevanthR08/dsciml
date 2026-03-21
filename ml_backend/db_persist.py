"""
Reads a forensic report JSON (produced by forensic_report.py) and persists
all data into the Neon PostgreSQL database.
"""

import json
import os
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
    IngestedLog,
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


def _safe_bigint(val, default=None) -> int | None:
    try:
        if val is None or (isinstance(val, float) and pd.isna(val)):
            return default
        s = str(val).strip()
        if not s:
            return default
        return int(float(s))
    except (TypeError, ValueError, OverflowError):
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


def _csv_sep(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        first = f.readline()
    return "|" if "|" in first else ","


def _ingested_row_from_series(row: pd.Series, scan_id) -> dict | None:
    """Map one CSV row (already lowercased / de-duplicated column names) to IngestedLog insert dict."""
    d = row.to_dict()
    # Normalized access
    def g(*names):
        for n in names:
            if n not in d:
                continue
            v = d[n]
            if v is None or (isinstance(v, float) and pd.isna(v)):
                continue
            if isinstance(v, str) and v.strip() == "":
                continue
            return v
        return None

    ts_raw = g("timestamp", "timecreated", "logged", "timegenerated", "systemtime", "time")
    logged_at = _parse_dt(ts_raw)
    if not logged_at:
        return None

    is_android_shape = (
        g("event_id", "eventid") is None
        and (g("score") is not None or g("tag") is not None or g("package_r", "package_name", "package") is not None)
    )

    op_a = g("opcode")
    op_b = g("opcode.1")
    opcode_str = None
    opcode_num = None
    if op_b is not None:
        opcode_str = str(op_a).strip() if op_a is not None else None
        opcode_num = _safe_int(op_b)
    elif op_a is not None:
        s = str(op_a).strip()
        if s.lstrip("-").isdigit():
            opcode_num = _safe_int(s)
        else:
            opcode_str = s

    win_eid = _safe_int(g("event_id", "eventid"))
    if win_eid is None and is_android_shape:
        win_eid = _safe_int(g("score"))

    task_cat = g("task_category")
    if task_cat is None and is_android_shape:
        task_cat = g("tag")
    pkg = g("package_r", "package_name", "package")

    src = g("source")
    if src is None and pkg is not None:
        src = str(pkg).strip()

    msg = g("message")
    if msg is None and g("detail") is not None:
        msg = str(g("detail"))

    if is_android_shape:
        lv = g("level")
        if lv is not None and not str(lv).strip().lstrip("-").isdigit():
            opcode_str = opcode_str or str(lv).strip()

    return {
        "log_row_id": uuid.uuid4(),
        "scan_id": scan_id,
        "logged_at": logged_at,
        "windows_event_id": win_eid,
        "user_account": (str(g("user")).strip() if g("user") is not None else None),
        "opcode": opcode_str,
        "opcode_numeric": opcode_num,
        "task_category": (str(task_cat).strip() if task_cat is not None else None),
        "computer": (str(g("computer")).strip() if g("computer") is not None else None) or (
            "Android Device" if is_android_shape else None
        ),
        "source": (str(src).strip() if src is not None else None),
        "detail": (str(g("detail")) if g("detail") is not None else None),
        "message": (str(msg) if msg is not None else None),
        "brief": (str(g("brief")) if g("brief") is not None else None),
        "windows_internal_id": _safe_int(g("id")),
        "version": (str(g("version")) if g("version") is not None else None),
        "qualifiers": (str(g("qualifiers")) if g("qualifiers") is not None else None),
        "level": _safe_int(g("level")),
        "windows_task_id": _safe_int(g("task")),
        "keywords": (str(g("keywords")) if g("keywords") is not None else None),
        "record_id": _safe_bigint(g("recordid")),
        "provider_name": (str(g("providername")) if g("providername") is not None else None),
        "provider_id": (str(g("providerid")) if g("providerid") is not None else None),
        "log_name": (str(g("logname")) if g("logname") is not None else None),
        "process_id": _safe_int(g("processid")),
        "thread_id": _safe_int(g("threadid")),
        "machine_name": (str(g("machinename")) if g("machinename") is not None else None),
        "user_sid": (str(g("userid")) if g("userid") is not None else None),
        "time_created": _parse_dt(g("timecreated")),
        "activity_id": (str(g("activityid")) if g("activityid") is not None else None),
        "related_activity_id": (str(g("relatedactivityid")) if g("relatedactivityid") is not None else None),
        "container_log": (str(g("containerlog")) if g("containerlog") is not None else None),
        "matched_query_ids": (str(g("matchedqueryids")) if g("matchedqueryids") is not None else None),
        "bookmark": (str(g("bookmark")) if g("bookmark") is not None else None),
        "level_display_name": (str(g("leveldisplayname")) if g("leveldisplayname") is not None else None),
        "opcode_display_name": (str(g("opcodedisplayname")) if g("opcodedisplayname") is not None else None),
        "task_display_name": (str(g("taskdisplayname")) if g("taskdisplayname") is not None else None),
        "keywords_display_names": (str(g("keywordsdisplaynames")) if g("keywordsdisplaynames") is not None else None),
        "properties": (str(g("properties")) if g("properties") is not None else None),
        "security_id": (str(g("securityid")) if g("securityid") is not None else None),
        "account_name": (str(g("accountname")) if g("accountname") is not None else None),
        "account_domain": (str(g("accountdomain")) if g("accountdomain") is not None else None),
        "logon_id": (str(g("logonid")) if g("logonid") is not None else None),
        "read_operation": (str(g("readoperation")) if g("readoperation") is not None else None),
        "ip": (str(g("ip")) if g("ip") is not None else None),
        "label": (str(g("label")).strip().lower() if g("label") is not None else None),
    }


def persist_ingested_logs_from_csv(db: Session, scan_id, csv_path: str) -> int:
    """
    Bulk-insert every row from *csv_path* into ingested_logs for this scan.
    Expects Windows-style exports (timestamp + optional label). Rows without a
    parseable primary timestamp are skipped.
    Returns number of rows inserted.
    """
    if not csv_path or not os.path.isfile(csv_path):
        return 0
    if os.path.splitext(csv_path)[1].lower() != ".csv":
        return 0

    sep = _csv_sep(csv_path)
    try:
        df = pd.read_csv(csv_path, sep=sep, low_memory=False, encoding="utf-8")
    except Exception:
        df = pd.read_csv(csv_path, sep=sep, quoting=3, low_memory=False, encoding="utf-8")

    if df.empty:
        return 0

    df.columns = [str(c).strip().lower() for c in df.columns]

    # PG bind limit ~65535; ~46 cols/row → keep batches well under (2500*46 overflows).
    batch: list[dict] = []
    total = 0
    chunk_size = 500

    for _, row in df.iterrows():
        rec = _ingested_row_from_series(row, scan_id)
        if not rec:
            continue
        batch.append(rec)
        if len(batch) >= chunk_size:
            db.execute(insert(IngestedLog), batch)
            db.flush()
            total += len(batch)
            batch.clear()

    if batch:
        db.execute(insert(IngestedLog), batch)
        db.flush()
        total += len(batch)

    return total


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
    json_path: str,
    source_file_name: str | None = None,
    source_csv_path: str | None = None,
    log_platform: str | None = None,
) -> Scan:
    """
    Parse the forensic report JSON at *json_path* and INSERT into
    scans, anomaly_categories, anomalous_events, attack_chains,
    impossible_travels, and (when *source_csv_path* is set) either ingested_logs
    (Windows) or android_logs (Android, *log_platform* / meta).

    Returns the created Scan ORM object (with scan_id populated).
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    meta = data.get("_meta", {})
    platform = log_platform or meta.get("log_platform")

    # ── 1. Scan row ──────────────────────────────────────────────────────
    scan = Scan(
        generated_at=(
            datetime.fromisoformat(meta["generated_at"])
            if meta.get("generated_at")
            else datetime.utcnow()
        ),
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

    if source_csv_path:
        if (platform or "").lower() == "android":
            persist_android_logs_from_csv(db, scan.scan_id, source_csv_path)
        else:
            persist_ingested_logs_from_csv(db, scan.scan_id, source_csv_path)

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
