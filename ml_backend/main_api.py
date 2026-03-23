import base64
import os
import re
import uuid as _uuid
from pathlib import Path

from dotenv import load_dotenv

# Uvicorn cwd is often not ml_backend; load .env next to this file so OP_ROUTER / DB URL resolve.
# override=True: project .env wins over stale Windows user env (e.g. old LLM_API_KEY).
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

from fastapi import (
    FastAPI,
    BackgroundTasks,
    UploadFile,
    File,
    Query,
    HTTPException,
    Depends,
    WebSocket,
)
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text

from database import SessionLocal, get_db
from db_models import (
    Scan,
    AnomalyCategory,
    AnomalousEvent,
    AttackChain,
    ImpossibleTravel,
    AndroidLog,
)
from db_persist import persist_scan_report
from ai_intelligence import SecurityAI
from forensic_report import run_forensic_analysis
from forensic_android import run_android_forensic_analysis
from migrations.databasecleanup import clean_database
from storage_supabase import (
    download_from_bucket_bytes,
    upload_bytes_to_bucket,
    BUCKET_NAME,
)
from system_monitor import get_system_stats, stream_system_stats

app = FastAPI(title="LogSentinal SOC Microservice", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_ai_engine: SecurityAI | None = None


def _get_ai_engine() -> SecurityAI:
    """Lazy init so the app can boot without LLM keys; AI routes fail until keys are set."""
    global _ai_engine
    if _ai_engine is None:
        _ai_engine = SecurityAI()
    return _ai_engine


REPORTS_DIR = "detected_anomalies"
ALLOWED_EXTENSIONS = {".csv", ".evtx"}


# ━━━ Helpers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _is_android_csv(file_bytes: bytes, filename: str) -> bool:
    """Heuristic: Android CSV — strong match (score+root+ram) or typical columns in header."""
    if not filename.lower().endswith(".csv"):
        return False
    try:
        head = file_bytes[:65536].decode("utf-8", errors="ignore").split("\n", 1)[0].lower()
    except Exception:
        return False
    if "score" in head and "root" in head and "ram" in head:
        return True
    if "score" in head and "detail" in head and ("tag" in head or "package" in head):
        return True
    base = os.path.basename(filename or "").lower()
    if "android" in base and "score" in head:
        return True
    return False


def _resolve_scan(scan_id: str, db: Session) -> Scan:
    """
    Accept a scan_id as UUID string **or** the literal 'latest'.
    Returns the Scan ORM object or raises 404.
    """
    if scan_id == "latest":
        scan = db.query(Scan).order_by(desc(Scan.generated_at)).first()
    else:
        try:
            sid = _uuid.UUID(scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid scan_id: {scan_id}")
        scan = db.query(Scan).filter(Scan.scan_id == sid).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


def _analysis_export_summary(analysis_dict: dict) -> dict:
    """Lightweight API payload when results are not persisted to PostgreSQL."""
    meta = analysis_dict.get("_meta") or {}
    categories = [k for k in analysis_dict if not str(k).startswith("_")]
    return {
        "scan_id": None,
        "status": "completed",
        "persisted_to_database": False,
        "total_logs": meta.get("total_logs"),
        "total_threats": meta.get("total_threats"),
        "risk_score": meta.get("risk_score"),
        "log_platform": meta.get("log_platform"),
        "category_names": categories,
    }


def _run_forensic_pipeline(
    file_bytes: bytes,
    filename: str,
    user_id: str = None,
    persist_db: bool = True,
) -> dict:
    """
    Execute forensic analysis (in-memory). By default results are saved to PostgreSQL
    (scan, categories, events, etc.). Set *persist_db* False to skip DB and return a
    summary only (e.g. bucket-only testing).
    """
    is_android = _is_android_csv(file_bytes, filename)
    try:
        if is_android:
            analysis_dict = run_android_forensic_analysis(
                file_bytes=file_bytes, filename=filename, return_dict=True
            )
        else:
            analysis_dict = run_forensic_analysis(
                file_bytes=file_bytes, filename=filename, return_dict=True
            )
    except Exception as e:
        return {"error": f"Forensic analysis failed: {e}"}

    if not analysis_dict:
        return {"error": "No analysis data returned"}
    if isinstance(analysis_dict, dict) and analysis_dict.get("error"):
        return {"error": analysis_dict["error"]}

    if not persist_db:
        print(f"✅ Analysis complete (no DB persist): {filename}")
        return _analysis_export_summary(analysis_dict)

    db = SessionLocal()
    try:
        scan = persist_scan_report(
            db,
            source_file_name=filename,
            user_id=user_id,
            data_dict=analysis_dict,
            log_platform="android" if is_android else None,
        )
        briefing = _get_ai_engine().process_full_report_for_scan(
            scan_id=str(scan.scan_id),
            user_id=str(scan.user_id) if scan.user_id else None,
        )
        scan.ai_briefing = (
            briefing
            if briefing is not None and str(briefing).strip()
            else "[AI briefing: empty or unavailable.]"
        )
        db.commit()
        db.refresh(scan)

        print(f"✅ Analysis complete (in-memory processing): {filename}")

        return {
            "scan_id": str(scan.scan_id),
            "status": "completed",
            "persisted_to_database": True,
            "total_logs": scan.total_logs,
            "total_threats": scan.total_threats,
            "risk_score": scan.risk_score,
        }
    except Exception as e:
        db.rollback()
        return {"error": str(e)}
    finally:
        db.close()


# ━━━ Health ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "unreachable"

    return {
        "status": "online",
        "service": "LogSentinal SOC Microservice",
        "version": "2.0",
        "database": db_status,
    }


# ━━━ Upload (CSV + EVTX) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    user_id: str = None,
    persist_db: bool = Query(
        True,
        description="If false, skip saving scan results to PostgreSQL (analysis + Storage upload still run when configured).",
    ),
):
    """
    Upload a log file and run forensic analysis.
    Accepts both .csv and .evtx (Windows Event Log) formats.

    By default: results are persisted to Postgres (scan, categories, events, …); CSV is also
    uploaded to Storage when ``Bucket_*`` env is set. Raw CSV rows are not duplicated into
    ``android_logs``. Use ``persist_db=false`` only to skip DB writes.

    Query parameters:
      - user_id (required): UUID (used for Storage path ``logs/{user_id}/...``)
      - persist_db (default true): set false to skip database persistence
    """
    # Validate userId is provided
    if not user_id:
        raise HTTPException(
            status_code=400,
            detail="user_id is required as query parameter (UUID string)",
        )

    # Validate it's a valid UUID
    try:
        _uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid user_id format: {user_id}. Must be a valid UUID.",
        )

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Accepted: .csv, .evtx",
        )

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Empty upload body (0 bytes).",
                "hint": "In Postman form-data: set the row type to File, click the file cell, and re-pick the CSV until the warning icon is gone. "
                "Or use curl: -F \"file=@/full/path/to/android_security_100k.csv\"",
            },
        )

    safe_name = re.sub(r"[^\w.\-]", "_", os.path.basename(file.filename or "upload"))[
        :180
    ]
    object_key = f"logs/{user_id}/{_uuid.uuid4().hex}_{safe_name}"
    content_type = "text/csv" if ext == ".csv" else "application/octet-stream"
    bucket_path, storage_error = upload_bytes_to_bucket(
        file_bytes, object_key, content_type=content_type
    )

    pipeline_result = _run_forensic_pipeline(
        file_bytes=file_bytes,
        filename=file.filename,
        user_id=user_id,
        persist_db=persist_db,
    )

    return {
        "message": f"Uploaded {file.filename} and analysis completed",
        "file_type": ext[1:].upper(),
        "bytes_received": len(file_bytes),
        "persist_db": persist_db,
        "processing": "in-memory analysis; CSV copy in Storage when configured",
        "bucket": BUCKET_NAME,
        "bucket_path": bucket_path,
        "storage_ok": bucket_path is not None,
        "storage_error": storage_error,
        "analysis": pipeline_result,
    }


# ━━━ Scans ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.post("/scans")
def create_scan(
    background_tasks: BackgroundTasks, body: dict = None, db: Session = Depends(get_db)
):
    """
    Trigger a forensic scan (in-memory processing, zero local storage).

    Body options (S3 priority):
      {
        "bucket_path": "logs/System.csv",
        "user_id": "uuid-string",
        "background": false,
        "persist_db": true
      }
      OR
      {
        "file_content": "<base64>",
        "filename": "logs.csv",
        "user_id": "uuid-string",
        "background": false,
        "persist_db": true
      }

    Default is to persist scan results to Postgres. Set persist_db false to skip DB only.
    """
    body = body or {}

    persist_db = body.get("persist_db", True)
    if isinstance(persist_db, str):
        persist_db = persist_db.strip().lower() in ("1", "true", "yes")

    # Validate userId is provided
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=400, detail="user_id is required in request body (UUID string)"
        )

    # Validate it's a valid UUID
    try:
        _uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid user_id format: {user_id}. Must be a valid UUID.",
        )

    # Resolve file content (in-memory)
    file_bytes = None
    filename = None

    if body.get("bucket_path"):
        # Download from S3 into memory (zero disk I/O)
        object_name = body["bucket_path"]
        filename = os.path.basename(object_name.strip().rstrip("/"))

        file_bytes = download_from_bucket_bytes(object_name)
        if file_bytes is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "message": "Object not found or storage misconfigured.",
                    "hint": "Use the exact `bucket_path` string returned by POST /upload (e.g. logs/<user_id>/<uuid>_file.csv). "
                    "Do not use the Dashboard-only path if it differs; Bucket_Name in .env must match your Supabase bucket id.",
                    "attempted_key": object_name,
                    "bucket": BUCKET_NAME,
                },
            )
    elif body.get("file_content") and body.get("filename"):
        try:
            file_bytes = base64.b64decode(body["file_content"])
            filename = body["filename"]
        except Exception as e:
            raise HTTPException(
                status_code=400, detail=f"Invalid base64-encoded file content: {e}"
            )
    else:
        raise HTTPException(
            status_code=400,
            detail="Either 'bucket_path' or ('file_content' + 'filename') is required in request body.",
        )

    if not file_bytes or not filename:
        raise HTTPException(status_code=400, detail="No valid file data found.")

    # Execute pipeline (can be sync or added to background)
    if body.get("background"):
        background_tasks.add_task(
            _run_forensic_pipeline,
            file_bytes=file_bytes,
            filename=filename,
            user_id=user_id,
            persist_db=persist_db,
        )
        msg = (
            "Pipeline running in background. Poll GET /scans/{scan_id} when persist_db is true."
            if persist_db
            else "Pipeline running in background (persist_db=false; no scan row — check server logs)."
        )
        return {
            "status": "started",
            "analyzing": filename,
            "user_id": user_id,
            "persist_db": persist_db,
            "message": msg,
        }
    else:
        result = _run_forensic_pipeline(
            file_bytes=file_bytes,
            filename=filename,
            user_id=user_id,
            persist_db=persist_db,
        )
        return {
            "status": "completed",
            "analyzing": filename,
            "user_id": user_id,
            "persist_db": persist_db,
            **result,
        }


@app.get("/scans")
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List all scans, newest first."""
    total = db.query(func.count(Scan.scan_id)).scalar()
    scans = (
        db.query(Scan)
        .order_by(desc(Scan.generated_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": [s.to_dict() for s in scans],
    }


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Get a scan by its UUID or use 'latest' for the most recent one.
    Returns scan metadata, category summary, chain count, and travel count.
    """
    scan = _resolve_scan(scan_id, db)

    categories = (
        db.query(AnomalyCategory)
        .filter(AnomalyCategory.scan_id == scan.scan_id)
        .order_by(desc(AnomalyCategory.risk_score))
        .all()
    )
    chain_count = (
        db.query(func.count(AttackChain.chain_id))
        .filter(AttackChain.scan_id == scan.scan_id)
        .scalar()
    )
    travel_count = (
        db.query(func.count(ImpossibleTravel.travel_id))
        .filter(ImpossibleTravel.scan_id == scan.scan_id)
        .scalar()
    )
    android_log_count = (
        db.query(func.count(AndroidLog.android_log_id))
        .filter(AndroidLog.scan_id == scan.scan_id)
        .scalar()
    )

    return {
        **scan.to_dict(),
        "terminal_summary": scan.terminal_summary,
        "categories": [c.to_dict() for c in categories],
        "attack_chain_count": chain_count,
        "impossible_travel_count": travel_count,
        "android_log_count": android_log_count or 0,
    }


@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan and all its cascaded data."""
    scan = _resolve_scan(scan_id, db)
    db.delete(scan)
    db.commit()
    return {"deleted": str(scan.scan_id)}


# ━━━ Scan Sub-resources ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.get("/scans/{scan_id}/categories")
def get_scan_categories(scan_id: str, db: Session = Depends(get_db)):
    """Anomaly categories for a scan, ranked by risk."""
    scan = _resolve_scan(scan_id, db)
    categories = (
        db.query(AnomalyCategory)
        .filter(AnomalyCategory.scan_id == scan.scan_id)
        .order_by(desc(AnomalyCategory.risk_score))
        .all()
    )
    return {"count": len(categories), "categories": [c.to_dict() for c in categories]}


@app.get("/scans/{scan_id}/events")
def get_scan_events(
    scan_id: str,
    category: str = Query(None, description="Filter by attack category name"),
    computer: str = Query(None, description="Filter by computer name"),
    user: str = Query(None, description="Filter by user account"),
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Paginated anomalous events for a scan, with optional filters."""
    scan = _resolve_scan(scan_id, db)

    query = (
        db.query(AnomalousEvent, AnomalyCategory.category_name)
        .join(
            AnomalyCategory, AnomalousEvent.category_id == AnomalyCategory.category_id
        )
        .filter(AnomalousEvent.scan_id == scan.scan_id)
    )

    if category:
        query = query.filter(AnomalyCategory.category_name == category)
    if computer:
        query = query.filter(AnomalousEvent.computer == computer)
    if user:
        query = query.filter(AnomalousEvent.user_account == user)

    total = query.count()
    rows = query.order_by(AnomalousEvent.time_logged).offset(offset).limit(limit).all()

    events = [evt.to_dict(category_name=cat_name) for evt, cat_name in rows]
    return {"total": total, "limit": limit, "offset": offset, "events": events}


@app.get("/scans/{scan_id}/chains")
def get_scan_chains(scan_id: str, db: Session = Depends(get_db)):
    """Attack chains detected in a scan."""
    scan = _resolve_scan(scan_id, db)
    chains = db.query(AttackChain).filter(AttackChain.scan_id == scan.scan_id).all()
    return {"count": len(chains), "chains": [c.to_dict() for c in chains]}


@app.get("/scans/{scan_id}/travels")
def get_scan_travels(scan_id: str, db: Session = Depends(get_db)):
    """Impossible travel detections for a scan."""
    scan = _resolve_scan(scan_id, db)
    travels = (
        db.query(ImpossibleTravel)
        .filter(ImpossibleTravel.scan_id == scan.scan_id)
        .all()
    )
    return {"count": len(travels), "travels": [t.to_dict() for t in travels]}


# ━━━ AI / Intelligence ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.get("/scans/{scan_id}/summary")
def get_scan_summary(scan_id: str, db: Session = Depends(get_db)):
    """AI executive briefing for a scan."""
    scan = _resolve_scan(scan_id, db)

    if not scan.ai_briefing:
        briefing = _get_ai_engine().process_full_report_for_scan(
            scan_id=str(scan.scan_id),
            user_id=str(scan.user_id) if scan.user_id else None,
        )
        scan.ai_briefing = (
            briefing
            if briefing is not None and str(briefing).strip()
            else "[AI briefing: empty or unavailable.]"
        )
        db.commit()

    return {
        "scan_id": str(scan.scan_id),
        "generated_at": scan.generated_at.isoformat() if scan.generated_at else None,
        "scan_meta": scan.to_dict(),
        "executive_briefing": scan.ai_briefing,
    }


@app.post("/ask")
def ask_question(body: dict = None, db: Session = Depends(get_db)):
    """
    Ask a security question about detected anomalies for a specific scan.
    All data comes from the database - no local file access.

    Body:
      {
        "scan_id": "uuid-string",   ← Required: UUID of scan to analyze
        "question": "Your question..."  ← Required: Security question
      }
    """
    body = body or {}

    question = body.get("question")
    scan_id = body.get("scan_id")

    if not scan_id:
        raise HTTPException(
            status_code=400, detail="scan_id is required in request body."
        )

    if not question:
        raise HTTPException(
            status_code=400, detail="question is required in request body."
        )

    # Validate scan exists in database
    try:
        sid = _uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(
            status_code=400, detail=f"Invalid scan_id format: {scan_id}"
        )

    scan = db.query(Scan).filter(Scan.scan_id == sid).first()
    if not scan:
        raise HTTPException(
            status_code=404, detail=f"Scan {scan_id} not found in database."
        )

    # Answer is based on DB data, not local files
    answer = _get_ai_engine().answer_question(question, scan_id=scan_id)
    return {
        "scan_id": str(scan.scan_id),
        "question": question,
        "answer": answer,
    }


# ━━━ Dashboard ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.get("/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    """Aggregate statistics across all scans."""
    total_scans = db.query(func.count(Scan.scan_id)).scalar()
    if not total_scans:
        return {"total_scans": 0}

    total_logs = db.query(func.sum(Scan.total_logs)).scalar() or 0
    total_threats = db.query(func.sum(Scan.total_threats)).scalar() or 0
    avg_risk = db.query(func.avg(Scan.risk_score)).scalar() or 0
    max_risk = db.query(func.max(Scan.risk_score)).scalar() or 0

    return {
        "total_scans": total_scans,
        "total_logs_analyzed": total_logs,
        "total_threats_detected": total_threats,
        "average_risk_score": round(float(avg_risk), 1),
        "highest_risk_score": max_risk,
    }


# ━━━ Administration ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.post("/admin/cleanup")
def wipe_database():
    """
    Truncates application tables except ``users`` (schema preserved) and empties the storage bucket.
    """
    try:
        clean_database()
        return {
            "status": "success",
            "message": "Application data cleared (users preserved, schema unchanged); bucket empty attempted.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ━━━ System Monitor ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@app.get("/system/stats")
def system_stats():
    """One-shot CPU + RAM snapshot."""
    return get_system_stats()


@app.websocket("/ws/system-stats")
async def websocket_system_stats(ws: WebSocket):
    """Stream live CPU + RAM every 2 seconds over WebSocket."""
    await ws.accept()
    await stream_system_stats(ws)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    import uvicorn

    # Pass app as import string for reload to work properly
    uvicorn.run("main_api:app", host="0.0.0.0", port=8000, reload=True)
