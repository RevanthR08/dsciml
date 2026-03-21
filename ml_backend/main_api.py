import os
import uuid as _uuid

from fastapi import (
    FastAPI,
    BackgroundTasks,
    UploadFile,
    File,
    Query,
    HTTPException,
    Depends,
    WebSocket,
    WebSocketDisconnect,
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
)
from db_persist import persist_scan_report
from ai_intelligence import SecurityAI
from forensic_report import run_forensic_analysis
from storage_supabase import download_from_bucket_bytes, BUCKET_NAME
from system_monitor import get_system_stats, stream_system_stats

app = FastAPI(title="LogSentinal SOC Microservice", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ai_engine = SecurityAI()

REPORTS_DIR = "detected_anomalies"
ALLOWED_EXTENSIONS = {".csv", ".evtx"}


# ━━━ Helpers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


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


def _run_forensic_pipeline(
    file_bytes: bytes, filename: str, user_id: str = None
) -> dict:
    """
    Execute forensic analysis pipeline (fully in-memory, zero disk storage).
    Returns analysis results dict or error info.

    Args:
        file_bytes: Raw file content as bytes (no disk writes)
        filename: Original filename (for logging only)
        user_id: User UUID owning this scan
    """
    # Call forensic analysis directly with in-memory bytes
    try:
        analysis_dict = run_forensic_analysis(
            file_bytes=file_bytes, filename=filename, return_dict=True
        )
    except Exception as e:
        return {"error": f"Forensic analysis failed: {e}"}

    if not analysis_dict:
        return {"error": "No analysis data returned"}

    # Persist to database directly (no intermediate files)
    db = SessionLocal()
    try:
        scan = persist_scan_report(
            db,
            source_file_name=filename,
            user_id=user_id,
            data_dict=analysis_dict,
        )
        briefing = ai_engine.process_full_report_for_scan(
            scan_id=scan.scan_id,
            user_id=str(scan.user_id),
        )
        scan.ai_briefing = briefing
        db.commit()
        db.refresh(scan)

        print(f"✅ Analysis complete (in-memory processing): {filename}")

        return {
            "scan_id": str(scan.scan_id),
            "status": "completed",
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
async def upload_file(file: UploadFile = File(...), user_id: str = None):
    """
    Upload a log file and automatically run forensic analysis.
    Accepts both .csv and .evtx (Windows Event Log) formats.
    Processing is fully in-memory (zero local storage). Results stored in database only.

    Query Parameters:
      - user_id (required): UUID of the user who owns this scan

    Note: All results are stored in the PostgreSQL database, not locally.
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

    # ✅ Read file into memory (no disk writes)
    file_bytes = await file.read()

    # 🚀 Trigger analysis with in-memory bytes (no temp files)
    pipeline_result = _run_forensic_pipeline(
        file_bytes=file_bytes, filename=file.filename, user_id=user_id
    )

    return {
        "message": f"Uploaded {file.filename} and analysis completed",
        "file_type": ext[1:].upper(),  # "CSV" or "EVTX"
        "processing": "in-memory (no local storage)",
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
        "bucket_path": "logs/System.csv",      ← Download and scan from S3 bucket
        "user_id": "uuid-string",               ← Required: UUID of the user who owns this scan
        "background": false                     ← Optional: Run in background (default: false)
      }
      OR
      {
        "file_content": "<base64-encoded-bytes>",  ← File bytes (base64)
        "filename": "logs.csv",                     ← Filename (to detect format)
        "user_id": "uuid-string",                   ← Required: UUID of the user who owns this scan
        "background": false                         ← Optional: Run in background (default: false)
      }
    """
    body = body or {}

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
        filename = os.path.basename(object_name)

        file_bytes = download_from_bucket_bytes(object_name)
        if file_bytes is None:
            raise HTTPException(
                status_code=404,
                detail=f"Could not download '{object_name}' from S3 bucket '{BUCKET_NAME}'.",
            )
    elif body.get("file_content") and body.get("filename"):
        # Accept pre-encoded file bytes
        import base64

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
        )
        return {
            "status": "started",
            "analyzing": filename,
            "user_id": user_id,
            "message": "Pipeline running in background. Poll GET /scans/{scan_id} to check status.",
        }
    else:
        # Run synchronously and return results immediately
        result = _run_forensic_pipeline(
            file_bytes=file_bytes, filename=filename, user_id=user_id
        )
        return {
            "status": "completed",
            "analyzing": filename,
            "user_id": user_id,
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

    return {
        **scan.to_dict(),
        "terminal_summary": scan.terminal_summary,
        "categories": [c.to_dict() for c in categories],
        "attack_chain_count": chain_count,
        "impossible_travel_count": travel_count,
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
        briefing = ai_engine.process_full_report()
        scan.ai_briefing = briefing
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
    answer = ai_engine.answer_question(question, scan_id=scan_id)
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
