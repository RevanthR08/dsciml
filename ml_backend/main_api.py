import shutil
import subprocess
import os
import traceback
import uuid as _uuid
import glob

from fastapi import (
    FastAPI, BackgroundTasks, UploadFile, File,
    Query, HTTPException, Depends,
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
    IngestedLog,
    AndroidLog,
)
from db_persist import persist_scan_report
from ai_intelligence import SecurityAI
from evtx_parser import parse_evtx_to_csv
from storage_supabase import (
    upload_to_bucket, get_public_url, download_from_bucket,
    BUCKET_NAME, _is_configured as _storage_ok
)

app = FastAPI(title="LogSentinal SOC Microservice", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ai_engine = SecurityAI()

UPLOAD_DIR = "temp_uploads"
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


def _latest_report_path() -> str | None:
    files = glob.glob(os.path.join(REPORTS_DIR, "anomalous_logs_*.json"))
    return max(files, key=os.path.getctime) if files else None


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

def _upload_to_supabase(local_path: str, object_name: str, content_type: str = "text/csv") -> dict:
    """Upload file to Supabase Storage. Returns dict with bucket_path and public_url."""
    bucket_path = upload_to_bucket(local_path, object_name, content_type=content_type)
    return {
        "bucket_path": bucket_path,
        "public_url": get_public_url(object_name) if bucket_path else None,
    }


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a log file for analysis.
    Accepts both .csv and .evtx (Windows Event Log) formats.
    Always writes a local copy under temp_uploads/ first (for POST /scans), then uploads
    to Supabase Storage when bucket credentials are configured.

    Local testing without Storage: set env ``ALLOW_UPLOAD_WITHOUT_STORAGE=1`` — file is
    still saved under temp_uploads/; ``storage_skipped`` will be true in the response.
    """
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Accepted: .csv, .evtx",
        )

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    raw_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(raw_path, "wb") as buf:
        shutil.copyfileobj(file.file, buf)

    allow_local_only = os.getenv("ALLOW_UPLOAD_WITHOUT_STORAGE", "").lower() in (
        "1", "true", "yes",
    )

    if not _storage_ok():
        if not allow_local_only:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Supabase Storage is not configured.",
                    "fix": "Set Bucket_Key, Bucket_Access_Key, and Bucket_Secret_Key in .env, "
                    "or set ALLOW_UPLOAD_WITHOUT_STORAGE=1 for local testing (temp_uploads only).",
                },
            )

    bucket_path = None
    if ext == ".evtx":
        csv_filename = file.filename.rsplit(".", 1)[0] + ".csv"
        csv_path = os.path.join(UPLOAD_DIR, csv_filename)
        try:
            row_count = parse_evtx_to_csv(raw_path, csv_path)
        except Exception as e:
            os.remove(raw_path)
            raise HTTPException(status_code=500, detail=f"EVTX parsing failed: {e}")
        os.remove(raw_path)

        final_path = os.path.abspath(csv_path)
        object_name = f"logs/{csv_filename}"
        storage = (
            _upload_to_supabase(final_path, object_name)
            if _storage_ok()
            else {"bucket_path": None, "public_url": None}
        )
        if not storage.get("bucket_path"):
            if not (allow_local_only or not _storage_ok()):
                raise HTTPException(
                    status_code=503,
                    detail="Upload to storage bucket failed after EVTX conversion. Check credentials and bucket name.",
                )
        os.environ["SOC_LOG_FILE"] = final_path
        return {
            "message": f"EVTX converted successfully ({row_count:,} records)",
            "original_file": file.filename,
            "converted_to": csv_filename,
            "file_path": final_path,
            "file_type": "evtx",
            "bucket": BUCKET_NAME,
            "storage_skipped": not _storage_ok() or not storage.get("bucket_path"),
            **storage,
            "next_step": "Call POST /scans to analyze.",
        }

    final_path = os.path.abspath(raw_path)
    object_name = f"logs/{file.filename}"
    storage = (
        _upload_to_supabase(final_path, object_name)
        if _storage_ok()
        else {"bucket_path": None, "public_url": None}
    )
    if not storage.get("bucket_path"):
        if not (allow_local_only or not _storage_ok()):
            raise HTTPException(
                status_code=503,
                detail="Upload to storage bucket failed. Check Bucket_Key, keys, and Bucket_Name in .env.",
            )
    os.environ["SOC_LOG_FILE"] = final_path
    return {
        "message": f"Uploaded {file.filename}",
        "file_path": final_path,
        "file_type": "csv",
        "bucket": BUCKET_NAME,
        "storage_skipped": not _storage_ok() or not storage.get("bucket_path"),
        **storage,
        "next_step": "Call POST /scans to analyze.",
    }


# ━━━ Scans ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.get("/files")
def list_files():
    """
    List all files available in temp_uploads/ that can be submitted to POST /scans.
    Returns file names, sizes, and the file_path to pass to /scans.
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    files = []
    for fname in sorted(os.listdir(UPLOAD_DIR)):
        fpath = os.path.join(UPLOAD_DIR, fname)
        if os.path.isfile(fpath) and os.path.splitext(fname)[1].lower() == ".csv":
            files.append({
                "file_name": fname,
                "file_path": os.path.abspath(fpath),
                "size_kb": round(os.path.getsize(fpath) / 1024, 1),
            })
    return {"count": len(files), "files": files}


@app.post("/scans")
def create_scan(background_tasks: BackgroundTasks, body: dict = None):
    """
    Trigger a forensic scan on any uploaded file.

    Body options (S3 priority):
      {"bucket_path": "logs/System.csv"}   ← Download and scan from S3 bucket
      {"file_name": "System.csv"}          ← file name inside temp_uploads/
      {"file_path": "/absolute/path.csv"}  ← absolute path on disk
    """
    body = body or {}

    # Resolve target file
    file_path = None
    
    if body.get("bucket_path"):
        object_name = body["bucket_path"]
        local_filename = os.path.basename(object_name)
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        file_path = os.path.abspath(os.path.join(UPLOAD_DIR, local_filename))
        
        success = download_from_bucket(object_name, file_path)
        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"Could not download '{object_name}' from S3 bucket '{BUCKET_NAME}'."
            )
    elif body.get("file_name"):
        file_path = os.path.abspath(
            os.path.join(UPLOAD_DIR, body["file_name"])
        )
    elif body.get("file_path"):
        file_path = body["file_path"]
    else:
        file_path = os.getenv("SOC_LOG_FILE")
        if not file_path or not os.path.exists(file_path):
            files = glob.glob(os.path.join(UPLOAD_DIR, "*.csv"))
            if files:
                file_path = max(files, key=os.path.getctime)

    if not file_path or not os.path.exists(file_path):
        available = [f for f in os.listdir(UPLOAD_DIR) if f.endswith(".csv")] \
            if os.path.exists(UPLOAD_DIR) else []
        raise HTTPException(
            status_code=400,
            detail={
                "error": "No valid log file found.",
                "hint": "Upload one via POST /upload, then pass its file_name or file_path here.",
                "available_files": available,
            },
        )

    def run_pipeline(path: str):
        env = os.environ.copy()
        env["SOC_LOG_FILE"] = path
        
        target_script = "forensic_report.py"
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                header = f.readline().lower()
                if all(col in header for col in ['score', 'payload', 'root'][-1:]): # Relaxed check in case of variations
                    pass 
                if 'score' in header and 'root' in header and 'ram' in header:
                    target_script = "forensic_android.py"
        except Exception:
            pass

        subprocess.run(["python", target_script, path], env=env)

        report_path = _latest_report_path()
        if not report_path:
            return

        log_platform = "android" if target_script == "forensic_android.py" else "windows"

        db = SessionLocal()
        try:
            scan = persist_scan_report(
                db,
                report_path,
                source_file_name=os.path.basename(path),
                source_csv_path=path if path.lower().endswith(".csv") else None,
                log_platform=log_platform,
            )
            briefing = ai_engine.process_full_report()
            scan.ai_briefing = briefing
            db.commit()
        except Exception:
            db.rollback()
            print("[scan pipeline] Database persist failed:", flush=True)
            traceback.print_exc()
        finally:
            db.close()

    background_tasks.add_task(run_pipeline, file_path)
    return {
        "status": "started",
        "analyzing": os.path.basename(file_path),
        "file_path": file_path,
        "message": "Pipeline running in background. Poll GET /scans/latest for results.",
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
    chain_count = db.query(func.count(AttackChain.chain_id)).filter(
        AttackChain.scan_id == scan.scan_id
    ).scalar()
    travel_count = db.query(func.count(ImpossibleTravel.travel_id)).filter(
        ImpossibleTravel.scan_id == scan.scan_id
    ).scalar()
    ingested_count = db.query(func.count(IngestedLog.log_row_id)).filter(
        IngestedLog.scan_id == scan.scan_id
    ).scalar()
    android_log_count = db.query(func.count(AndroidLog.android_log_id)).filter(
        AndroidLog.scan_id == scan.scan_id
    ).scalar()

    return {
        **scan.to_dict(),
        "terminal_summary": scan.terminal_summary,
        "categories": [c.to_dict() for c in categories],
        "attack_chain_count": chain_count,
        "impossible_travel_count": travel_count,
        "ingested_log_count": ingested_count or 0,
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
        .join(AnomalyCategory, AnomalousEvent.category_id == AnomalyCategory.category_id)
        .filter(AnomalousEvent.scan_id == scan.scan_id)
    )

    if category:
        query = query.filter(AnomalyCategory.category_name == category)
    if computer:
        query = query.filter(AnomalousEvent.computer == computer)
    if user:
        query = query.filter(AnomalousEvent.user_account == user)

    total = query.count()
    rows = (
        query.order_by(AnomalousEvent.time_logged)
        .offset(offset)
        .limit(limit)
        .all()
    )

    events = [evt.to_dict(category_name=cat_name) for evt, cat_name in rows]
    return {"total": total, "limit": limit, "offset": offset, "events": events}


@app.get("/scans/{scan_id}/ingested-logs")
def get_scan_ingested_logs(
    scan_id: str,
    label: str = Query(
        None,
        description="Filter by dataset label, e.g. normal, suspicious, anomalous",
    ),
    limit: int = Query(500, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Full source log rows for this scan (normal + anomalous). Use *label* to
    segregate rows that came from the CSV `label` column.
    """
    scan = _resolve_scan(scan_id, db)
    q = db.query(IngestedLog).filter(IngestedLog.scan_id == scan.scan_id)
    if label:
        q = q.filter(IngestedLog.label == label.strip().lower())
    total = q.count()
    rows = (
        q.order_by(IngestedLog.logged_at)
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": [r.to_dict() for r in rows],
    }


@app.get("/scans/{scan_id}/chains")
def get_scan_chains(scan_id: str, db: Session = Depends(get_db)):
    """Attack chains detected in a scan."""
    scan = _resolve_scan(scan_id, db)
    chains = (
        db.query(AttackChain)
        .filter(AttackChain.scan_id == scan.scan_id)
        .all()
    )
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
def ask_question(query: dict):
    """
    Ask a security question about detected anomalies.
    Expects: {"question": "..."}
    """
    question = query.get("question")
    if not question:
        raise HTTPException(status_code=400, detail="No question provided.")
    answer = ai_engine.answer_question(question)
    return {"answer": answer}


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

from migrations.databasecleanup import clean_database

@app.post("/admin/cleanup")
def wipe_database():
    """
    Truncates all rows in application tables (schema preserved) and empties the storage bucket.
    """
    try:
        clean_database()
        return {
            "status": "success",
            "message": "All table data cleared (schema unchanged); bucket empty attempted.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
