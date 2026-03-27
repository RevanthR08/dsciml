import os
import json
import time
import threading
from pathlib import Path

from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import text
import uuid

from database import SessionLocal
from db_models import Scan, AnomalyCategory, AnomalousEvent


class UUIDEncoder(json.JSONEncoder):
    """Custom JSON encoder for UUID serialization"""
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return super().default(obj)

def _env_api_key(*names: str) -> str | None:
    """First non-empty value; strip whitespace/quotes (common .env mistakes)."""
    for name in names:
        raw = os.getenv(name)
        if not raw:
            continue
        v = raw.strip().strip("'\"")
        if not v:
            continue
        if v.lower().startswith("bearer "):
            v = v[7:].strip()
        if v:
            return v
    return None


def _env_str(name: str) -> str | None:
    raw = os.getenv(name)
    if not raw:
        return None
    v = raw.strip().strip("'\"")
    return v if v else None


def _env_url(name: str) -> str | None:
    """Non-empty URL-ish string; strip trailing slash for OpenAI client base_url."""
    v = _env_str(name)
    return v.rstrip("/") if v else None


def _env_float(name: str, default: float) -> float:
    v = _env_str(name)
    if v is None:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def _rate_limit_backoff_seconds(attempt: int) -> int:
    """
    Sleep duration after 429 / rate / quota errors. attempt is 0-based.
    Defaults: 15s, 30s, 45s (cap 60). Override via LLM_RATE_LIMIT_STEP_SEC / LLM_RATE_LIMIT_CAP_SEC.
    """
    step = max(5, int(_env_float("LLM_RATE_LIMIT_STEP_SEC", 15)))
    cap = max(step, int(_env_float("LLM_RATE_LIMIT_CAP_SEC", 60)))
    return min(cap, step * (attempt + 1))


def _canonical_gemini_model_id(raw: str | None) -> str:
    """
    Map common mistakes to real Gemini API model codes (generateContent on AI Studio).
    """
    if not raw:
        return "gemini-1.5-flash"
    s = raw.strip().strip('"').strip("'")
    if s.lower().startswith("models/"):
        s = s.split("/", 1)[1].strip()
    if "/" in s:
        s = s.split("/")[-1].strip()
    key = s.lower().replace(" ", "")
    aliases = {
        "gemini-3-flash": "gemini-3-flash-preview",
        "gemini-1.5-flash": "gemini-1.5-flash",
        "gemini-2.0-flash": "gemini-2.0-flash-exp",
    }
    return aliases.get(key, s)


def _gemini_disable_tools() -> bool:
    _reload_ml_backend_env()
    v = (_env_str("GEMINI_DISABLE_TOOLS") or "").lower()
    return v in ("1", "true", "yes", "on")


# Load API Keys
_ML_BACKEND_ENV = Path(__file__).resolve().parent / ".env"


def _reload_ml_backend_env() -> None:
    load_dotenv(_ML_BACKEND_ENV, override=True)


_reload_ml_backend_env()


def _gemini_api_key() -> str | None:
    _reload_ml_backend_env()
    return _env_api_key("GOOGLE_API_KEY", "GEMINI_API_KEY")


def _http_llm_key() -> str | None:
    _reload_ml_backend_env()
    return _env_api_key("OPENAI_API_KEY", "OP_ROUTER", "OPENROUTER_API_KEY", "LLM_API_KEY", "GROQ_API_KEY")


DEFAULT_USER_ID = "356721c8-1559-4c00-9aec-8be06d861028"
MAX_TOOL_CALLS = 5


class SecurityAI:
    def __init__(self):
        _reload_ml_backend_env()
        gemini_key = _gemini_api_key()
        http_key = _http_llm_key()
        
        mode = _env_str("AI_MODE") or ("GEMINI" if gemini_key else "HTTP")
        self._ai_mode = mode

        print(f"🤖 Initializing AI in {self._ai_mode} mode...")
        self.gemini_client = None
        self.http_client = None
        self.model_id = ""
        self._lock = threading.Lock()

        if self._ai_mode == "GEMINI":
            from google import genai
            from google.genai import types as genai_types
            raw_model = _env_str("LLM_MODEL") or "gemini-1.5-flash"
            self.model_id = _canonical_gemini_model_id(raw_model)
            self.gemini_client = genai.Client(api_key=gemini_key)
        else:
            from openai import OpenAI
            base_url = _env_url("LLM_BASE_URL") or "https://api.openai.com/v1"
            self.model_id = _env_str("LLM_MODEL") or "gpt-4o-mini"
            self.http_client = OpenAI(api_key=http_key, base_url=base_url)

    def _reload_config(self):
        _reload_ml_backend_env()

    def _generate_content(self, prompt, config=None):
        self._reload_config()
        if self._ai_mode == "GEMINI":
            with self._lock:
                return self.gemini_client.models.generate_content(
                    model=self.model_id, contents=prompt, config=config
                )
        else:
            with self._lock:
                res = self.http_client.chat.completions.create(
                    model=self.model_id,
                    messages=[{"role": "user", "content": prompt}]
                )
                return res.choices[0].message.content

    def _get_text(self, response) -> str:
        if self._ai_mode == "GEMINI":
            if not response or not hasattr(response, "text"):
                return ""
            return response.text
        return str(response)

    def _resolve_scan_context(self, scan_id=None, user_id=DEFAULT_USER_ID):
        db = SessionLocal()
        try:
            target_scan = None
            if scan_id:
                target_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            else:
                target_scan = (
                    db.query(Scan)
                    .filter(Scan.user_id == user_id)
                    .order_by(Scan.generated_at.desc())
                    .first()
                )
            return target_scan
        finally:
            db.close()

    def _build_grouped_payload(self, scan_id):
        db = SessionLocal()
        try:
            categories = (
                db.query(AnomalyCategory)
                .filter(AnomalyCategory.scan_id == scan_id, AnomalyCategory.category_name != 'Normal')
                .all()
            )
            grouped = {}
            for cat in categories:
                rows = (
                    db.query(
                        AnomalousEvent.user_account,
                        AnomalousEvent.computer,
                        AnomalousEvent.task_category,
                        text('COUNT(*) AS event_count'),
                        text('MIN(time_logged) AS start_time'),
                        text('MAX(time_logged) AS end_time'),
                    )
                    .filter(AnomalousEvent.scan_id == scan_id, AnomalousEvent.category_id == cat.category_id)
                    .group_by(AnomalousEvent.user_account, AnomalousEvent.computer, AnomalousEvent.task_category)
                    .order_by(text('COUNT(*) DESC'))
                    .all()
                )
                grouped[cat.category_name] = {
                    'category_id': str(cat.category_id),
                    'category_name': cat.category_name,
                    'tactic': cat.tactic,
                    'mitre_id': cat.mitre_id,
                    'risk_score': cat.risk_score,
                    'event_count': cat.event_count,
                    'groups': [
                        {
                            'user_account': r[0],
                            'computer': r[1],
                            'task_category': r[2],
                            'count': int(r[3]),
                            'start_time': r[4].isoformat() if r[4] else None,
                            'end_time': r[5].isoformat() if r[5] else None,
                        } for r in rows
                    ],
                }
            return grouped
        finally:
            db.close()

    def _scan_facts_for_briefing(self, scan_id) -> dict:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if not scan: return {}
            sid = str(scan_id)
            agg = db.execute(text("SELECT MIN(time_logged) as first_ts, MAX(time_logged) as last_ts, COUNT(*) as event_rows FROM anomalous_events ae JOIN anomaly_categories ac ON ac.category_id = ae.category_id WHERE ae.scan_id = CAST(:sid AS uuid) AND ac.category_name <> 'Normal'"), {"sid": sid}).mappings().first()
            per_cat = db.execute(text("SELECT ac.category_name, ac.mitre_id, ac.tactic, ac.risk_score, MIN(ae.time_logged) as first_ts, MAX(ae.time_logged) as last_ts, COUNT(*) as cnt FROM anomalous_events ae JOIN anomaly_categories ac ON ac.category_id = ae.category_id WHERE ae.scan_id = CAST(:sid AS uuid) AND ac.category_name <> 'Normal' GROUP BY ac.category_id, ac.category_name, ac.mitre_id, ac.tactic, ac.risk_score ORDER BY COUNT(*) DESC"), {"sid": sid}).mappings().all()
            return {
                "scan_id": sid,
                "file_name": scan.file_name,
                "generated_at": scan.generated_at.isoformat() if scan.generated_at else None,
                "total_logs": scan.total_logs,
                "total_threats": scan.total_threats,
                "risk_score": scan.risk_score,
                "anomaly_log_window": {
                    "first_observed": agg["first_ts"].isoformat() if agg and agg.get("first_ts") else None,
                    "last_observed": agg["last_ts"].isoformat() if agg and agg.get("last_ts") else None,
                    "stored_anomaly_event_rows": int(agg["event_rows"] or 0)
                },
                "categories_time_ranges": [
                    {
                        "category": r["category_name"],
                        "tactic": r.get("tactic"),
                        "mitre_id": r.get("mitre_id"),
                        "category_risk_score": r.get("risk_score"),
                        "first_observed": r["first_ts"].isoformat() if r.get("first_ts") else None,
                        "last_observed": r["last_ts"].isoformat() if r.get("last_ts") else None,
                        "event_rows": int(r["cnt"] or 0),
                    } for r in per_cat
                ],
            }
        finally:
            db.close()

    def _category_strict_prompt(self, payload, name):
        return f"""Role: Security Analyst (STRICT)
DATA: {json.dumps(payload, cls=UUIDEncoder)}
Category: {name}
Analyze the logs above and produce a factual summary. No hallucinations.
FORMAT:
1. Classification: Tactic, MITRE ID, Risk.
2. Observed: Behavioral log patterns.
3. Entities: Users, Devices.
4. Summary: Time range and pattern.
"""

    def summarize_category(self, payload, scan_id, user_id):
        name = payload["category_name"]
        prompt = self._category_strict_prompt(payload, name)
        for attempt in range(4):
            try:
                print(f"📡 [{self._ai_mode}] Analyzing '{name}'...")
                res = self._generate_content(prompt)
                txt = self._get_text(res)
                if txt: return txt
            except Exception as e:
                wait = _rate_limit_backoff_seconds(attempt)
                if "429" in str(e) or "quota" in str(e).lower():
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"⚠️ Error: {e}")
                return f"Error: {e}"
        return "Failed after retries."

    def generate_final_briefing(self, partial_summaries, scan_facts=None):
        if not partial_summaries: return "No threats detected."
        prompt = f"""Role: CISO
FACTS: {json.dumps(scan_facts or {}, cls=UUIDEncoder)}
SUMMARIES: {''.join(partial_summaries)}
Create a high-level incident report."""
        try:
            res = self._generate_content(prompt)
            return self._get_text(res)
        except Exception as e:
            return f"Error: {e}"

    def process_full_report_for_scan(self, scan_id=None, user_id=DEFAULT_USER_ID):
        target = self._resolve_scan_context(scan_id, user_id)
        if not target: return "No scan found."
        payloads = self._build_grouped_payload(target.scan_id)
        if not payloads: return "No threats."
        summaries = {}
        for name, payload in payloads.items():
            summaries[name] = self.summarize_category(payload, target.scan_id, target.user_id)
            time.sleep(_env_float("GEMINI_CATEGORY_DELAY_SEC", 2.0))
        
        db = SessionLocal()
        try:
            cats = db.query(AnomalyCategory).filter(AnomalyCategory.scan_id == target.scan_id).all()
            for cat in cats:
                if cat.category_name in summaries:
                    cat.ai_summary = summaries[cat.category_name]
            db.commit()
        finally:
            db.close()

        ordered = [f"## {k}\n{v}" for k, v in summaries.items()]
        facts = self._scan_facts_for_briefing(target.scan_id)
        return self.generate_final_briefing(ordered, facts)

    def regenerate_executive_briefing_from_db(self, scan_id) -> str:
        db = SessionLocal()
        try:
            cats = db.query(AnomalyCategory).filter(AnomalyCategory.scan_id == scan_id, AnomalyCategory.category_name != "Normal").all()
            if not cats: return "No anomaly categories."
            ordered = [f"## {c.category_name}\n{c.ai_summary}" for c in cats if c.ai_summary]
            if not ordered: return "AI summaries missing. Run full AI first."
            facts = self._scan_facts_for_briefing(scan_id)
            return self.generate_final_briefing(ordered, facts)
        finally:
            db.close()

    def answer_question(self, question, scan_id):
        facts = self._scan_facts_for_briefing(scan_id)
        prompt = f"Context: {json.dumps(facts, cls=UUIDEncoder)}\nQuestion: {question}"
        res = self._generate_content(prompt)
        return self._get_text(res)

if __name__ == "__main__":
    ai = SecurityAI()
    print(ai.process_full_report_for_scan())
