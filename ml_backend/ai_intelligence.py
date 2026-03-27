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
    Invalid ids produce 404 NOT_FOUND, not rate limits.
    """
    if not raw:
        return "gemini-3-flash-preview"
    s = raw.strip().strip('"').strip("'")
    # REST resource name from docs / copy-paste
    if s.lower().startswith("models/"):
        s = s.split("/", 1)[1].strip()
    # OpenRouter-style slug (never valid for google.genai)
    if "/" in s:
        s = s.split("/")[-1].strip()
    key = s.lower().replace(" ", "")
    aliases = {
        "gemini-3-flash": "gemini-3-flash-preview",
        "gemini3flash": "gemini-3-flash-preview",
        "gemini-3.0-flash": "gemini-3-flash-preview",
        "gemini-3-flash-latest": "gemini-3-flash-preview",
    }
    return aliases.get(key, s)


def _gemini_disable_tools() -> bool:
    v = (_env_str("GEMINI_DISABLE_TOOLS") or "").lower()
    return v in ("1", "true", "yes", "on")


# Load API Keys (path: this package dir — cwd may not be ml_backend when using uvicorn)
# override=True: stale Windows/User env vars (e.g. LLM_API_KEY) must not shadow ml_backend/.env
# Do NOT call load_dotenv() again without a path: override=True would let a repo-root .env
# overwrite these values and bring back bad LLM_MODEL strings (e.g. gemini-3-flash).
_ML_BACKEND_ENV = Path(__file__).resolve().parent / ".env"


def _reload_ml_backend_env() -> None:
    """Re-apply ml_backend/.env so edits + correct model ids apply without guessing cwd."""
    load_dotenv(_ML_BACKEND_ENV, override=True)


_reload_ml_backend_env()


def _gemini_api_key() -> str | None:
    """Google AI Studio usually provides GOOGLE_API_KEY; GEMINI_API_KEY is an alias."""
    return _env_api_key("GOOGLE_API_KEY", "GEMINI_API_KEY")


DEFAULT_USER_ID = "356721c8-1559-4c00-9aec-8be06d861028"
MAX_TOOL_CALLS = 5


class SecurityAI:
    def __init__(self):
        _reload_ml_backend_env()
        gemini_key = _gemini_api_key()
        if gemini_key:
            gemini_key = "".join(gemini_key.split())
        if not gemini_key:
            raise ValueError(
                "Gemini mode requires GOOGLE_API_KEY or GEMINI_API_KEY in .env."
            )
        self._ai_mode = "GEMINI"

        print(f"🤖 Initializing AI in {self._ai_mode} mode...")
        self.gemini_client = None
        self.gemini_model_id = ""
        self._gemini_lock = threading.Lock()
        from google import genai
        from google.genai import types as genai_types

        raw_model = (
            _env_str("GEMINI_MODEL")
            or _env_str("LLM_MODEL")
            or "gemini-3-flash-preview"
        )
        gemini_model = _canonical_gemini_model_id(raw_model)
        if gemini_model != raw_model:
            print(
                f"  (Gemini model: {raw_model!r} -> using API id {gemini_model!r})"
            )
        else:
            print(f"  (Gemini model: {gemini_model})")
        endpoint = _env_url("GEMINI_API_BASE")
        http_options = (
            genai_types.HttpOptions(base_url=endpoint) if endpoint else None
        )
        self.gemini_client = genai.Client(
            api_key=gemini_key,
            http_options=http_options,
        )
        self.gemini_model_id = gemini_model
        if _gemini_disable_tools():
            print(
                "  (GEMINI_DISABLE_TOOLS=1: one generateContent per category — fewer 429s.)"
            )

    def _gemini_effective_model_id(self) -> str:
        """
        Re-read .env on every call. main_api caches a single SecurityAI instance; without this,
        an old bad LLM_MODEL (e.g. gemini-3-flash) sticks until full process restart.
        """
        _reload_ml_backend_env()
        raw = (
            _env_str("GEMINI_MODEL")
            or _env_str("LLM_MODEL")
            or (self.gemini_model_id or None)
            or "gemini-3-flash-preview"
        )
        return _canonical_gemini_model_id(raw)

    def _gemini_generate_content(self, contents, config=None):
        assert self.gemini_client is not None
        model_id = self._gemini_effective_model_id()
        with self._gemini_lock:
            return self.gemini_client.models.generate_content(
                model=model_id,
                contents=contents,
                config=config,
            )

    @staticmethod
    def _gemini_text_from_response(response) -> str | None:
        """Prefer SDK ``response.text`` (handles Gemini 3 multi-part replies); else join parts."""
        if response is None:
            return None
        aggregated = getattr(response, "text", None)
        if isinstance(aggregated, str) and aggregated.strip():
            return aggregated
        if not response.candidates:
            return None
        content = response.candidates[0].content
        if not content or not content.parts:
            return None
        chunks = [
            p.text
            for p in content.parts
            if getattr(p, "text", None) and str(p.text).strip()
        ]
        return "\n".join(chunks) if chunks else None

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

            if not target_scan:
                return None

            return target_scan
        finally:
            db.close()

    def _build_grouped_payload(self, scan_id):
        db = SessionLocal()
        try:
            categories = (
                db.query(AnomalyCategory)
                .filter(
                    AnomalyCategory.scan_id == scan_id,
                    AnomalyCategory.category_name != 'Normal',
                )
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
                    .filter(
                        AnomalousEvent.scan_id == scan_id,
                        AnomalousEvent.category_id == cat.category_id,
                    )
                    .group_by(
                        AnomalousEvent.user_account,
                        AnomalousEvent.computer,
                        AnomalousEvent.task_category,
                    )
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
                            'count': int(r[3]) if r[3] is not None else 0,
                            'start_time': r[4].isoformat() if r[4] else None,
                            'end_time': r[5].isoformat() if r[5] else None,
                        }
                        for r in rows
                    ],
                }
            
            return grouped
        finally:
            db.close()

    def _scan_facts_for_briefing(self, scan_id) -> dict:
        """Ground-truth times and counts from DB so the executive summary is not vague."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if not scan:
                return {}
            sid = str(scan_id)
            agg = db.execute(
                text(
                    """
                    SELECT
                        MIN(ae.time_logged) AS first_ts,
                        MAX(ae.time_logged) AS last_ts,
                        COUNT(*) AS event_rows
                    FROM anomalous_events ae
                    JOIN anomaly_categories ac ON ac.category_id = ae.category_id
                    WHERE ae.scan_id = CAST(:sid AS uuid)
                      AND ac.category_name <> 'Normal'
                    """
                ),
                {"sid": sid},
            ).mappings().first()
            per_cat = db.execute(
                text(
                    """
                    SELECT
                        ac.category_name,
                        ac.mitre_id,
                        ac.tactic,
                        ac.risk_score AS category_risk_score,
                        MIN(ae.time_logged) AS first_ts,
                        MAX(ae.time_logged) AS last_ts,
                        COUNT(*) AS cnt
                    FROM anomalous_events ae
                    JOIN anomaly_categories ac ON ac.category_id = ae.category_id
                    WHERE ae.scan_id = CAST(:sid AS uuid)
                      AND ac.category_name <> 'Normal'
                    GROUP BY
                        ac.category_id,
                        ac.category_name,
                        ac.mitre_id,
                        ac.tactic,
                        ac.risk_score
                    ORDER BY COUNT(*) DESC
                    """
                ),
                {"sid": sid},
            ).mappings().all()
            return {
                "scan_id": sid,
                "file_name": scan.file_name,
                "generated_at": scan.generated_at.isoformat() if scan.generated_at else None,
                "total_logs": scan.total_logs,
                "total_threats": scan.total_threats,
                "risk_score": scan.risk_score,
                "anomaly_log_window": {
                    "first_observed": agg["first_ts"].isoformat()
                    if agg and agg.get("first_ts")
                    else None,
                    "last_observed": agg["last_ts"].isoformat()
                    if agg and agg.get("last_ts")
                    else None,
                    "stored_anomaly_event_rows": int(agg["event_rows"] or 0)
                    if agg
                    else 0,
                },
                "categories_time_ranges": [
                    {
                        "category": r["category_name"],
                        "tactic": r.get("tactic"),
                        "mitre_id": r.get("mitre_id"),
                        "category_risk_score": int(r["category_risk_score"])
                        if r.get("category_risk_score") is not None
                        else None,
                        "first_observed": r["first_ts"].isoformat()
                        if r.get("first_ts")
                        else None,
                        "last_observed": r["last_ts"].isoformat()
                        if r.get("last_ts")
                        else None,
                        "event_rows": int(r["cnt"] or 0),
                    }
                    for r in per_cat
                ],
            }
        finally:
            db.close()

    def _db_lookup_tool(self, query, scan_id, user_id):
        """Execute SELECT query on anomalous_events table for tool calls."""
        if not isinstance(query, str) or not query.strip().lower().startswith('select'):
            return {'error': 'Only SELECT queries are allowed.'}

        safe_query = query.strip().rstrip(';')
        if 'limit' not in safe_query.lower():
            safe_query = f"{safe_query} LIMIT 100"

        db = SessionLocal()
        try:
            rows = db.execute(
                text(safe_query),
                {
                    'scan_id': str(scan_id),
                    'user_id': str(user_id),
                },
            )
            materialized = rows.mappings().all()
            return {'rows': [dict(r) for r in materialized[:100]], 'count': len(materialized[:100])}
        except Exception as e:
            return {'error': str(e)}
        finally:
            db.close()

    def _category_strict_prompt(self, category_payload, category_name):
        return f"""
Role: Security Analyst (STRICT MODE)

You are analyzing real security logs.
DO NOT assume anything not present in the data.

RULES:
- Only use the provided data
- DO NOT infer attack types (APT, malware, exfiltration, etc.)
- DO NOT generate IPs, domains, or techniques unless explicitly present
- If something is unknown -> say "Not observed"
- Keep output concise and factual

DATA:
{json.dumps(category_payload, cls=UUIDEncoder)}

OUTPUT FORMAT:

Category: {category_name}

1. Classification rationale:
- Pipeline metadata: copy tactic, mitre_id, risk_score from DATA exactly (use "Not observed" if missing)
- Log evidence: up to 3 bullets — only task_category, users, computers, or counts from DATA.groups that explain why this category name applies (no new MITRE or tactics not in DATA)

2. Observed Activity:
- (what actually happened based on logs)

3. Affected Entities:
- Users:
- Devices:

4. Time Range:
- Start:
- End:

5. Event Summary:
- Total Events:
- Pattern:

6. Indicators:
- IPs: (only if present)
- Domains: (only if present)

7. Risk Level:
- Low / Medium / High (based only on event frequency or severity field)

8. Notes:
- Any limitations in data based on ml data

DO NOT ADD ANY EXTRA EXPLANATION.
"""

    def _summarize_category_openai(self, category_payload, scan_id, user_id):
        """
        Gemini-only category summary entrypoint.
        """
        if _gemini_disable_tools():
            return self._summarize_category_gemini_plain(category_payload, scan_id, user_id)
        return self._summarize_category_gemini_with_tools(category_payload, scan_id, user_id)

    def _summarize_category_gemini_plain(self, category_payload, scan_id, user_id):
        """Single generateContent per category (no db_lookup tool loop) — far fewer API calls / 429s."""
        category_name = category_payload["category_name"]
        prompt = self._category_strict_prompt(category_payload, category_name)
        for attempt in range(3):
            try:
                print(f"📡 [Gemini] Analyzing category: '{category_name}'...")
                response = self._gemini_generate_content(prompt)
                t = self._gemini_text_from_response(response)
                if t:
                    return t
                return "No summary generated."
            except Exception as e:
                err = str(e).lower()
                if (
                    "429" in str(e)
                    or "rate" in err
                    or "resource exhausted" in err
                    or "quota" in err
                ):
                    wait = _rate_limit_backoff_seconds(attempt)
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"⚠️ Error in Gemini summarization: {e}")
                return f"Error: {e}"
        return "Failed after retries."

    def _summarize_category_gemini_with_tools(self, category_payload, scan_id, user_id):
        """Summarize using Gemini (google.genai) with db_lookup tool support."""
        from google.genai import types as genai_types

        category_name = category_payload['category_name']

        def db_lookup(query: str):
            """Query the anomalous_events table to verify raw event details for forensic analysis.

            Args:
                query: SELECT query to run against anomalous_events table. Use :scan_id and :user_id parameters.
            """
            return self._db_lookup_tool(query, scan_id, user_id)

        tool_cfg = genai_types.GenerateContentConfig(
            tools=[db_lookup],
            automatic_function_calling=genai_types.AutomaticFunctionCallingConfig(
                disable=True
            ),
        )

        prompt = self._category_strict_prompt(category_payload, category_name)
        
        for attempt in range(3):
            try:
                print(
                    f"📡 [Gemini + Tools] Analyzing category: '{category_payload['category_name']}'..."
                )
                conversation: list = [
                    genai_types.UserContent(parts=[genai_types.Part(text=prompt)])
                ]
                tool_calls = 0

                while True:
                    response = self._gemini_generate_content(
                        conversation, config=tool_cfg
                    )
                    text = self._gemini_text_from_response(response)
                    if not response.candidates:
                        return text or "No summary generated."

                    content = response.candidates[0].content
                    if not content or not content.parts:
                        return text or "No summary generated."

                    func_calls = [
                        p.function_call
                        for p in content.parts
                        if p.function_call is not None
                    ]
                    if not func_calls:
                        return text or "No summary generated."

                    if tool_calls >= MAX_TOOL_CALLS:
                        return text or "No summary generated."

                    conversation.append(content)
                    resp_parts = []
                    for fc in func_calls:
                        if tool_calls >= MAX_TOOL_CALLS:
                            break
                        tool_calls += 1
                        q = (fc.args or {}).get("query", "")
                        result = self._db_lookup_tool(str(q), scan_id, user_id)
                        fr = genai_types.FunctionResponse(
                            name=fc.name or "db_lookup",
                            response=result,
                            id=fc.id,
                        )
                        resp_parts.append(
                            genai_types.Part(function_response=fr)
                        )
                    if not resp_parts:
                        return text or "No summary generated."
                    conversation.append(
                        genai_types.UserContent(parts=resp_parts)
                    )
            except Exception as e:
                err = str(e).lower()
                if (
                    "429" in str(e)
                    or "rate" in err
                    or "resource exhausted" in err
                    or "quota" in err
                ):
                    wait = _rate_limit_backoff_seconds(attempt)
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"⚠️ Error in Gemini summarization: {e}")
                return f"Error: {e}"
        
        return "Failed after retries."

    def analyze_category(self, category, events):
        """Analyzes events using Gemini."""
        sample_size = 500
        sample_data = events[:sample_size]
        
        prompt = f"""
        Role: Senior SOC Forensic Lead
        Task: Perform deep investigative analysis on {len(sample_data)} security logs for category: {category}
        
        DATA (JSON):
        {json.dumps(sample_data, cls=UUIDEncoder, indent=2)}
        
        REQUIRED OUTPUT STRUCTURE:
        1. ## 🔍 Forensic Analysis: {category}
           - Deconstruct the exact behavioral pattern.
           - Identify specific anomalies in timing, user context, or host interaction.
        
        2. ## 📊 Statistical Breakdown
           - Detailed counts of Compromised Computers vs Users.
           - Top 3 specific entities (Computer/User) and their role in the incident.
        
        3. ## 🔗 Attack Sequence (Mermaid Diagram)
           - Generate a Mermaid `graph LR` diagram representing the flow of this specific detection.
           - Example: [User] --> [Auth Fail] --> [Locked]
        
        4. ## 🛡️ MITRE Mapping & Remediation
           - Map to specific MITRE ATT&CK Techniques.
           - Provide actionable bullet points for immediate containment.
        """

        for attempt in range(3):
            try:
                print(f"📡 [{self._ai_mode}] Analyzing '{category}'...")
                response = self._gemini_generate_content(prompt)
                txt = self._gemini_text_from_response(response)
                return txt if txt else "No analysis generated."
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    wait = _rate_limit_backoff_seconds(attempt)
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                return f"Error: {e}"
        return "Failed after retries."

    def _executive_briefing_strict_prompt(
        self, partial_summaries: list[str], scan_facts: dict | None = None
    ) -> str:
        """One short scan-level briefing. No Mermaid — long CISO prompts hit default max tokens and truncate mid-sentence."""
        joined = chr(10).join(partial_summaries)
        cap = max(200, int(_env_float("AI_BRIEFING_MAX_INPUT_CHARS", 120_000)))
        if len(joined) > cap:
            joined = joined[:cap] + "\n[Category summaries truncated for briefing.]"
        facts_json = json.dumps(scan_facts or {}, cls=UUIDEncoder, indent=2)
        return f"""Role: Security Analyst (dashboard briefing only)

You must produce a complete briefing in plain text. Do not stop early. No Mermaid, no markdown tables, no emoji.

RULES:
- Copy timestamps and row counts from SCAN_FACTS exactly when present; never invent times.
- For each category use tactic, mitre_id, category_risk_score from SCAN_FACTS when present; never invent MITRE IDs.
- Use CATEGORY SUMMARIES for behavior (what happened); add 2–4 sentences per category explaining why the label fits, tied to summary + pipeline fields.
- Keep total output compact (aim ~30–45 lines) but include EVERY section below with real content.

SCAN_FACTS (database):
{facts_json}

CATEGORY SUMMARIES:
{joined}

OUTPUT — mandatory structure. Print each heading below EXACTLY as a single line, then its bullets. Do not merge sections into one paragraph. Do not skip a heading.

Scan overview
- File / scan: file_name and generated_at from SCAN_FACTS
- 2–3 sentences: what the scan shows overall (from summaries + SCAN_FACTS)

Timeline
- first_observed -> last_observed from SCAN_FACTS.anomaly_log_window (or say not in DB)
- stored anomaly event row count from SCAN_FACTS

Categories
- For each row in SCAN_FACTS.categories_time_ranges (in order): write a mini-block:
  Line A: category name; ISO time window; event_rows
  Line B: Pipeline classification — tactic, mitre_id, category_risk_score (copy from SCAN_FACTS; write "none" if a field is null)
  Line C–D: Why this category — 2–4 sentences using that category's block in CATEGORY SUMMARIES plus Line B (behavior + rationale; no invented techniques)
  (If categories_time_ranges empty, say none.)

Risk
- One line: total_logs, total_threats, risk_score from SCAN_FACTS

Next step
- One concrete action from the summaries

End after the Next step bullet. No preamble, no conclusion paragraph after that."""

    def generate_final_briefing(
        self, partial_summaries: list[str], scan_facts: dict | None = None
    ):
        if not partial_summaries:
            return "No threats to summarize."

        from google.genai import types as genai_types

        prompt = self._executive_briefing_strict_prompt(
            partial_summaries, scan_facts=scan_facts
        )
        # max_output_tokens = ceiling the model may use, not a target length; too small causes mid-sentence cuts.
        # Set AI_BRIEFING_MAX_OUTPUT_TOKENS=0 to omit (use API/model default). Default ~3k is plenty for this format.
        raw_cap = _env_float("AI_BRIEFING_MAX_OUTPUT_TOKENS", 3072)
        cfg = None
        if raw_cap > 0:
            cfg = genai_types.GenerateContentConfig(
                max_output_tokens=max(512, int(raw_cap)),
            )
        try:
            if self.gemini_client is not None:
                r = self._gemini_generate_content(prompt, config=cfg)
                t = self._gemini_text_from_response(r)
                return t if t else "No briefing generated."
            return "Error: no LLM client configured."
        except Exception as e:
            return f"Error: {e}"

    def answer_question(self, question, scan_id=None):
        """
        Answer a security question about a specific scan (Gemini only).
        All data comes from the database, not local files.
        """
        if not scan_id:
            return "Error: scan_id is required to answer questions."
        
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if not scan:
                return f"Scan {scan_id} not found in database."
            
            # Get categories and event counts from DB
            categories = db.query(AnomalyCategory).filter(AnomalyCategory.scan_id == scan_id).all()
            threat_summary = {cat.category_name: cat.event_count for cat in categories}
            
            # Build context from database
            context = {
                "scan_id": str(scan_id),
                "total_logs": scan.total_logs,
                "total_threats": scan.total_threats,
                "risk_score": scan.risk_score,
                "threat_summary": threat_summary,
                "categories": [c.to_dict() for c in categories[:10]],  # Top 10 categories
            }
            
            prompt = f"""
            Context (from security scan database):
            {json.dumps(context, cls=UUIDEncoder, indent=2)}
            
            User Question: {question}
            
            Task: You are a Forensic Analyst. Answer the question directly using the threat data provided.
            Be specific with numbers, categories, and risk assessments from the database.
            """
            
            for attempt in range(3):
                try:
                    print(f"📡 [{self._ai_mode}] Answering question...")
                    if self.gemini_client is not None:
                        r = self._gemini_generate_content(prompt)
                        t = self._gemini_text_from_response(r)
                        return t if t else "No answer generated."
                    return "Error: no LLM client configured."
                except Exception as e:
                    if "429" in str(e) or "rate" in str(e).lower():
                        wait = _rate_limit_backoff_seconds(attempt)
                        print(f"⚠️ Rate limited. Waiting {wait}s...")
                        time.sleep(wait)
                        continue
                    return f"Error: {e}"
            return "Failed to get answer after retries."
        finally:
            db.close()

    def process_full_report(self):
        return self.process_full_report_for_scan()

    def process_full_report_for_scan(self, scan_id=None, user_id=DEFAULT_USER_ID):
        target_scan = self._resolve_scan_context(scan_id=scan_id, user_id=user_id)
        if not target_scan:
            return 'No scan found for summarization.'

        grouped_payload = self._build_grouped_payload(target_scan.scan_id)
        if not grouped_payload:
            return 'No threat categories to summarize.'

        print(f"🚀 Summarizing {len(grouped_payload)} categories for scan {target_scan.scan_id}...")

        category_summaries = {}
        # Pace requests so preview-tier RPM limits are less likely to trip (each category may
        # issue multiple generateContent calls when tools are used). Set GEMINI_CATEGORY_DELAY_SEC=2–5 if needed.
        between_cat_delay = _env_float("GEMINI_CATEGORY_DELAY_SEC", 0.0)
        # One worker: httpx OpenAI client is not thread-safe; lock serializes HTTP anyway.
        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = {}
            for _, payload in grouped_payload.items():
                future = executor.submit(
                    self._summarize_category_openai,
                    category_payload=payload,
                    scan_id=target_scan.scan_id,
                    user_id=target_scan.user_id,
                )
                futures[payload['category_name']] = future
            
            # Collect results as they complete
            for category_name, future in futures.items():
                try:
                    summary = future.result(timeout=300)  # 5-minute timeout per category
                    category_summaries[category_name] = summary
                except Exception as e:
                    print(f"⚠️ Failed to summarize {category_name}: {e}")
                    category_summaries[category_name] = f"Error: {e}"
                if between_cat_delay > 0:
                    time.sleep(between_cat_delay)

        db = SessionLocal()
        try:
            categories = (
                db.query(AnomalyCategory)
                .filter(AnomalyCategory.scan_id == target_scan.scan_id)
                .all()
            )
            for cat in categories:
                if cat.category_name in category_summaries:
                    cat.ai_summary = category_summaries[cat.category_name]
            db.commit()
        finally:
            db.close()

        ordered_summaries = [
            f"## {k}\n{v}" for k, v in category_summaries.items() if v
        ]
        scan_facts = self._scan_facts_for_briefing(target_scan.scan_id)
        briefing = self.generate_final_briefing(
            ordered_summaries, scan_facts=scan_facts
        )
        if not briefing or not str(briefing).strip():
            return "[Executive briefing: model returned no text.]"
        return briefing

    def regenerate_executive_briefing_from_db(self, scan_id) -> str:
        """
        Rebuild the executive briefing from persisted category ai_summary rows + SCAN_FACTS
        (same prompt as PDF/dashboard). Does not re-run per-category Gemini unless summaries are missing.
        """
        db = SessionLocal()
        try:
            sid = scan_id
            cats = (
                db.query(AnomalyCategory)
                .filter(
                    AnomalyCategory.scan_id == sid,
                    AnomalyCategory.category_name != "Normal",
                )
                .order_by(AnomalyCategory.event_count.desc())
                .all()
            )
            if not cats:
                return "No anomaly categories in database for this scan."
            ordered = [
                f"## {c.category_name}\n{(c.ai_summary or '').strip()}"
                for c in cats
                if (c.ai_summary or "").strip()
            ]
            if not ordered:
                return (
                    "No category AI summaries stored. Run AI on this scan first "
                    "(e.g. upload with run_ai=true, or POST workflow that populates ai_summary)."
                )
            facts = self._scan_facts_for_briefing(sid)
            return self.generate_final_briefing(ordered, scan_facts=facts)
        finally:
            db.close()

if __name__ == "__main__":
    ai = SecurityAI()
    print("\n" + "="*50)
    print(ai.process_full_report())
    print("="*50)
