import os
import json
import glob
import time
import importlib
import threading
from pathlib import Path
from typing import Mapping

from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
import hashlib
import warnings
from sqlalchemy import text
from openai import OpenAI
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


def _completion_text(response) -> str:
    """
    Chat completions often return message.content=None (empty or tool-only).
    Never return None — Postgres Text columns would store NULL and look 'broken' in UI.
    """
    try:
        msg = response.choices[0].message
        text = getattr(msg, "content", None)
        if text is not None and str(text).strip():
            return str(text)
    except (IndexError, AttributeError, TypeError):
        pass
    return "[Model returned no text for this request.]"


# Load API Keys (path: this package dir — cwd may not be ml_backend when using uvicorn)
# override=True: stale Windows/User env vars (e.g. LLM_API_KEY) must not shadow ml_backend/.env
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
load_dotenv(override=True)


def _openrouter_key_only() -> str | None:
    """Keys meant for OpenRouter (never use GROQ_API_KEY here)."""
    return _env_api_key("OP_ROUTER", "OPENROUTER_API_KEY", "LLM_API_KEY")


def _http_llm_key() -> str | None:
    """
    Read at use-time so .env is visible even if this module imported early.

    OP_ROUTER / OPENROUTER_API_KEY are checked before LLM_API_KEY so a bad LLM_API_KEY
    in the environment does not shadow a good OP_ROUTER in .env.

    Canonical OpenRouter .env:
      OP_ROUTER=sk-or-v1-...  (or OPENROUTER_API_KEY / LLM_API_KEY)
      LLM_BASE_URL=https://openrouter.ai/api/v1
      LLM_MODEL=provider/model
    Groq: GROQ_API_KEY + LLM_BASE_URL=https://api.groq.com/openai/v1
    """
    return _env_api_key(
        "OP_ROUTER",
        "OPENROUTER_API_KEY",
        "LLM_API_KEY",
        "GROQ_API_KEY",
    )


def _ping_openrouter(base: str, headers: Mapping[str, str]) -> None:
    """One GET /models with the same auth headers OpenRouter expects."""
    if _env_str("LLM_SKIP_VERIFY"):
        return
    try:
        import httpx

        url = f"{base.rstrip('/')}/models"
        r = httpx.get(url, headers=dict(headers), timeout=25.0)
        if r.status_code == 200:
            print("✓ OpenRouter: API key accepted (GET /models OK).")
        else:
            print(
                f"⚠️  OpenRouter: GET /models → {r.status_code}. "
                f"If 401: key or account issue on OpenRouter's side. Snippet: {r.text[:280]!r}"
            )
    except Exception as e:
        print(f"⚠️  OpenRouter verify (GET /models) failed: {e}")


DEFAULT_USER_ID = "356721c8-1559-4c00-9aec-8be06d861028"
MAX_TOOL_CALLS = 5


class SecurityAI:
    def __init__(self):
        # Resolve keys after load_dotenv (avoid stale module-level reads).
        http_key = _http_llm_key()
        gemini_key = _env_api_key("GEMINI_API_KEY")

        if http_key:
            self._ai_mode = "HTTP"
        elif gemini_key:
            self._ai_mode = "GEMINI"
        else:
            raise ValueError(
                "No LLM API key configured. OpenRouter: OP_ROUTER or OPENROUTER_API_KEY "
                "or LLM_API_KEY, plus LLM_BASE_URL and LLM_MODEL. "
                "Groq: GROQ_API_KEY + LLM_BASE_URL. Gemini: GEMINI_API_KEY."
            )

        print(f"🤖 Initializing AI in {self._ai_mode} mode...")
        self.model = None
        self.client = None
        self.model_name = ""
        # httpx/OpenAI sync client is not thread-safe; parallel category summaries corrupted headers (401).
        self._http_lock = threading.Lock()

        if self._ai_mode == "HTTP":
            base = _env_url("LLM_BASE_URL") or "https://openrouter.ai/api/v1"
            if "openrouter.ai" in base.lower():
                # Never send Groq (or other) keys to OpenRouter — use only OR* / LLM_API_KEY.
                or_key = _openrouter_key_only()
                if or_key:
                    http_key = or_key
                elif _env_api_key("GROQ_API_KEY"):
                    print(
                        "⚠️  LLM_BASE_URL is OpenRouter but only GROQ_API_KEY is set. "
                        "Set OP_ROUTER or OPENROUTER_API_KEY (sk-or-v1-... from openrouter.ai/keys)."
                    )
            # Newlines / stray chars from .env breaks Bearer token.
            http_key = "".join(http_key.split())
            # OpenAI-compatible client; force Authorization on every request.
            hdrs: dict[str, str] = {"Authorization": f"Bearer {http_key}"}
            if "openrouter.ai" in base.lower():
                hdrs["HTTP-Referer"] = os.getenv(
                    "OPENROUTER_HTTP_REFERER", "https://localhost"
                )
                hdrs["X-Title"] = os.getenv(
                    "OPENROUTER_APP_TITLE", "DSCIML Forensics"
                )
                if not http_key.startswith("sk-or-"):
                    print(
                        "⚠️  OpenRouter API keys usually start with sk-or-v1-. "
                        "401 User not found = OpenRouter does not recognize this token."
                    )
                _ping_openrouter(base, hdrs)
            self.client = OpenAI(
                api_key=http_key,
                base_url=base,
                default_headers=hdrs,
            )
            self.model_name = _env_str("LLM_MODEL") or "stepfun/step-3.5-flash"
        else:
            # Gemini (not OpenAI-compatible; optional custom endpoint for Vertex / proxies)
            warnings.filterwarnings("ignore", message=".*google.generativeai.*")
            genai = importlib.import_module("google.generativeai")
            gemini_model = (
                _env_str("LLM_MODEL")
                or _env_str("GEMINI_MODEL")
                or "gemini-1.5-flash-latest"
            )
            endpoint = _env_url("GEMINI_API_BASE")
            if endpoint:
                try:
                    from google.api_core import client_options as gco

                    genai.configure(
                        api_key=gemini_key,
                        client_options=gco.ClientOptions(api_endpoint=endpoint),
                    )
                except Exception:
                    genai.configure(api_key=gemini_key)
            else:
                genai.configure(api_key=gemini_key)
            self.model = genai.GenerativeModel(gemini_model)

    def _http_chat(self, **kwargs):
        """Thread-safe chat.completions (shared httpx client is not concurrent-safe)."""
        assert self.client is not None
        with self._http_lock:
            return self.client.chat.completions.create(**kwargs)

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

    def _summarize_category_openai(self, category_payload, scan_id, user_id):
        """
        Summarize a category using the HTTP LLM (OpenAI-compatible) or Gemini.
        """
        if self._ai_mode == "HTTP":
            return self._summarize_category_groq_with_tools(category_payload, scan_id, user_id)
        return self._summarize_category_gemini_with_tools(category_payload, scan_id, user_id)

    def _summarize_category_groq_with_tools(self, category_payload, scan_id, user_id):
        """Summarize using OpenAI-compatible chat API (grouped DB payload; no tool calls)."""
        category_name = category_payload['category_name']
        
        prompt = f"""
        Role: Senior SOC Forensic Lead
        Task: Perform forensic deep-dive on attack category: {category_name}
        
        MITRE ID: {category_payload.get('mitre_id')} | TACTIC: {category_payload.get('tactic')} | Risk: {category_payload.get('risk_score')}/10
        
        GROUPED INCIDENT DATA (pre-aggregated from database):
        {json.dumps(category_payload, cls=UUIDEncoder, indent=2)}
        
        REQUIRED ANALYSIS:
        1) TIMELINE: Exact hours/dates when attack occurred
        2) ENTRY POINTS: How intruders initially compromised the system (attack vector, protocols, ports)
        3) SOURCE IPs & INFRASTRUCTURE: All suspicious IPs, domains, or external systems involved
        4) ATTACK METHODOLOGY: Step-by-step technique breakdown (lateral movement, privilege escalation, persistence)
        5) AFFECTED ENTITIES: Specific users, computers, accounts, and scope of compromise
        6) IMPACT & RISK: Severity, data exposure, system availability impact
        7) REMEDIATION: Immediate containment steps and long-term hardening
        
        Produce a comprehensive technical Markdown summary with findings and remediation.
        """
        
        for attempt in range(3):
            try:
                print(f"📡 [{self._ai_mode}] Analyzing category: '{category_name}'...")
                
                messages = [
                    {"role": "system", "content": "You are a Senior SOC Forensic Lead analyzing security incidents from aggregated database data."},
                    {"role": "user", "content": prompt}
                ]
                
                response = self._http_chat(
                    model=self.model_name,
                    messages=messages,
                    max_tokens=2000,
                )
                
                return _completion_text(response)
                
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    wait = 30
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"⚠️ Error in HTTP LLM summarization: {e}")
                return f"Error: {e}"
        
        return "Failed after retries."

    def _summarize_category_gemini_with_tools(self, category_payload, scan_id, user_id):
        """Summarize using Gemini with db_lookup tool support."""
        category_name = category_payload['category_name']
        
        # Define the tool for Gemini
        tool = {
            "type": "function",
            "function": {
                "name": "db_lookup",
                "description": "Query the anomalous_events table to verify raw event details for forensic analysis.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "SELECT query to run against anomalous_events table. Use :scan_id and :user_id parameters."
                        }
                    },
                    "required": ["query"]
                }
            }
        }
        
        prompt = f"""
        Role: Senior SOC Forensic Lead
        Task: Perform forensic deep-dive on attack category: {category_name}
        
        MITRE ID: {category_payload.get('mitre_id')} | TACTIC: {category_payload.get('tactic')} | Risk: {category_payload.get('risk_score')}/10
        
        GROUPED INCIDENT DATA (pre-aggregated from database):
        {json.dumps(category_payload, cls=UUIDEncoder, indent=2)}
        
        You may query the anomalous_events database table via the db_lookup function (max 5 calls) to:
        - Verify specific event details
        - Extract source IPs, timestamps, or user accounts
        - Confirm attack progression
        
        REQUIRED ANALYSIS:
        1) TIMELINE: Exact hours/dates when attack occurred
        2) ENTRY POINTS: How intruders initially compromised the system (attack vector, protocols, ports)
        3) SOURCE IPs & INFRASTRUCTURE: All suspicious IPs, domains, or external systems involved
        4) ATTACK METHODOLOGY: Step-by-step technique breakdown (lateral movement, privilege escalation, persistence)
        5) AFFECTED ENTITIES: Specific users, computers, accounts, and scope of compromise
        6) IMPACT & RISK: Severity, data exposure, system availability impact
        7) REMEDIATION: Immediate containment steps and long-term hardening
        
        Produce a comprehensive technical Markdown summary with findings and remediation.
        """
        
        for attempt in range(3):
            try:
                print(f"📡 [Gemini + Tools] Analyzing category: '{category_payload['category_name']}'...")
                response = self.model.generate_content(
                    prompt,
                    tools=[tool]
                )
                
                # Handle tool calls if any
                tool_calls = 0
                while response.candidates and response.candidates[0].content.parts:
                    last_part = response.candidates[0].content.parts[-1]
                    
                    # Check if there's a function call
                    if hasattr(last_part, 'function_call'):
                        if tool_calls >= MAX_TOOL_CALLS:
                            break
                        
                        tool_calls += 1
                        func_call = last_part.function_call
                        query = func_call.args.get('query', '')
                        
                        # Execute the DB lookup
                        result = self._db_lookup_tool(query, scan_id, user_id)
                        
                        # Continue conversation with tool result
                        response = self.model.generate_content(
                            [
                                prompt,
                                response.candidates[0].content,
                                {
                                    "role": "user",
                                    "parts": [
                                        f"Tool result for db_lookup:\n{json.dumps(result)}"
                                    ]
                                }
                            ],
                            tools=[tool]
                        )
                    else:
                        # No more tool calls, we have the final response
                        break
                
                # Extract final text response
                if response.candidates and response.candidates[0].content.parts:
                    for part in response.candidates[0].content.parts:
                        if hasattr(part, 'text'):
                            return part.text
                
                return "No summary generated."
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    wait = 60
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"⚠️ Error in Gemini summarization: {e}")
                return f"Error: {e}"
        
        return "Failed after retries."

    def analyze_category(self, category, events):
        """Analyzes events using the HTTP LLM (OpenAI-compatible client)."""
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
                messages = [
                    {"role": "system", "content": "You are a Senior SOC Analyst."},
                    {"role": "user", "content": prompt}
                ]
                response = self._http_chat(
                    model=self.model_name,
                    messages=messages,
                    max_tokens=1500,
                )
                return _completion_text(response)
            except Exception as e:
                if "429" in str(e):
                    wait = 30
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                return f"Error: {e}"
        return "Failed after retries."

    def generate_final_briefing(self, partial_summaries):
        if not partial_summaries:
            return "No threats to summarize."

        prompt = f"""
        Role: Chief Information Security Officer (CISO)
        Task: Create a High-Fidelity Forensic Incident Report from the following categorical findings.
        
        SUMMARIES:
        {chr(10).join(partial_summaries)}
        
        REPORT REQUIREMENTS:
        - Use professional, formal security terminology.
        - Include an Executive Summary (The "Elevator Pitch").
        - Create a comprehensive "Master Attack Chain" using a Mermaid `sequenceDiagram` or `graph TD` that links multiple categories together.
        - Provide a 'Global Remediation & Hardening' section.
        - Ensure all sections have deep technical justification based on the summaries provided.
        
        FORMAT:
        # 🛡️ GLOBAL FORENSIC INCIDENT REPORT
        ## 🏁 Executive Summary
        ## 📉 Aggregated Threat Analytics
        ## 🗺️ Visual Attack Flow (Mermaid)
        ## 👤 Identified Compromised Entities
        ## 🛡️ Strategic Remediation Plan
        """
        try:
            if self.client is not None:
                messages = [
                    {
                        "role": "system",
                        "content": "You are a CISO creating a forensic report.",
                    },
                    {"role": "user", "content": prompt},
                ]
                response = self._http_chat(
                    model=self.model_name,
                    messages=messages,
                    max_tokens=2000,
                )
                return _completion_text(response)
            if self.model is not None:
                r = self.model.generate_content(prompt)
                if r.candidates and r.candidates[0].content.parts:
                    for part in r.candidates[0].content.parts:
                        if hasattr(part, "text"):
                            return part.text
                return "No briefing generated."
            return "Error: no LLM client configured."
        except Exception as e:
            return f"Error: {e}"

    def answer_question(self, question, scan_id=None):
        """
        Answer a security question about a specific scan (OpenAI-compatible or Gemini).
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
                    if self.client is not None:
                        messages = [
                            {
                                "role": "system",
                                "content": "You are a precise SOC Forensic Analyst.",
                            },
                            {"role": "user", "content": prompt},
                        ]
                        response = self._http_chat(
                            model=self.model_name,
                            messages=messages,
                            max_tokens=1000,
                        )
                        return _completion_text(response)
                    if self.model is not None:
                        r = self.model.generate_content(prompt)
                        if r.candidates and r.candidates[0].content.parts:
                            for part in r.candidates[0].content.parts:
                                if hasattr(part, "text"):
                                    return part.text
                        return "No answer generated."
                    return "Error: no LLM client configured."
                except Exception as e:
                    if "429" in str(e) or "rate" in str(e).lower():
                        wait = 30
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
        briefing = self.generate_final_briefing(ordered_summaries)
        if not briefing or not str(briefing).strip():
            return "[Executive briefing: model returned no text.]"
        return briefing

if __name__ == "__main__":
    ai = SecurityAI()
    print("\n" + "="*50)
    print(ai.process_full_report())
    print("="*50)
