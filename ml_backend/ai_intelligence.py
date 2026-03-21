import os
import json
import glob
import time
import importlib
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

# Load API Keys
load_dotenv()
GROQ_KEY = os.getenv("GROQ_API_KEY")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
DEFAULT_USER_ID = "356721c8-1559-4c00-9aec-8be06d861028"
MAX_TOOL_CALLS = 5

# Use Groq as primary AI backend (OpenAI-compatible)
AI_MODE = 'GROQ' if GROQ_KEY else 'GEMINI'

class SecurityAI:
    def __init__(self):
        print(f"🤖 Initializing AI in {AI_MODE} mode...")
        if AI_MODE == 'GROQ':
            # Groq via OpenAI-compatible client
            self.client = OpenAI(
                api_key=GROQ_KEY,
                base_url="https://api.groq.com/openai/v1"
            )
            self.model_name = "llama-3.3-70b-versatile"  # Groq's Llama 70B model
        else:
            # Fallback to Gemini if Groq not available
            warnings.filterwarnings('ignore', message='.*google.generativeai.*')
            genai = importlib.import_module("google.generativeai")
            genai.configure(api_key=GEMINI_KEY)
            self.model = genai.GenerativeModel('gemini-1.5-flash-latest')
            self.client = None

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
        Summarize a category using Groq (with tools) or Gemini (fallback).
        Both support tool calling for DB lookups.
        """
        if AI_MODE == 'GROQ':
            return self._summarize_category_groq_with_tools(category_payload, scan_id, user_id)
        else:
            return self._summarize_category_gemini_with_tools(category_payload, scan_id, user_id)

    def _summarize_category_groq_with_tools(self, category_payload, scan_id, user_id):
        """Summarize using Groq with grouped data (no tools needed - data already aggregated)."""
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
                print(f"📡 [Groq] Analyzing category: '{category_name}'...")
                
                messages = [
                    {"role": "system", "content": "You are a Senior SOC Forensic Lead analyzing security incidents from aggregated database data."},
                    {"role": "user", "content": prompt}
                ]
                
                # Call Groq without tools (grouped data is comprehensive)
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    max_tokens=2000
                )
                
                # Extract final text response
                if response.choices[0].message.content:
                    return response.choices[0].message.content
                return "No summary generated."
                
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower():
                    wait = 30
                    print(f"⚠️ Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                print(f"⚠️ Error in Groq summarization: {e}")
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
        """Analyzes events using Groq backend."""
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
                print(f"📡 [Groq] Analyzing '{category}'...")
                messages = [
                    {"role": "system", "content": "You are a Senior SOC Analyst."},
                    {"role": "user", "content": prompt}
                ]
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    max_tokens=1500
                )
                return response.choices[0].message.content
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
            messages = [
                {"role": "system", "content": "You are a CISO creating a forensic report."},
                {"role": "user", "content": prompt}
            ]
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                max_tokens=2000
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error: {e}"

    def answer_question(self, question, scan_id=None):
        """
        Answer a security question about a specific scan using Groq.
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
                    print(f"📡 [Groq] Answering question...")
                    messages = [
                        {"role": "system", "content": "You are a precise SOC Forensic Analyst."},
                        {"role": "user", "content": prompt}
                    ]
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=messages,
                        max_tokens=1000
                    )
                    return response.choices[0].message.content
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
        with ThreadPoolExecutor(max_workers=5) as executor:
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
        return briefing

if __name__ == "__main__":
    ai = SecurityAI()
    print("\n" + "="*50)
    print(ai.process_full_report())
    print("="*50)
