import os
import json
import glob
import time
import google.generativeai as genai
from huggingface_hub import InferenceClient
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
import hashlib

# Load API Keys
load_dotenv()
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
HF_TOKEN = os.getenv("HF_API_TOKEN")

# Configuration: Switch between 'GEMINI' and 'HF' here
AI_MODE = 'HF' if HF_TOKEN and HF_TOKEN != "your_hugging_face_token_here" else 'GEMINI'

class SecurityAI:
    def __init__(self):
        print(f"🤖 Initializing AI in {AI_MODE} mode...")
        if AI_MODE == 'GEMINI':
            genai.configure(api_key=GEMINI_KEY)
            self.model = genai.GenerativeModel('gemini-1.5-flash-latest')
        else:
            # Using Llama 3.1 8B - powerful and fits in HF free inference
            self.client = InferenceClient("meta-llama/Llama-3.1-8B-Instruct", token=HF_TOKEN)

    def get_latest_report(self):
        list_of_files = glob.glob('detected_anomalies/*.json')
        if not list_of_files:
            return None
        return max(list_of_files, key=os.path.getctime)

    def analyze_category(self, category, events):
        """Analyzes events using the selected AI backend."""
        # For HF, we use smaller samples because of context window limits (approx 8k tokens)
        sample_size = 50 if AI_MODE == 'HF' else 500
        sample_data = events[:sample_size]
        
        prompt = f"""
        Role: Senior SOC Forensic Lead
        Task: Perform deep investigative analysis on {len(sample_data)} security logs for category: {category}
        
        DATA (JSON):
        {json.dumps(sample_data, indent=2)}
        
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
                if AI_MODE == 'GEMINI':
                    print(f"📡 [Gemini] Analyzing '{category}'...")
                    response = self.model.generate_content(prompt)
                    time.sleep(10) 
                    return response.text
                else:
                    print(f"📡 [HuggingFace] Analyzing '{category}'...")
                    messages = [
                        {"role": "system", "content": "You are a Senior SOC Analyst."},
                        {"role": "user", "content": prompt}
                    ]
                    response = self.client.chat_completion(messages, max_tokens=1000)
                    return response.choices[0].message.content
            except Exception as e:
                if "429" in str(e):
                    wait = 60 if AI_MODE == 'GEMINI' else 30
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
            if AI_MODE == 'GEMINI':
                return self.model.generate_content(prompt).text
            else:
                messages = [
                    {"role": "system", "content": "You are a CISO."},
                    {"role": "user", "content": prompt}
                ]
                response = self.client.chat_completion(messages, max_tokens=1500)
                return response.choices[0].message.content
        except Exception as e:
            return f"Error: {e}"

    def answer_question(self, question):
        """Allows the user to ask specific questions about the detected anomalies with actual log context."""
        report_path = self.get_latest_report()
        if not report_path: return "No data available."
        
        with open(report_path, 'r') as f:
            data = json.load(f)
            
        # Extract a sample of actual logs for the AI to see (first 50 events per high-risk category)
        detailed_context = {}
        for cat in data.keys():
            if not cat.startswith('_'):
                events = data[cat].get('events', [])
                # Provide a sample of timestamps and computers so the AI can be specific
                detailed_context[cat] = [
                    {"time": e.get('logged'), "computer": e.get('computer'), "user": e.get('User')} 
                    for e in events[:50]
                ]

        context = {
            "threat_summary": {cat: len(details.get('events', [])) for cat, details in data.items() if not cat.startswith('_')},
            "detailed_samples": detailed_context,
            "meta": data.get('_meta', {})
        }
        
        prompt = f"""
        Context: {json.dumps(context)}
        User Question: {question}
        
        Task: You are a Forensic Analyst. Use the 'detailed_samples' to provide specific timestamps, 
        computers, and users where appropriate. If asked for timestamps, list a representative 
        sample from the records provided.
        """
        try:
            if AI_MODE == 'GEMINI':
                return self.model.generate_content(prompt).text
            else:
                messages = [{"role": "system", "content": "You are a precise SOC assistant."}, {"role": "user", "content": prompt}]
                return self.client.chat_completion(messages, max_tokens=800).choices[0].message.content
        except Exception as e:
            return f"Error: {e}"

    def process_full_report(self):
        report_path = self.get_latest_report()
        if not report_path: return "No report found."

        # --- SPEED OPTIMIZATION: CACHING ---
        # Create a unique hash for this report to see if we've analyzed it already
        file_stats = os.stat(report_path)
        cache_key = hashlib.md5(f"{report_path}_{file_stats.st_size}_{file_stats.st_mtime}".encode()).hexdigest()
        cache_path = os.path.join("detected_anomalies", f"cache_{cache_key}.txt")

        if os.path.exists(cache_path):
            print(f"⚡ [FastLoad] Loading cached briefing for {os.path.basename(report_path)}")
            with open(cache_path, 'r', encoding='utf-8') as f:
                return f.read()

        print(f"📄 Processing: {report_path}")
        with open(report_path, 'r') as f:
            data = json.load(f)

        # Filter for actual attack categories
        categories = [k for k in data.keys() if not k.startswith('_')]
        
        # --- SPEED OPTIMIZATION: PARALLEL PROCESSING ---
        print(f"🚀 Analyzing {len(categories)} categories in parallel...")
        category_data = []
        for cat in categories:
            events = data[cat].get('events', [])
            if events:
                category_data.append((cat, events))

        summaries = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Map categories to the analyzer
            results = list(executor.map(lambda p: self.analyze_category(*p), category_data))
            summaries = [r for r in results if r]

        print("📝 Finalizing briefing...")
        briefing = self.generate_final_briefing(summaries)
        
        # Save to cache
        with open(cache_path, 'w', encoding='utf-8') as f:
            f.write(briefing)
            
        return briefing

if __name__ == "__main__":
    ai = SecurityAI()
    print("\n" + "="*50)
    print(ai.process_full_report())
    print("="*50)
