# 🛡️ LogSentinal SOC Microservice (v2.0)

LogSentinal is a hybrid cybersecurity analytics platform that transforms raw, messy log data into actionable security intelligence. It combines **deterministic rules**, **unsupervised machine learning**, and **large language models (LLMs)** to detect, correlate, and explain advanced cyber threats.

---

## 🏗️ How it Works: The 3-Layer Architecture

The system operates in three distinct phases, moving from raw data to human reasoning.

### 1. The Detection Layer (`forensic_report.py`)
This is the "engine" of the project. It uses a hybrid approach to find threats:
*   **Deterministic Rules (The Known)**: Uses a library of high-fidelity rules mapped to **MITRE ATT&CK** techniques.
*   **Unsupervised ML (The Unknown)**: Uses the **Isolation Forest** algorithm to detect sequence anomalies and zero-day behaviors.

### 2. The Intelligence Layer (`ai_intelligence.py`)
Once the threats are found, this layer adds the "Expert Reasoning":
*   **Map-Reduce Analysis (Chunking)**: Detections are chunked and sent to **Gemini 1.5/2.0** or **Llama 3.1** (via Hugging Face) for localized analysis, then reduced to a Master Executive Briefing.
*   **Interactive Querying**: A specialized "SOC Assistant" mode allows natural language questions against the forensic evidence.

### 3. The Integration Layer (`main_api.py`)
This layer exposes the ML and AI as simple web endpoints documented below.

---

## 🚀 How to Run the Server
1.  **Install Dependencies**: `pip install -r requirements.txt`
2.  **Configure Environment**: Set your API keys and Supabase credentials in `.env`
3.  **Start API Server**: `uvicorn main_api:app --host 0.0.0.0 --port 8000`

---

## 📡 Complete API Reference

Base URL: `http://localhost:8000`

### 🩺 Health & Server Status

#### `GET /health`
Checks if the server and the database are reachable.
- **Response `200 OK`**:
  ```json
  {
    "status": "online",
    "service": "LogSentinal SOC Microservice",
    "version": "2.0",
    "database": "connected"
  }
  ```

---

### 📂 File Management

#### `POST /upload`
Uploads a log file (`.csv` or `.evtx`) for analysis. EVTX files are automatically converted to CSV. It saves the file locally and uploads it to Supabase Storage.
- **Request Body**: `multipart/form-data` with a `file` field.
- **Response `200 OK`**:
  ```json
  {
    "message": "Uploaded System.csv",
    "file_path": "/absolute/path/to/temp_uploads/System.csv",
    "file_type": "csv",
    "bucket": "files_format",
    "bucket_path": "logs/System.csv",
    "public_url": "https://<ref>.supabase.co/storage/v1/object/public/files_format/logs/System.csv",
    "next_step": "Call POST /scans to analyze."
  }
  ```

#### `GET /files`
Lists all `.csv` files available in the temporary uploads directory that are ready for scanning.
- **Response `200 OK`**:
  ```json
  {
    "count": 1,
    "files": [
      {
        "file_name": "System.csv",
        "file_path": "/absolute/path/to/temp_uploads/System.csv",
        "size_kb": 1500.5
      }
    ]
  }
  ```

---

### 🔍 Threat Scanning

#### `POST /scans`
Triggers the forensic logging pipeline in the background on an uploaded file.
- **Request Body (JSON)**:
  - `file_name` (optional): The name of a file in `temp_uploads/` (e.g. `{"file_name": "System.csv"}`).
  - `file_path` (optional): An absolute path to the dataset.
  - *If omitted, it analyzes the most recently uploaded file.*
- **Response `200 OK`**:
  ```json
  {
    "status": "started",
    "analyzing": "System.csv",
    "file_path": "/absolute/path/to/temp_uploads/System.csv",
    "message": "Pipeline running in background. Poll GET /scans/latest for results."
  }
  ```

#### `GET /scans`
Lists all historical scans in the database.
- **Query Parameters**:
  - `limit` (int, default: 20)
  - `offset` (int, default: 0)
- **Response `200 OK`**:
  ```json
  {
    "total": 5,
    "limit": 20,
    "offset": 0,
    "scans": [
      {
        "scan_id": "uuid-string",
        "source_file": "System.csv",
        "risk_score": 8.5,
        "total_threats": 42
      }
    ]
  }
  ```

#### `GET /scans/{scan_id}`
Retrieves high-level metadata and counts for a specific scan. You can use `"latest"` as the `{scan_id}` to get the most recent scan.
- **Response `200 OK`**:
  ```json
  {
    "scan_id": "uuid-string",
    "source_file": "System.csv",
    "terminal_summary": "Scan found 42 anomalies...",
    "categories": [ ... ],
    "attack_chain_count": 3,
    "impossible_travel_count": 1
  }
  ```

#### `DELETE /scans/{scan_id}`
Deletes a scan and cleanly cascades the deletion to all its associated sub-resources.
- **Response `200 OK`**:
  ```json
  { "deleted": "uuid-string" }
  ```

---

### 📊 Scan Sub-Resources

#### `GET /scans/{scan_id}/categories`
Returns the breakdown of anomaly categories detected, ranked by risk score.
- **Response `200 OK`**:
  ```json
  {
    "count": 2,
    "categories": [
      {
        "category_name": "Brute Force Success",
        "risk_score": 9.2,
        "event_count": 15
      }
    ]
  }
  ```

#### `GET /scans/{scan_id}/events`
Returns paginated logs of anomalous events discovered during the scan.
- **Query Parameters**:
  - `category` (string, optional): Filter by attack category name 
  - `computer` (string, optional): Filter by computer name
  - `user` (string, optional): Filter by active user account
  - `limit` (int, default: 200)
  - `offset` (int, default: 0)
- **Response `200 OK`**:
  ```json
  {
    "total": 150,
    "limit": 200,
    "offset": 0,
    "events": [
      {
        "event_id": 4625,
        "category_name": "Failed Login Spike",
        "user_account": "admin",
        "computer": "WORKSTATION-01",
        "time_logged": "2023-10-27T10:00:00"
      }
    ]
  }
  ```

#### `GET /scans/{scan_id}/chains`
Returns the sequential "Attack Chains" reconstructed natively through temporal correlation.
- **Response `200 OK`**: array of chains indicating attacker workflow.

#### `GET /scans/{scan_id}/travels`
Retrieves impossible travel detections for a scan (e.g. users logging in from completely disparate geography rapidly).

---

### 🧠 AI & Intelligence

#### `GET /scans/{scan_id}/summary`
Generates or retrieves the AI executive briefing (Gemini/Llama output) for the entire scan report.
- **Response `200 OK`**:
  ```json
  {
    "scan_id": "uuid-string",
    "executive_briefing": "## 🏁 Executive Summary ...",
    "scan_meta": { ... }
  }
  ```

#### `POST /ask`
Chat interactively with the SOC Forensics AI, asking direct questions about anomaly details.
- **Request Body (JSON)**:
  ```json
  { "question": "Why was the Brute Force activity on WORKSTATION-01 flagged?" }
  ```
- **Response `200 OK`**:
  ```json
  {
    "answer": "WORKSTATION-01 experienced 50 failed login attempts within 2 minutes for the 'admin' account, directly followed by a successful Event ID 4624..."
  }
  ```

---

### 📈 Dashboard Aggregates

#### `GET /dashboard/stats`
Fetches global totals and maximums across all scans for use in high-level dashboard metrics.
- **Response `200 OK`**:
  ```json
  {
    "total_scans": 15,
    "total_logs_analyzed": 450000,
    "total_threats_detected": 124,
    "average_risk_score": 5.4,
    "highest_risk_score": 9.8
  }
  ```
