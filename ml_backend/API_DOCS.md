# 🛡️ LogSentinal SOC Microservice - API Documentation

**Advanced Forensic Analysis & AI-Powered Security** 🚀

This is a **Research-Grade SOC Detection System** combining:
- ✅ **Rule-Based Detection** — Signature patterns for known attacks (Ransomware, Malware, Privilege Escalation)
- ✅ **Machine Learning** — Isolation Forest for behavioral anomaly detection
- ✅ **AI Intelligence** — Groq Llama 3.3 (70B) for executive briefings & security Q&A
- ✅ **In-Memory Processing** — Zero local file storage, pure database persistence

Built with **FastAPI** | **PostgreSQL** | **Groq AI** | **S3-Compatible Storage**

---

## 🚀 Quick Start

### 1. Start the API Server
```powershell
cd ml_backend
python main_api.py
```

### 2. API Base URL
```
http://localhost:8000
```

### 3. CORS Enabled
All endpoints support **Cross-Origin Requests** (React, Vue, Next.js, etc.)

---

## 📡 Complete API Reference

### **1️⃣ Health Check**
Verify the API is running and database is connected.

**Request**
```http
GET /health
```

**Response** (200 OK)
```json
{
  "status": "online",
  "service": "LogSentinal SOC Microservice",
  "version": "2.0",
  "database": "connected"
}
```

**cURL**
```bash
curl http://localhost:8000/health
```

**Purpose**: System health monitoring before loading UI dashboard

---

### **2️⃣ Upload & Auto-Analyze Log File**
Upload CSV or EVTX file and **automatically trigger forensic analysis**. Processing is fully in-memory (zero disk storage).

**Request**
```http
POST /upload?user_id=356721c8-1559-4c00-9aec-8be06d861028
Content-Type: multipart/form-data

file: <binary-file-data>
```

**Parameters**
| Parameter | Type | Location | Required | Description |
|-----------|------|----------|----------|-------------|
| `user_id` | UUID string | Query | ✅ Yes | UUID of the user running this scan |
| `file` | Binary file | Body | ✅ Yes | Log file (.csv or .evtx) |

**Response** (200 OK)
```json
{
  "message": "Uploaded logs.csv and analysis completed",
  "file_type": "CSV",
  "processing": "in-memory (no local storage)",
  "analysis": {
    "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
    "status": "completed",
    "total_logs": 5421,
    "total_threats": 87,
    "risk_score": 445
  }
}
```

**cURL**
```bash
curl -X POST "http://localhost:8000/upload?user_id=356721c8-1559-4c00-9aec-8be06d861028" \
  -F "file=@system_logs.csv"
```

**JavaScript**
```javascript
const formData = new FormData();
formData.append('file', fileInputElement.files[0]);

const response = await fetch(
  `http://localhost:8000/upload?user_id=356721c8-1559-4c00-9aec-8be06d861028`,
  { method: 'POST', body: formData }
);
const data = await response.json();
console.log("Scan ID:", data.analysis.scan_id);
```

**Purpose**: Upload forensic logs and get immediate analysis results. Supports .csv and .evtx formats.

---

### **3️⃣ List All Scans**
Retrieve all scans in the database, paginated and sorted by newest first.

**Request**
```http
GET /scans?limit=20&offset=0
```

**Query Parameters**
| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | Integer | 20 | 100 | Number of scans to return |
| `offset` | Integer | 0 | - | Skip this many scans (pagination) |

**Response** (200 OK)
```json
{
  "total": 142,
  "limit": 20,
  "offset": 0,
  "scans": [
    {
      "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
      "user_id": "356721c8-1559-4c00-9aec-8be06d861028",
      "source_file": "2026-03-21_system.csv",
      "total_logs": 5421,
      "total_threats": 87,
      "risk_score": 445,
      "generated_at": "2026-03-21T10:30:00"
    }
  ]
}
```

**cURL**
```bash
curl "http://localhost:8000/scans?limit=10&offset=0"
```

**Purpose**: Browse all past scans, check history, audit trail

---

### **4️⃣ Get Scan Details**
Retrieve metadata, categories, and statistics for a **specific scan**.

**Request**
```http
GET /scans/{scan_id}
```

**Path Parameters**
| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | UUID or "latest" | Scan ID (or use "latest" for most recent) |

**Response** (200 OK)
```json
{
  "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
  "user_id": "356721c8-1559-4c00-9aec-8be06d861028",
  "source_file": "system_logs.csv",
  "total_logs": 5421,
  "total_threats": 87,
  "risk_score": 445,
  "generated_at": "2026-03-21T10:30:00",
  "categories": [
    {
      "category_id": "cat-001",
      "category_name": "Brute Force — Succeeded",
      "risk_score": 90,
      "event_count": 23,
      "ai_summary": "15 failed login attempts followed by successful access within 5-minute window on WORKSTATION-08"
    }
  ],
  "attack_chain_count": 3,
  "impossible_travel_count": 2
}
```

**cURL**
```bash
# Get specific scan
curl http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o

# Get latest scan
curl http://localhost:8000/scans/latest
```

**Purpose**: View scan summary, risk scores, detected attack categories

---

### **5️⃣ Get Anomaly Categories**
Retrieve all **attack categories** detected in a scan, ranked by risk.

**Request**
```http
GET /scans/{scan_id}/categories
```

**Response** (200 OK)
```json
{
  "count": 8,
  "categories": [
    {
      "category_id": "cat-001",
      "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
      "category_name": "Brute Force — Succeeded",
      "attack_count": 23,
      "risk_score": 90,
      "mitre_id": "T1110",
      "tactic": "Credential Access",
      "ai_summary": "Detected 15 failed logins followed by success on WORKSTATION-08 in 5-minute window"
    },
    {
      "category_id": "cat-002",
      "category_name": "Privilege Escalation",
      "attack_count": 12,
      "risk_score": 90,
      "mitre_id": "T1078",
      "tactic": "Privilege Escalation",
      "ai_summary": "Admin account accessed after suspicious lateral movement"
    }
  ]
}
```

**cURL**
```bash
curl http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o/categories
```

**Purpose**: See breakdown of all detected attack types, MITRE mappings, AI insights

---

### **6️⃣ Get Anomalous Events**
Retrieve **individual log events** flagged as suspicious, with filtering and pagination.

**Request**
```http
GET /scans/{scan_id}/events?category=Brute+Force&computer=WORKSTATION-08&limit=50&offset=0
```

**Query Parameters**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `category` | String | ❌ No | Filter by attack category name (e.g., "Brute Force — Succeeded") |
| `computer` | String | ❌ No | Filter by computer/hostname |
| `user` | String | ❌ No | Filter by user account |
| `limit` | Integer | ❌ No | Max results (default: 200, max: 5000) |
| `offset` | Integer | ❌ No | Pagination offset (default: 0) |

**Response** (200 OK)
```json
{
  "total": 87,
  "limit": 50,
  "offset": 0,
  "events": [
    {
      "event_id": "evt-001",
      "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
      "category_name": "Brute Force — Succeeded",
      "event_id_code": 4625,
      "user_account": "CORP\\admin",
      "computer": "WORKSTATION-08",
      "time_logged": "2026-03-21T10:15:32",
      "task_category": "Logon",
      "risk_score": 9,
      "mitre_id": "T1110"
    }
  ]
}
```

**cURL**
```bash
# Get all events for a scan
curl "http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o/events"

# Filter by computer
curl "http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o/events?computer=WORKSTATION-08"

# Filter by category and limit
curl "http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o/events?category=Brute%20Force&limit=20"
```

**Purpose**: Deep-dive into individual suspicious events, drill-down analysis

---

### **7️⃣ Get Attack Chains**
Retrieve **attack chains** (correlated sequences of suspicious events).

**Request**
```http
GET /scans/{scan_id}/chains
```

**Response** (200 OK)
```json
{
  "count": 3,
  "chains": [
    {
      "chain_id": "chain-001",
      "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
      "attacker_account": "CORP\\user123",
      "target_computer": "WORKSTATION-08",
      "first_event_time": "2026-03-21T09:30:00",
      "last_event_time": "2026-03-21T11:45:00",
      "event_progression": "Failed Login → Brute Force → Success → Privilege Escalation",
      "chain_risk_score": 90
    }
  ]
}
```

**cURL**
```bash
curl http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o/chains
```

**Purpose**: Identify multi-step attack patterns and attacker behavior chains

---

### **8️⃣ Get Impossible Travel**
Retrieve **impossible travel detections** (user logged in from impossible locations).

**Request**
```http
GET /scans/{scan_id}/travels
```

**Response** (200 OK)
```json
{
  "count": 2,
  "travels": [
    {
      "travel_id": "travel-001",
      "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
      "user_account": "CORP\\admin",
      "location_1": "New York Office (10.0.1.0)",
      "location_2": "Shanghai Office (172.16.0.0)",
      "time_1": "2026-03-21T09:00:00",
      "time_2": "2026-03-21T09:15:00",
      "time_diff_minutes": 15,
      "risk_score": 95
    }
  ]
}
```

**cURL**
```bash
curl http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o/travels
```

**Purpose**: Detect account compromise via physical impossibilities

---

### **9️⃣ Get AI Executive Briefing**
Retrieve **AI-generated executive summary** for a scan using Groq Llama 3.3 (70B).

**Request**
```http
GET /scans/{scan_id}/summary
```

**Response** (200 OK)
```json
{
  "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
  "generated_at": "2026-03-21T10:30:00",
  "scan_meta": {
    "total_logs": 5421,
    "total_threats": 87,
    "risk_score": 445
  },
  "executive_briefing": "## 🚨 Critical Security Alert\n\n**Threat Summary**: Multiple coordinated attacks detected targeting administrative accounts\n\n**Attack Timeline**:\n- 09:30 AM: Brute force attempts on WORKSTATION-08 (15 failed logins)\n- 09:45 AM: Successful admin login (T1110 - Credential Access)\n- 10:15 AM: Privilege escalation detected (T1078)\n- 11:30 AM: Lateral movement to 3 additional workstations\n\n**MITRE ATT&CK Tactics**:\n- Credential Access (T1110)\n- Privilege Escalation (T1078)\n- Lateral Movement (T1021)\n\n**Recommended Actions**:\n1. Reset admin account password immediately\n2. Revoke active sessions\n3. Review network traffic to target systems"
}
```

**cURL**
```bash
curl http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o/summary
```

**Purpose**: Get AI-powered executive briefing, Markdown formatted for reports

---

### **🔟 Interactive Security Q&A**
Ask AI security questions about a specific scan. Answers are based on **database data only** (no local files).

**Request**
```http
POST /ask
Content-Type: application/json

{
  "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
  "question": "Which user accounts were involved in the brute force attack?"
}
```

**Request Body**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | UUID | ✅ Yes | Scan ID to analyze |
| `question` | String | ✅ Yes | Security question about the scan |

**Response** (200 OK)
```json
{
  "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
  "question": "Which user accounts were involved in the brute force attack?",
  "answer": "Based on the forensic analysis, the following accounts were targeted in the brute force attack:\n\n1. **CORP\\admin** - 15 failed login attempts on WORKSTATION-08 between 09:30-09:45 AM\n2. **CORP\\service_user** - 8 failed attempts on SERVER-01\n3. **CORP\\backup_admin** - 12 failed attempts across multiple systems\n\nThe CORP\\admin account was successfully compromised after the brute force attack, indicating credential exposure. Immediate password reset recommended."
}
```

**cURL**
```bash
curl -X POST http://localhost:8000/ask \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o",
    "question": "What was the attacker trying to accomplish?"
  }'
```

**JavaScript**
```javascript
const response = await fetch('http://localhost:8000/ask', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    scan_id: 'a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o',
    question: 'Which systems were compromised?'
  })
});
const data = await response.json();
console.log("AI Answer:", data.answer);
```

**Purpose**: Chat-based security analysis, ask specific questions about detected threats

---

### **1️⃣1️⃣ Dashboard Statistics**
Retrieve aggregate statistics across all scans.

**Request**
```http
GET /dashboard/stats
```

**Response** (200 OK)
```json
{
  "total_scans": 142,
  "total_events": 854231,
  "total_threats": 2847,
  "avg_risk_score": 384,
  "high_risk_scans": 23,
  "top_threats": [
    {
      "threat": "Brute Force — Succeeded",
      "count": 456,
      "risk": 90
    },
    {
      "threat": "Privilege Escalation",
      "count": 234,
      "risk": 90
    }
  ]
}
```

**cURL**
```bash
curl http://localhost:8000/dashboard/stats
```

**Purpose**: Dashboard KPIs and statistics

---

### **1️⃣2️⃣ Delete Scan**
Remove a scan and all associated data FROM THE DATABASE.

**Request**
```http
DELETE /scans/{scan_id}
```

**Response** (200 OK)
```json
{
  "deleted": "a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o"
}
```

**cURL**
```bash
curl -X DELETE http://localhost:8000/scans/a1b2c3d4-e5f6-47g8-9h0i-1j2k3l4m5n6o
```

**Purpose**: Purge scan data from database

---

## ⚙️ Environment Configuration

Ensure these are set in `.env`:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/soc_db

# AI Backend (choose one or both)
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxx
GEMINI_API_KEY=ai-xxxxxxxxxxxxx

# S3 / Supabase Storage (optional)
Bucket_Key=https://xxxx.storage.supabase.co/storage/v1/s3
Bucket_Access_Key=xxxxx
Bucket_Secret_Key=xxxxx
Bucket_Name=forensic-logs
```

---

## 📊 Authentication

**Current**: No authentication (development mode)
**Future**: Add JWT tokens to `.env` when deploying to production

---

## 🔄 Error Responses

All errors return standard HTTP status codes:

```json
{
  "detail": "Error message describing what went wrong"
}
```

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Bad request (missing/invalid parameters) |
| 404 | Not found (scan_id doesn't exist) |
| 500 | Server error (database/processing error) |

---

## 💡 Common Use Cases

### **Use Case 1: Upload & Analyze Logs**
```bash
# 1. Upload file
curl -X POST "http://localhost:8000/upload?user_id=356721c8-1559-4c00-9aec-8be06d861028" \
  -F "file=@logs.csv"

# Response includes scan_id
# 2. Get AI briefing
curl http://localhost:8000/scans/{scan_id}/summary
```

### **Use Case 2: Browse Past Scans**
```bash
# List all scans
curl "http://localhost:8000/scans?limit=10"

# Get latest
curl http://localhost:8000/scans/latest

# View details
curl http://localhost:8000/scans/{scan_id}
```

### **Use Case 3: Deep Dive into Threats**
```bash
# 1. Get categories ranked by risk
curl http://localhost:8000/scans/{scan_id}/categories

# 2. Get events for highest-risk category
curl "http://localhost:8000/scans/{scan_id}/events?category=Brute%20Force&limit=20"

# 3. Ask AI about the threat
curl -X POST http://localhost:8000/ask \
  -d '{"scan_id":"...","question":"What is the impact?"}'
```

---

## 🚀 Performance Notes

- **Upload Processing**: ~50-200ms for 100MB files (in-memory, no disk I/O)
- **AI Briefing**: ~5-10 seconds (parallel Groq API call)
- **Database Queries**: <100ms for typical scans (<10k events)
- **Pagination**: Optimized for 1M+ event scans

---

## 📝 Glossary

| Term | Definition |
|------|-----------|
| **Scan** | A single forensic analysis run on uploaded logs |
| **Category** | Attack type (e.g., "Brute Force", "Privilege Escalation") |
| **Event** | Individual log entry flagged as suspicious |
| **Chain** | Sequence of correlated events showing attacker progression |
| **Travel** | Impossible geographic locations detected for one user |
| **MITRE ID** | AttackID framework ID (e.g., T1110 = Brute Force) |
