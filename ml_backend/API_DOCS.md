# LogSentinal SOC Microservice - API Documentation

Base URL: `http://localhost:8000`

This document is synchronized with all routes defined in `main_api.py`.

## Notes

- Scan routes are user-scoped: every scan endpoint includes `{user_id}` in the path.
- `user_id` and `scan_id` are expected to be UUID strings unless explicitly noted.
- `scan_id` supports the special value `latest` on scan detail-style endpoints.
- Error format:

```json
{
  "detail": "Error message"
}
```

## 1. Health

### `GET /health`

Checks API and database connectivity.

Response example:

```json
{
  "status": "online",
  "service": "LogSentinal SOC Microservice",
  "version": "2.0",
  "database": "connected"
}
```

## 2. Upload and Analyze

### `POST /upload?user_id={user_id}`

Uploads a `.csv` or `.evtx` file and runs forensic analysis immediately in-memory.

Request:

- Content-Type: `multipart/form-data`
- Field: `file`
- Query: `user_id` (required UUID)

Response example:

```json
{
  "message": "Uploaded logs.csv and analysis completed",
  "file_type": "CSV",
  "processing": "in-memory (no local storage)",
  "analysis": {
    "scan_id": "8b0cd45b-8b23-4b01-9eef-702a7ca3d2d4",
    "status": "completed",
    "total_logs": 5421,
    "total_threats": 87,
    "risk_score": 445
  }
}
```

## 3. Scan Management (User Scoped)

### `POST /users/{user_id}/scans`

Creates a scan for a user.

Body option A (S3/supabase object path):

```json
{
  "bucket_path": "logs/System.csv",
  "background": false
}
```

Body option B (base64 bytes):

```json
{
  "file_content": "<base64-encoded-bytes>",
  "filename": "logs.csv",
  "background": false
}
```

Behavior:

- If `background=true`: returns started status.
- If `background=false` or omitted: returns completed result with scan metrics.

Synchronous response example:

```json
{
  "status": "completed",
  "analyzing": "logs.csv",
  "user_id": "356721c8-1559-4c00-9aec-8be06d861028",
  "scan_id": "8b0cd45b-8b23-4b01-9eef-702a7ca3d2d4",
  "total_logs": 5421,
  "total_threats": 87,
  "risk_score": 445
}
```

### `GET /users/{user_id}/scans?limit=20&offset=0`

Lists scans for a user, newest first.

Response example:

```json
{
  "total": 3,
  "limit": 20,
  "offset": 0,
  "scans": [
    {
      "scan_id": "8b0cd45b-8b23-4b01-9eef-702a7ca3d2d4",
      "user_id": "356721c8-1559-4c00-9aec-8be06d861028"
    }
  ]
}
```

### `GET /users/{user_id}/scans/{scan_id}`

Gets a single scan by UUID or `latest`.

Includes:

- scan metadata
- `terminal_summary`
- categories
- `attack_chain_count`
- `impossible_travel_count`

### `DELETE /users/{user_id}/scans/{scan_id}`

Deletes a scan (and cascaded child records).

Response example:

```json
{
  "deleted": "8b0cd45b-8b23-4b01-9eef-702a7ca3d2d4"
}
```

## 4. Scan Sub-Resources (User Scoped)

### `GET /users/{user_id}/scans/{scan_id}/categories`

Returns categories ranked by risk for the given scan.

Response shape:

```json
{
  "count": 2,
  "categories": []
}
```

### `GET /users/{user_id}/scans/{scan_id}/events`

Returns paginated anomalous events.

Query params:

- `category` (optional)
- `computer` (optional)
- `user` (optional)
- `limit` (default 200, max 5000)
- `offset` (default 0)

Response shape:

```json
{
  "total": 87,
  "limit": 200,
  "offset": 0,
  "events": []
}
```

### `GET /users/{user_id}/scans/{scan_id}/chains`

Returns correlated attack chains.

Response shape:

```json
{
  "count": 3,
  "chains": []
}
```

### `GET /users/{user_id}/scans/{scan_id}/travels`

Returns impossible-travel detections.

Response shape:

```json
{
  "count": 1,
  "travels": []
}
```

### `GET /users/{user_id}/scans/{scan_id}/summary`

Returns AI executive summary for the scan.

Response shape:

```json
{
  "scan_id": "8b0cd45b-8b23-4b01-9eef-702a7ca3d2d4",
  "generated_at": "2026-03-23T10:30:00",
  "scan_meta": {},
  "executive_briefing": "..."
}
```

## 5. AI Q&A

### `POST /ask`

Answers a security question based on one specific scan.

Request body:

```json
{
  "scan_id": "8b0cd45b-8b23-4b01-9eef-702a7ca3d2d4",
  "question": "Which users are involved in brute force activity?"
}
```

Response shape:

```json
{
  "scan_id": "8b0cd45b-8b23-4b01-9eef-702a7ca3d2d4",
  "question": "Which users are involved in brute force activity?",
  "answer": "..."
}
```

## 6. Dashboard

### `GET /dashboard/stats`

Aggregates totals across all scans.

Response example:

```json
{
  "total_scans": 142,
  "total_logs_analyzed": 854231,
  "total_threats_detected": 2847,
  "average_risk_score": 384.2,
  "highest_risk_score": 500
}
```

## 7. System Monitoring

### `GET /system/stats`

Returns one-shot system metrics (CPU/RAM snapshot).

### `WS /ws/system-stats`

WebSocket endpoint streaming live system stats every ~2 seconds.

## 8. Route Inventory (Complete)

All current routes in `main_api.py`:

1. `GET /health`
2. `POST /upload`
3. `POST /users/{user_id}/scans`
4. `GET /users/{user_id}/scans`
5. `GET /users/{user_id}/scans/{scan_id}`
6. `DELETE /users/{user_id}/scans/{scan_id}`
7. `GET /users/{user_id}/scans/{scan_id}/categories`
8. `GET /users/{user_id}/scans/{scan_id}/events`
9. `GET /users/{user_id}/scans/{scan_id}/chains`
10. `GET /users/{user_id}/scans/{scan_id}/travels`
11. `GET /users/{user_id}/scans/{scan_id}/summary`
12. `POST /ask`
13. `GET /dashboard/stats`
14. `GET /system/stats`
15. `WS /ws/system-stats`
