# AI-Driven WAF — Frozen API Contract

> **IMPORTANT**: This contract defines the communication interface between the WAF Gateway / Storage Plane and the Analytics Dashboard UI (Next.js). Any modifications to endpoints, request bodies, query parameters, or response schemas require explicit team agreement and must be reflected in `docs/openapi.json`.

---

## 1. Contract Overview

- **Format**: REST API + Server-Sent Events (SSE)
- **OpenAPI Specification**: [`docs/openapi.json`](file:///d:/vsasaaadada/mini-proj-V/docs/openapi.json)
- **Generation Command**: `make openapi`
- **Default Port**: `8000` (`http://localhost:8000`)
- **Documentation UI**: Swagger UI at `http://localhost:8000/docs`, ReDoc at `http://localhost:8000/redoc`

---

## 2. Endpoints Summary (TRD 2.6)

| Method | Endpoint | Description | Request / Query | Response Model |
|---|---|---|---|---|
| `POST` | `/api/auth/login` | SecOps authentication with brute-force defense | JSON: `{"username", "password"}` | `LoginResponse` |
| `GET` | `/api/auth/me` | Current authenticated admin session profile | Bearer Token Header | `UserResponse` |
| `POST` | `/api/auth/logout` | Client token disposal endpoint | None | `{"success": true}` |
| `GET` | `/api/stats/summary` | Aggregate KPI statistics | `range` (`5m`, `1h`, `24h`, `7d`) | `SummaryStatsResponse` |
| `GET` | `/api/stats/timeseries` | Binned traffic vs threats data | `range`, `bucket` (`1m`, `5m`, `1h`) | `TimeSeriesResponse` |
| `GET` | `/api/stats/attack-types` | Breakdown by attack category | `range` | `AttackTypeResponse` |
| `GET` | `/api/stats/top-endpoints` | Top targeted paths | `limit` (default: 10), `range` | `TopEndpointsResponse` |
| `GET` | `/api/stats/top-ips` | Top requesting and blocked IPs | `limit` (default: 10), `range` | `TopIPsResponse` |
| `GET` | `/api/events` | Paginated inspection log with multi-facet filters | `limit`, `offset`, `verdict`, `attack_type`, `anomaly_flag`, `feedback`, `search` | `EventsListResponse` |
| `GET` | `/api/events/{id}` | Single event with explainer tokens & spans | `{id}` in path | `EventDetailResponse` |
| `POST` | `/api/events/{id}/feedback` | Record FP / TP / Clear analyst review | JSON: `{"feedback": "fp" \| "tp" \| "clear", "notes"}` | `FeedbackResponse` |
| `GET` | `/api/feedback/export` | Export analyst feedback for candidate retraining | `limit` (default: 500) | `FeedbackExportResponse` |
| `GET` | `/api/stream` | Real-time SSE alert event feed | None | `text/event-stream` (`event: alert`) |
| `GET` | `/api/config` | Read runtime WAF configuration | None | `WAFConfig` |
| `PUT` | `/api/config` | Update runtime WAF settings (creates audit log) | JSON: `WAFConfig` | `WAFConfig` |
| `GET` | `/api/config/audit` | Query immutable configuration change audit trail | `limit` (default: 20) | `ConfigAuditResponse` |
| `GET` | `/api/config/threshold-sweep` | 11-point threshold trade-off curve (FPR, recall, F1) | None | `ThresholdSweepResponse` |
| `GET` | `/healthz` | Dashboard API liveness check | None | `{"status": "ok", ...}` |

---

## 3. Data Transfer Objects (DTOs)

### SummaryStatsResponse
```json
{
  "total_requests": 2000,
  "total_blocked": 400,
  "total_flagged": 0,
  "total_allowed": 1600,
  "block_rate": 20.0,
  "flag_rate": 0.0,
  "avg_latency_ms": 11.45
}
```

### TimeSeriesPoint
```json
{
  "timestamp": "2026-11-15T00:00:00Z",
  "total": 85,
  "threats": 15,
  "blocked": 15,
  "flagged": 0
}
```

### EventDetailResponse
```json
{
  "id": "e4a2b910-c081-4b72-9ff0-51a8d05e3201",
  "ts": "2026-11-14T23:45:10Z",
  "client_ip": "45.33.32.156",
  "method": "GET",
  "path": "/rest/products/search",
  "query_summary": "q=' OR '1'='1",
  "body_summary": "",
  "user_agent": "sqlmap/1.7.11#stable",
  "verdict": "block",
  "attack_type": "sqli",
  "ml_score": 0.942,
  "rule_hit": "SQLI_TAUTOLOGY_01",
  "latency_ms": 14.2,
  "explanation": {
    "matched_rule": "SQLI_TAUTOLOGY_01",
    "top_tokens": [
      { "token": "' or '1'='1", "weight": 0.45 }
    ],
    "summary": "SQL injection detected via signature SQLI_TAUTOLOGY_01"
  },
  "feedback": null,
  "model_version": "20261114_195540"
}
```

---

## 4. Contract Governance Rules

1. Any schema change must maintain backward compatibility or be scheduled with all frontend/ML developers.
2. The UI client must never execute raw HTML or unescaped strings received from `query_summary`, `body_summary`, or `path`.
3. The OpenAPI specification at `docs/openapi.json` must be re-exported (`make openapi`) whenever route signatures or schemas change.
