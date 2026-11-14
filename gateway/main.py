"""
FastAPI WAF Gateway (Reverse Proxy & Inspection Engine).
Implements TRD 2.1, 2.2, 2.5, 2.6 and Stage 1 Task 3:
  - Asynchronous reverse-proxy forwarding to UPSTREAM_URL
  - Hop-by-hop header stripping
  - Normalisation & detection pipeline stubs
  - Monitor vs Block mode handling
  - Non-blocking async queue for DB event logging
  - Sensitive parameter masking
  - /healthz endpoint
  - Fail-open / fail-closed exception handling
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from gateway.config import settings
from gateway.masking import mask_body_summary, mask_query_string
from gateway.models import Event, get_engine, init_db
from gateway.normalizer import normalise_request
from gateway.pipeline import decide, ml_score, rule_check

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("waf-gateway")

# Hop-by-hop headers according to RFC 7230 / RFC 2616 to strip when proxying
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}

BLOCK_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 Forbidden - Request Blocked</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 2.5rem;
      max-width: 480px;
      text-align: center;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }}
    h1 {{ color: #f43f5e; margin: 0 0 1rem 0; font-size: 1.75rem; }}
    p {{ color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin-bottom: 1.5rem; }}
    .id-badge {{
      background: #0f172a;
      border: 1px dashed #475569;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, monospace;
      color: #38bdf8;
      font-size: 0.875rem;
      word-break: break-all;
      margin-bottom: 1.5rem;
    }}
    .footer {{ font-size: 0.8rem; color: #64748b; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>403 Forbidden</h1>
    <p>This request was blocked by the AI-Driven Web Application Firewall (WAF) because it violated active security policy rules.</p>
    <div class="id-badge">Request ID: {request_id}</div>
    <div class="footer">If you believe this is a false positive, please share this Request ID with your security administrator.</div>
  </div>
</body>
</html>
"""

# Asynchronous log queue & HTTP client
log_queue: asyncio.Queue = asyncio.Queue(maxsize=settings.log_queue_max_size)
http_client: Optional[httpx.AsyncClient] = None
worker_task: Optional[asyncio.Task] = None


def _write_event_sync(event_data: Dict[str, Any]) -> None:
    """Synchronous database write executed in worker thread."""
    from sqlalchemy.orm import sessionmaker

    engine = get_engine(settings.db_url)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        event = Event(**event_data)
        session.add(event)
        session.commit()


async def log_worker() -> None:
    """Background worker processing event logs asynchronously to decouple latency."""
    logger.info("Started background event logging worker")
    while True:
        try:
            event_data = await log_queue.get()
            try:
                await asyncio.to_thread(_write_event_sync, event_data)
            except Exception as db_err:
                logger.error("DB logging error (gateway continuing): %s", db_err)
            finally:
                log_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Unexpected error in log worker: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database schema, background worker and HTTP client
    global http_client, worker_task
    try:
        init_db(settings.db_url)
    except Exception as e:
        logger.warning("Could not initialize DB on startup: %s. Continuing...", e)

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=5.0),
        follow_redirects=False,
    )
    worker_task = asyncio.create_task(log_worker())
    logger.info("WAF Gateway initialized. Upstream: %s | Mode: %s", settings.upstream_url, settings.waf_mode)

    yield

    # Shutdown
    if worker_task:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass
    if http_client:
        await http_client.aclose()


app = FastAPI(
    title="AI-Driven WAF Gateway",
    description="Reverse-proxy WAF inspection engine with ML threat detection",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/healthz")
async def healthz():
    """Liveness check endpoint. Not logged as an inspection event."""
    return {
        "status": "ok",
        "service": "waf-gateway",
        "waf_mode": settings.waf_mode,
        "upstream": settings.upstream_url,
    }


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_catch_all(request: Request, path: str):
    start_time = time.perf_counter()
    request_id = str(uuid.uuid4())
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Forwarded-For handling
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(",")[0].strip()

    raw_query = request.url.query
    raw_body = await request.body()
    user_agent = request.headers.get("user-agent", "")

    # 1. Normalise & Inspect
    try:
        norm = normalise_request(
            method=request.method,
            path=f"/{path}",
            query_string=raw_query,
            headers=dict(request.headers),
            body_bytes=raw_body,
            max_inspect_bytes=settings.max_body_inspect_bytes,
        )

        # 2. Rule Check & ML Score
        rule_res = rule_check(norm)
        ml_res = ml_score(norm)

        # 3. Decision
        verdict = decide(
            rule=rule_res,
            ml=ml_res,
            mode=settings.waf_mode,
            threshold=settings.ml_threshold,
            norm=norm,
        )
    except Exception as inspect_err:
        logger.error("Inspection error on request %s: %s", request_id, inspect_err)
        if settings.fail_mode == "closed":
            return HTMLResponse(
                status_code=403,
                content=BLOCK_HTML_TEMPLATE.format(request_id=request_id),
            )
        # Fail-open behavior: proceed as allowed
        from gateway.pipeline import Verdict
        verdict = Verdict(
            action="allow",
            attack_type="benign",
            rule_hit=None,
            ml_score=0.0,
            explanation={"error": str(inspect_err), "fail_mode": "open"},
        )

    latency_ms = (time.perf_counter() - start_time) * 1000.0

    # 4. Asynchronously enqueue event log with sensitive data masked
    masked_query = mask_query_string(raw_query)
    body_snippet = raw_body[: settings.max_body_inspect_bytes].decode("utf-8", errors="replace")
    masked_body = mask_body_summary(body_snippet)

    event_payload = {
        "id": request_id,
        "client_ip": client_ip,
        "method": request.method,
        "path": f"/{path}",
        "query_summary": masked_query,
        "body_summary": masked_body,
        "user_agent": user_agent,
        "rule_hit": verdict.rule_hit,
        "ml_score": float(verdict.ml_score),
        "verdict": verdict.action,
        "attack_type": verdict.attack_type,
        "latency_ms": round(latency_ms, 2),
        "explanation": verdict.explanation,
    }

    try:
        log_queue.put_nowait(event_payload)
    except asyncio.QueueFull:
        logger.warning("Log queue full; dropped event %s", request_id)

    # 5. Enforcement: Block verdict returns HTTP 403
    if verdict.action == "block":
        return HTMLResponse(
            status_code=403,
            content=BLOCK_HTML_TEMPLATE.format(request_id=request_id),
            headers={"X-WAF-Request-ID": request_id, "X-WAF-Verdict": "block"},
        )

    # 6. Forwarding: Stream to upstream
    fwd_headers = {}
    for k, v in request.headers.items():
        if k.lower() not in HOP_BY_HOP_HEADERS:
            fwd_headers[k] = v

    fwd_headers["x-forwarded-for"] = client_ip
    fwd_headers["x-waf-request-id"] = request_id

    upstream_base = settings.upstream_url.rstrip("/")
    target_url = f"{upstream_base}/{path}"
    if raw_query:
        target_url = f"{target_url}?{raw_query}"

    try:
        global http_client
        if http_client is None:
            http_client = httpx.AsyncClient(timeout=30.0)

        upstream_req = http_client.build_request(
            method=request.method,
            url=target_url,
            headers=fwd_headers,
            content=raw_body,
        )

        # Ensure hop-by-hop headers are stripped from outgoing request to upstream
        for h in HOP_BY_HOP_HEADERS:
            if h != "host" and h in upstream_req.headers:
                del upstream_req.headers[h]

        upstream_resp = await http_client.send(upstream_req, stream=True)

        resp_headers = {}
        for hk, hv in upstream_resp.headers.items():
            if hk.lower() not in HOP_BY_HOP_HEADERS and hk.lower() != "content-length":
                resp_headers[hk] = hv

        resp_headers["x-waf-request-id"] = request_id
        resp_headers["x-waf-verdict"] = verdict.action

        async def response_streamer():
            try:
                async for chunk in upstream_resp.aiter_bytes():
                    yield chunk
            finally:
                await upstream_resp.aclose()

        return StreamingResponse(
            response_streamer(),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        )
    except Exception as upstream_err:
        logger.error("Error communicating with upstream %s: %s", target_url, upstream_err)
        return JSONResponse(
            status_code=502,
            content={
                "error": "Bad Gateway",
                "message": f"Could not reach upstream service: {upstream_err}",
                "request_id": request_id,
            },
        )
