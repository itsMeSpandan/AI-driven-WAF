"""
Pydantic schemas and response models for Dashboard API.
Implements TRD 2.6 frozen API contract.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class SummaryStatsResponse(BaseModel):
    total_requests: int = Field(..., description="Total requests processed")
    total_blocked: int = Field(..., description="Total blocked requests")
    total_flagged: int = Field(..., description="Total flagged (monitor mode) requests")
    total_allowed: int = Field(..., description="Total clean allowed requests")
    block_rate: float = Field(..., description="Percentage of requests blocked (0.0 to 100.0)")
    flag_rate: float = Field(..., description="Percentage of requests flagged (0.0 to 100.0)")
    avg_latency_ms: float = Field(..., description="Average request inspection latency in milliseconds")


class TimeSeriesPoint(BaseModel):
    timestamp: str = Field(..., description="ISO 8601 formatted bucket timestamp")
    total: int = Field(0, description="Total requests in bucket")
    threats: int = Field(0, description="Total threats (blocked + flagged) in bucket")
    blocked: int = Field(0, description="Blocked requests in bucket")
    flagged: int = Field(0, description="Flagged requests in bucket")


class TimeSeriesResponse(BaseModel):
    range: str
    bucket: str
    points: List[TimeSeriesPoint]


class AttackTypeItem(BaseModel):
    attack_type: str = Field(..., description="Category: sqli, xss, bot_anomaly, etc.")
    count: int = Field(..., description="Number of occurrences")
    percentage: float = Field(..., description="Percentage of total attacks")


class AttackTypeResponse(BaseModel):
    total_attacks: int
    items: List[AttackTypeItem]


class TopEndpointItem(BaseModel):
    path: str = Field(..., description="Request URI path")
    attack_count: int = Field(..., description="Number of malicious requests targeted at this path")
    total_count: int = Field(..., description="Total requests targeted at this path")


class TopEndpointsResponse(BaseModel):
    items: List[TopEndpointItem]


class TopIPItem(BaseModel):
    ip: str = Field(..., description="Client IP address")
    total_requests: int = Field(..., description="Total requests from this IP")
    blocked_requests: int = Field(..., description="Blocked requests from this IP")


class TopIPsResponse(BaseModel):
    items: List[TopIPItem]


class EventListItem(BaseModel):
    id: str
    ts: datetime
    client_ip: str
    method: str
    path: str
    query_summary: Optional[str] = ""
    body_summary: Optional[str] = ""
    verdict: str  # 'allow', 'flag', 'block'
    attack_type: str
    ml_score: float
    rule_hit: Optional[str] = None
    latency_ms: float
    feedback: Optional[str] = None


class EventsListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[EventListItem]


class EventDetailResponse(EventListItem):
    user_agent: Optional[str] = ""
    explanation: Dict[str, Any] = Field(default_factory=dict)


class FeedbackRequest(BaseModel):
    feedback: Literal["fp", "tp"] = Field(..., description="'fp' for false positive, 'tp' for true positive")
    notes: Optional[str] = Field(None, description="Optional analyst comment or justification")


class FeedbackResponse(BaseModel):
    success: bool
    id: str
    feedback: str


class WAFConfig(BaseModel):
    waf_mode: Literal["monitor", "block"] = Field("block", description="Operating mode")
    ml_threshold: float = Field(0.75, ge=0.0, le=1.0, description="ML anomaly trigger threshold")
    max_body_inspect_bytes: int = Field(16384, ge=512, le=1048576, description="Inspection cap in bytes")
    fail_mode: Literal["open", "closed"] = Field("closed", description="Fail open or closed on fatal error")
