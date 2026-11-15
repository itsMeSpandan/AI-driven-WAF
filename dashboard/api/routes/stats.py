"""
Analytics statistics and aggregation routes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from dashboard.api.schemas import (
    AttackTypeItem,
    AttackTypeResponse,
    SummaryStatsResponse,
    TimeSeriesPoint,
    TimeSeriesResponse,
    TopEndpointItem,
    TopEndpointsResponse,
    TopIPItem,
    TopIPsResponse,
)
from gateway.models import Event, get_db

router = APIRouter(prefix="/api/stats", tags=["stats"])


def parse_range(range_str: str) -> timedelta:
    """Parse range string like '5m', '1h', '24h', '7d' into timedelta."""
    val = range_str.strip().lower()
    if val.endswith("m"):
        return timedelta(minutes=int(val[:-1]))
    elif val.endswith("h"):
        return timedelta(hours=int(val[:-1]))
    elif val.endswith("d"):
        return timedelta(days=int(val[:-1]))
    return timedelta(hours=24)


@router.get("/summary", response_model=SummaryStatsResponse)
def get_summary(
    range: str = Query("24h", description="Time window: 5m, 1h, 24h, 7d"),
    db: Session = Depends(get_db),
):
    since = datetime.now(timezone.utc) - parse_range(range)

    total_reqs = db.query(func.count(Event.id)).filter(Event.ts >= since).scalar() or 0
    blocked_reqs = (
        db.query(func.count(Event.id))
        .filter(Event.ts >= since, Event.verdict == "block")
        .scalar()
        or 0
    )
    flagged_reqs = (
        db.query(func.count(Event.id))
        .filter(Event.ts >= since, Event.verdict == "flag")
        .scalar()
        or 0
    )
    allowed_reqs = (
        db.query(func.count(Event.id))
        .filter(Event.ts >= since, Event.verdict == "allow")
        .scalar()
        or 0
    )
    avg_latency = (
        db.query(func.avg(Event.latency_ms)).filter(Event.ts >= since).scalar() or 0.0
    )

    block_rate = (blocked_reqs / total_reqs * 100.0) if total_reqs > 0 else 0.0
    flag_rate = (flagged_reqs / total_reqs * 100.0) if total_reqs > 0 else 0.0

    return SummaryStatsResponse(
        total_requests=total_reqs,
        total_blocked=blocked_reqs,
        total_flagged=flagged_reqs,
        total_allowed=allowed_reqs,
        block_rate=round(block_rate, 2),
        flag_rate=round(flag_rate, 2),
        avg_latency_ms=round(float(avg_latency), 2),
    )


@router.get("/timeseries", response_model=TimeSeriesResponse)
def get_timeseries(
    range: str = Query("24h", description="Time range"),
    bucket: str = Query("1h", description="Bucket size: 1m, 5m, 1h"),
    db: Session = Depends(get_db),
):
    now_utc = datetime.now(timezone.utc)
    since = now_utc - parse_range(range)
    since_naive = since.replace(tzinfo=None)

    # Fetch relevant events in range ordered by timestamp
    events = (
        db.query(Event.ts, Event.verdict)
        .filter(Event.ts >= since_naive)
        .order_by(Event.ts.asc())
        .all()
    )

    # Bin into intervals
    bucket_delta = parse_range(bucket)
    if bucket_delta.total_seconds() < 60:
        bucket_delta = timedelta(minutes=1)
    bucket_secs = int(bucket_delta.total_seconds())

    # Generate fixed chronological bucket keys from since up to now
    points_dict = {}
    current = since
    while current <= now_utc:
        bucket_key = current.strftime("%Y-%m-%dT%H:%M:00Z")
        points_dict[bucket_key] = {"total": 0, "threats": 0, "blocked": 0, "flagged": 0}
        current += bucket_delta

    for ev_ts, verdict in events:
        if ev_ts is None:
            continue
        if ev_ts.tzinfo is None:
            ev_ts = ev_ts.replace(tzinfo=timezone.utc)
        if ev_ts < since:
            continue

        # Floor into the correct bucket interval without creating unaligned keys
        elapsed = (ev_ts - since).total_seconds()
        bucket_idx = int(elapsed // bucket_secs)
        bucket_time = since + timedelta(seconds=bucket_idx * bucket_secs)
        bucket_key = bucket_time.strftime("%Y-%m-%dT%H:%M:00Z")

        if bucket_key in points_dict:
            points_dict[bucket_key]["total"] += 1
            if verdict in ("block", "flag"):
                points_dict[bucket_key]["threats"] += 1
                if verdict == "block":
                    points_dict[bucket_key]["blocked"] += 1
                elif verdict == "flag":
                    points_dict[bucket_key]["flagged"] += 1

    sorted_points = [
        TimeSeriesPoint(
            timestamp=k,
            total=v["total"],
            threats=v["threats"],
            blocked=v["blocked"],
            flagged=v["flagged"],
        )
        for k, v in sorted(points_dict.items())
    ]

    return TimeSeriesResponse(range=range, bucket=bucket, points=sorted_points)


@router.get("/attack-types", response_model=AttackTypeResponse)
def get_attack_types(
    range: str = Query("24h"),
    db: Session = Depends(get_db),
):
    since = datetime.now(timezone.utc) - parse_range(range)

    query = (
        db.query(Event.attack_type, func.count(Event.id))
        .filter(Event.ts >= since, Event.attack_type != "benign")
        .group_by(Event.attack_type)
        .all()
    )

    total_attacks = sum(c for _, c in query)
    items = []
    for atype, count in query:
        pct = (count / total_attacks * 100.0) if total_attacks > 0 else 0.0
        items.append(AttackTypeItem(attack_type=atype, count=count, percentage=round(pct, 2)))

    # Sort descending by count
    items.sort(key=lambda x: x.count, reverse=True)

    return AttackTypeResponse(total_attacks=total_attacks, items=items)


@router.get("/top-endpoints", response_model=TopEndpointsResponse)
def get_top_endpoints(
    limit: int = Query(10, ge=1, le=50),
    range: str = Query("24h"),
    db: Session = Depends(get_db),
):
    since = datetime.now(timezone.utc) - parse_range(range)

    # Aggregated query for each path
    rows = (
        db.query(
            Event.path,
            func.sum(case((Event.verdict.in_(["block", "flag"]), 1), else_=0)).label("attack_cnt"),
            func.count(Event.id).label("total_cnt"),
        )
        .filter(Event.ts >= since)
        .group_by(Event.path)
        .order_by(func.sum(case((Event.verdict.in_(["block", "flag"]), 1), else_=0)).desc())
        .limit(limit)
        .all()
    )

    items = [
        TopEndpointItem(
            path=row[0],
            attack_count=int(row[1] or 0),
            total_count=int(row[2] or 0),
        )
        for row in rows
    ]

    return TopEndpointsResponse(items=items)


@router.get("/top-ips", response_model=TopIPsResponse)
def get_top_ips(
    limit: int = Query(10, ge=1, le=50),
    range: str = Query("24h"),
    db: Session = Depends(get_db),
):
    since = datetime.now(timezone.utc) - parse_range(range)

    rows = (
        db.query(
            Event.client_ip,
            func.count(Event.id).label("total_cnt"),
            func.sum(case((Event.verdict == "block", 1), else_=0)).label("blocked_cnt"),
        )
        .filter(Event.ts >= since)
        .group_by(Event.client_ip)
        .order_by(func.count(Event.id).desc())
        .limit(limit)
        .all()
    )

    items = [
        TopIPItem(
            ip=row[0],
            total_requests=int(row[1] or 0),
            blocked_requests=int(row[2] or 0),
        )
        for row in rows
    ]

    return TopIPsResponse(items=items)
