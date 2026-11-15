"""
Unit tests for Per-IP Rate Limiter and Rate Anomaly Detector (gateway/tests/test_rate_limiter.py).
Stage 4 Task 2 verification:
  - Sliding window request rate calculation
  - Anomaly flag triggers: rate_burst, block_burst, scanner_like
  - Enforcement mode: flag-only vs HTTP 429
  - Anti-spoofing trusted proxy verification
  - LRU memory bounding
  - Performance latency overhead
"""

import time
import pytest
from gateway.rate_limiter import SlidingWindowRateLimiter


def test_rate_limiter_burst_flagging():
    """Requests exceeding burst threshold are flagged as rate_burst."""
    limiter = SlidingWindowRateLimiter(max_tracked_ips=100)

    # 10 requests with burst threshold of 5
    for i in range(5):
        res = limiter.check_request("192.0.2.1", "/api/data", window_sec=10, burst_threshold=5, rate_enforce=False)
        assert res.anomaly_flag is None
        assert res.should_block_429 is False

    # 6th request triggers rate_burst
    burst_res = limiter.check_request("192.0.2.1", "/api/data", window_sec=10, burst_threshold=5, rate_enforce=False)
    assert burst_res.anomaly_flag == "rate_burst"
    assert burst_res.should_block_429 is False  # Flag-only by default


def test_rate_limiter_enforcement_429():
    """When rate_enforce is True, burst traffic triggers should_block_429."""
    limiter = SlidingWindowRateLimiter(max_tracked_ips=100)

    for _ in range(5):
        limiter.check_request("192.0.2.2", "/items", window_sec=10, burst_threshold=5, rate_enforce=True)

    enforce_res = limiter.check_request("192.0.2.2", "/items", window_sec=10, burst_threshold=5, rate_enforce=True)
    assert enforce_res.anomaly_flag == "rate_burst"
    assert enforce_res.should_block_429 is True


def test_rate_limiter_block_burst_flagging():
    """Multiple 403 blocks within the window trigger block_burst anomaly."""
    limiter = SlidingWindowRateLimiter(max_tracked_ips=100)
    ip = "192.0.2.3"

    for _ in range(5):
        limiter.record_block(ip)

    res = limiter.check_request(ip, "/login", window_sec=10, burst_threshold=20, rate_enforce=False)
    assert res.anomaly_flag == "block_burst"


def test_rate_limiter_scanner_like_detection():
    """Rapid scanning across multiple unique paths triggers scanner_like."""
    limiter = SlidingWindowRateLimiter(max_tracked_ips=100)
    ip = "192.0.2.4"

    for idx in range(16):
        res = limiter.check_request(ip, f"/path/{idx}", window_sec=10, burst_threshold=50, rate_enforce=False)

    assert res.anomaly_flag == "scanner_like"


def test_trusted_proxy_anti_spoofing():
    """
    X-Forwarded-For is only honored from trusted proxies.
    Untrusted peer IP spoofing attempts are ignored.
    """
    limiter = SlidingWindowRateLimiter(
        trusted_proxies_str="127.0.0.1,10.0.0.1",
    )

    # 1. Trusted proxy peer -> resolves client IP from X-Forwarded-For
    resolved_ip = limiter.resolve_client_ip(peer_ip="127.0.0.1", x_forwarded_for="203.0.113.55, 10.0.0.1")
    assert resolved_ip == "203.0.113.55"

    # 2. Untrusted peer IP -> X-Forwarded-For is discarded, peer IP is used
    spoofed_ip = limiter.resolve_client_ip(peer_ip="198.51.100.77", x_forwarded_for="8.8.8.8")
    assert spoofed_ip == "198.51.100.77"


def test_rate_limiter_lru_memory_bounding():
    """Maximum tracked IPs cap is strictly enforced via LRU eviction."""
    max_ips = 5
    limiter = SlidingWindowRateLimiter(max_tracked_ips=max_ips)

    # Add 5 IPs
    for i in range(5):
        limiter.check_request(f"192.0.2.{i}", "/test", window_sec=10, burst_threshold=10)

    assert len(limiter._states) == 5

    # 6th IP causes eviction of oldest
    limiter.check_request("192.0.2.100", "/test", window_sec=10, burst_threshold=10)
    assert len(limiter._states) == 5
    assert "192.0.2.0" not in limiter._states
    assert "192.0.2.100" in limiter._states


def test_rate_limiter_microsecond_latency():
    """Rate check latency overhead must be negligible (< 0.1 ms)."""
    limiter = SlidingWindowRateLimiter(max_tracked_ips=1000)

    t0 = time.perf_counter()
    for _ in range(100):
        limiter.check_request("192.0.2.50", "/benchmark", window_sec=10, burst_threshold=500)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    avg_lat = elapsed_ms / 100.0

    assert avg_lat < 0.1  # Less than 100 microseconds per request
