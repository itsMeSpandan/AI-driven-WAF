"""
Per-IP sliding-window rate anomaly detector and memory-bounded rate limiter.
Implements Stage 4 Task 2 per TRD 2.6, 2.7, 2.9 & STAGES.md:
  - In-memory sliding-window tracking per client IP:
      * Request rate (count in window)
      * Blocked/403 rate (count in window)
      * Unique path count in window (scanner detection)
  - Anomaly classification: 'rate_burst', 'block_burst', 'scanner_like'
  - Flag-only by default; optional HTTP 429 enforcement when rate_enforce=True
  - Trusted proxy verification: only honors X-Forwarded-For if client peer IP
    is within TRUSTED_PROXIES. Prevents IP spoofing.
  - Memory bounded state with LRU / TTL eviction (capped max_tracked_ips).
  - Note: State is maintained per-process (isolated in worker instance).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("waf-rate-limiter")

# Default trusted proxy IPs / CIDR networks
DEFAULT_TRUSTED_PROXIES = os.getenv(
    "TRUSTED_PROXIES",
    "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
)


@dataclass
class IPRateState:
    """Sliding-window history for a single client IP address."""

    timestamps: Deque[float] = field(default_factory=deque)
    block_timestamps: Deque[float] = field(default_factory=deque)
    path_history: Deque[Tuple[float, str]] = field(default_factory=deque)
    last_seen: float = field(default_factory=time.monotonic)


@dataclass
class RateLimitResult:
    """Evaluation result for an incoming HTTP request."""

    anomaly_flag: Optional[str] = None  # 'rate_burst', 'block_burst', 'scanner_like', or None
    should_block_429: bool = False
    current_rate: int = 0
    burst_threshold: int = 30
    window_sec: int = 10


class SlidingWindowRateLimiter:
    """
    In-memory bounded sliding window rate limiter.
    Employs an OrderedDict as an LRU cache to cap maximum tracked IPs.
    """

    def __init__(
        self,
        max_tracked_ips: int = 10000,
        cleanup_interval_sec: float = 60.0,
        trusted_proxies_str: Optional[str] = None,
    ):
        self.max_tracked_ips = max_tracked_ips
        self.cleanup_interval_sec = cleanup_interval_sec
        self._states: OrderedDict[str, IPRateState] = OrderedDict()
        self._last_cleanup = time.monotonic()
        self._trusted_networks = self._parse_trusted_proxies(
            trusted_proxies_str or DEFAULT_TRUSTED_PROXIES
        )

    def _parse_trusted_proxies(self, proxies_str: str) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for item in proxies_str.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                # Handle single IP or CIDR network
                if "/" not in item:
                    ip_obj = ipaddress.ip_address(item)
                    net = ipaddress.ip_network(f"{item}/32" if ip_obj.version == 4 else f"{item}/128")
                else:
                    net = ipaddress.ip_network(item, strict=False)
                networks.append(net)
            except ValueError:
                logger.warning("Invalid trusted proxy network string: %s", item)
        return networks

    def is_trusted_proxy(self, peer_ip: str) -> bool:
        """Determines if the raw socket peer is an authorized reverse proxy."""
        try:
            addr = ipaddress.ip_address(peer_ip)
            return any(addr in net for net in self._trusted_networks)
        except ValueError:
            return False

    def resolve_client_ip(self, peer_ip: str, x_forwarded_for: Optional[str]) -> str:
        """
        Safely extracts real client IP.
        Only trusts X-Forwarded-For if peer_ip originates from a configured trusted proxy.
        Otherwise discards X-Forwarded-For to prevent IP spoofing attacks.
        """
        if not peer_ip:
            return "127.0.0.1"

        if not x_forwarded_for:
            return peer_ip

        if not self.is_trusted_proxy(peer_ip):
            logger.debug(
                "Untrusted peer %s attempted X-Forwarded-For spoofing (%s); using socket peer.",
                peer_ip,
                x_forwarded_for,
            )
            return peer_ip

        # Peer is trusted proxy: take leftmost client IP in chain
        parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
        if parts:
            try:
                # Validate IP address syntax
                ipaddress.ip_address(parts[0])
                return parts[0]
            except ValueError:
                pass

        return peer_ip

    def _evict_if_needed(self, now: float) -> None:
        """Maintains memory safety by evicting stale IPs or LRU entries."""
        # 1. Periodic cleanup of expired entries
        if now - self._last_cleanup > self.cleanup_interval_sec:
            stale_threshold = now - 300.0  # 5 minutes idle
            stale_keys = [k for k, v in self._states.items() if v.last_seen < stale_threshold]
            for k in stale_keys:
                del self._states[k]
            self._last_cleanup = now

        # 2. Hard cap enforcement: remove oldest LRU item
        while len(self._states) >= self.max_tracked_ips:
            self._states.popitem(last=False)

    def check_request(
        self,
        client_ip: str,
        path: str,
        window_sec: int = 10,
        burst_threshold: int = 30,
        rate_enforce: bool = False,
        enabled: bool = True,
    ) -> RateLimitResult:
        """
        Inspects an incoming request from client_ip within the sliding window.
        Returns anomaly flags and HTTP 429 enforcement decision.
        """
        if not enabled:
            return RateLimitResult(
                anomaly_flag=None,
                should_block_429=False,
                current_rate=0,
                burst_threshold=burst_threshold,
                window_sec=window_sec,
            )

        now = time.monotonic()
        self._evict_if_needed(now)

        # Retrieve or initialize state, moving to end of OrderedDict for LRU
        if client_ip in self._states:
            state = self._states[client_ip]
            self._states.move_to_end(client_ip)
        else:
            state = IPRateState()
            self._states[client_ip] = state

        state.last_seen = now
        window_cutoff = now - float(window_sec)

        # 1. Record this request timestamp and prune expired
        state.timestamps.append(now)
        while state.timestamps and state.timestamps[0] < window_cutoff:
            state.timestamps.popleft()

        # 2. Record path and prune expired path history
        state.path_history.append((now, path))
        while state.path_history and state.path_history[0][0] < window_cutoff:
            state.path_history.popleft()

        # 3. Prune expired block timestamps
        while state.block_timestamps and state.block_timestamps[0] < window_cutoff:
            state.block_timestamps.popleft()

        req_count = len(state.timestamps)
        block_count = len(state.block_timestamps)
        unique_paths = len({p for _, p in state.path_history})

        # Evaluate anomaly conditions
        anomaly_flag = None
        should_block = False

        if req_count > burst_threshold:
            anomaly_flag = "rate_burst"
            if rate_enforce:
                should_block = True
        elif block_count >= 5:
            # 5 or more blocks within window -> scanner / brute force attack
            anomaly_flag = "block_burst"
        elif unique_paths >= 15 and req_count >= 15:
            # Probing many distinct paths rapidly
            anomaly_flag = "scanner_like"

        return RateLimitResult(
            anomaly_flag=anomaly_flag,
            should_block_429=should_block,
            current_rate=req_count,
            burst_threshold=burst_threshold,
            window_sec=window_sec,
        )

    def record_block(self, client_ip: str) -> None:
        """Invoked when a request from client_ip is blocked (e.g. 403 rule or ML hit)."""
        now = time.monotonic()
        if client_ip not in self._states:
            self._states[client_ip] = IPRateState()
        state = self._states[client_ip]
        state.block_timestamps.append(now)
        state.last_seen = now


# Global singleton instance for the gateway process
limiter = SlidingWindowRateLimiter()


def resolve_client_ip(peer_ip: str, x_forwarded_for: Optional[str] = None) -> str:
    """Convenience helper to safely resolve client IP using the global limiter's proxy trust rules."""
    return limiter.resolve_client_ip(peer_ip, x_forwarded_for)

