import os
import time
import math
import threading
from typing import Dict, Tuple, Optional
from fastapi import Request, HTTPException


class TokenBucketRateLimiter:
    """
    Thread-safe Token Bucket Rate Limiter with burst capacity and sliding replenishment.
    Keys on authenticated API Key (if present) or client remote IP.
    """

    def __init__(
        self,
        rate: Optional[float] = None,          # Replenishment rate (tokens per second)
        burst: Optional[int] = None,           # Maximum burst capacity (tokens)
        enabled: Optional[bool] = None,        # Global rate limiting toggle
        cleanup_interval_sec: float = 300.0,   # Interval between stale bucket sweeps
        client_ttl_sec: float = 3600.0         # Evict client if idle longer than this
    ):
        self._lock = threading.Lock()
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_update_ts)
        self._last_cleanup = time.time()
        self.cleanup_interval_sec = cleanup_interval_sec
        self.client_ttl_sec = client_ttl_sec

        # Rate configuration (RPS)
        if rate is not None:
            self.rate = float(rate)
        else:
            self.rate = float(os.getenv("RATE_LIMIT_RPS", "100.0"))

        # Burst configuration
        if burst is not None:
            self.burst = int(burst)
        else:
            self.burst = int(os.getenv("RATE_LIMIT_BURST", "150"))

        # Enabled toggle
        if enabled is not None:
            self.enabled = bool(enabled)
        else:
            env_val = os.getenv("RATE_LIMIT_ENABLED", "true").strip().lower()
            self.enabled = env_val in ("true", "1", "yes")

    def _get_client_key(self, request: Request, api_key: Optional[str] = None) -> str:
        """Extract a unique client identifier for rate tracking."""
        if api_key:
            return f"key:{api_key}"
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
            return f"ip:{client_ip}"
        if request.client and request.client.host:
            return f"ip:{request.client.host}"
        return "ip:unknown"

    def check(self, request: Request, api_key: Optional[str] = None, cost: float = 1.0) -> None:
        """
        Check rate limit against client bucket and deduct cost.
        Raises HTTPException(status_code=429) with Retry-After header if exceeded.
        """
        if not self.enabled or self.rate <= 0:
            return

        client_key = self._get_client_key(request, api_key)
        now = time.time()

        with self._lock:
            # Stale bucket garbage collection
            if now - self._last_cleanup > self.cleanup_interval_sec:
                self._prune_stale_buckets(now)

            if client_key in self._buckets:
                tokens, last_ts = self._buckets[client_key]
                elapsed = max(0.0, now - last_ts)
                tokens = min(float(self.burst), tokens + (elapsed * self.rate))
            else:
                tokens = float(self.burst)

            if tokens < cost:
                missing = cost - tokens
                retry_after = max(1, math.ceil(missing / self.rate))
                self._buckets[client_key] = (tokens, now)
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Try again in {retry_after} second(s).",
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(int(self.rate)),
                        "X-RateLimit-Remaining": "0"
                    }
                )

            # Consume tokens
            tokens -= cost
            self._buckets[client_key] = (tokens, now)

    def _prune_stale_buckets(self, now: float) -> None:
        """Evict stale buckets to keep memory usage bounded."""
        stale_keys = [
            k for k, (_, last_ts) in self._buckets.items()
            if (now - last_ts) > self.client_ttl_sec
        ]
        for k in stale_keys:
            del self._buckets[k]
        self._last_cleanup = now

    def reset(self) -> None:
        """Reset internal buckets (useful in test teardown)."""
        with self._lock:
            self._buckets.clear()
            self._last_cleanup = time.time()

