import time
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from src.api.server import app, rate_limiter
from src.api.rate_limiter import TokenBucketRateLimiter


class DummyRequest:
    def __init__(self, ip="127.0.0.1", headers=None):
        self.headers = headers or {}
        self.client = type("Client", (), {"host": ip})()


def test_token_bucket_initial_and_consumption():
    limiter = TokenBucketRateLimiter(rate=10.0, burst=5, enabled=True)
    req = DummyRequest()

    # Consuming 5 tokens should succeed
    for _ in range(5):
        limiter.check(req)

    # 6th immediate token consumption should raise HTTP 429
    with pytest.raises(HTTPException) as excinfo:
        limiter.check(req)

    assert excinfo.value.status_code == 429
    assert "Retry-After" in excinfo.value.headers
    assert int(excinfo.value.headers["Retry-After"]) >= 1


def test_token_bucket_replenishment():
    limiter = TokenBucketRateLimiter(rate=100.0, burst=2, enabled=True)
    req = DummyRequest()

    # Consume both tokens
    limiter.check(req)
    limiter.check(req)

    with pytest.raises(HTTPException):
        limiter.check(req)

    # Sleep 30ms -> at 100 tokens/sec, 30ms produces 3 tokens (capped at burst 2)
    time.sleep(0.035)

    # Now request should succeed again
    limiter.check(req)


def test_token_bucket_disabled():
    limiter = TokenBucketRateLimiter(rate=1.0, burst=1, enabled=False)
    req = DummyRequest()

    # Consuming 10 tokens in disabled mode should never raise
    for _ in range(10):
        limiter.check(req)


def test_token_bucket_stale_eviction():
    limiter = TokenBucketRateLimiter(
        rate=10.0,
        burst=5,
        enabled=True,
        cleanup_interval_sec=0.01,
        client_ttl_sec=0.02
    )
    req = DummyRequest(ip="10.0.0.1")
    limiter.check(req)
    assert len(limiter._buckets) == 1

    time.sleep(0.03)

    req2 = DummyRequest(ip="10.0.0.2")
    limiter.check(req2)
    # The first stale IP should have been evicted
    assert "ip:10.0.0.1" not in limiter._buckets
    assert "ip:10.0.0.2" in limiter._buckets


def test_api_rate_limiting_integration(monkeypatch):
    """Integration test: API endpoint throttles excessive requests with HTTP 429."""
    client = TestClient(app)

    # Configure a tiny burst of 2 requests and rate 1 rps
    rate_limiter.rate = 1.0
    rate_limiter.burst = 2
    rate_limiter.enabled = True
    rate_limiter.reset()

    try:
        # Request 1: OK
        res1 = client.post(
            "/api/v1/inspect",
            json={"prompt": "How do I create a virtual environment in Python?"}
        )
        assert res1.status_code == 200

        # Request 2: OK
        res2 = client.post(
            "/api/v1/inspect",
            json={"prompt": "How do I create a virtual environment in Python?"}
        )
        assert res2.status_code == 200

        # Request 3: Throttled (429)
        res3 = client.post(
            "/api/v1/inspect",
            json={"prompt": "How do I create a virtual environment in Python?"}
        )
        assert res3.status_code == 429
        assert "Retry-After" in res3.headers
        assert "Rate limit exceeded" in res3.json()["detail"]

    finally:
        # Reset limiter to production defaults so subsequent tests are unaffected
        rate_limiter.rate = 100.0
        rate_limiter.burst = 150
        rate_limiter.enabled = True
        rate_limiter.reset()


def test_api_rate_limiting_distinct_keys(monkeypatch):
    """Different API keys have separate rate limit quotas."""
    client = TestClient(app)
    monkeypatch.setenv("PID_API_KEYS", "user-key-a,user-key-b")

    rate_limiter.rate = 1.0
    rate_limiter.burst = 1
    rate_limiter.enabled = True
    rate_limiter.reset()

    try:
        # Key A consumes its 1 token
        res_a1 = client.post(
            "/api/v1/inspect",
            headers={"X-PID-API-Key": "user-key-a"},
            json={"prompt": "How do I create a virtual environment in Python?"}
        )
        assert res_a1.status_code == 200

        # Key A exceeds limit
        res_a2 = client.post(
            "/api/v1/inspect",
            headers={"X-PID-API-Key": "user-key-a"},
            json={"prompt": "How do I create a virtual environment in Python?"}
        )
        assert res_a2.status_code == 429

        # Key B still has full quota
        res_b1 = client.post(
            "/api/v1/inspect",
            headers={"X-PID-API-Key": "user-key-b"},
            json={"prompt": "How do I create a virtual environment in Python?"}
        )
        assert res_b1.status_code == 200

    finally:
        rate_limiter.rate = 100.0
        rate_limiter.burst = 150
        rate_limiter.enabled = True
        rate_limiter.reset()

