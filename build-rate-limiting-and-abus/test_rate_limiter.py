===
Tests for sliding-window rate limiter, tier configs, abuse protection, and backends.
"""

import time
import threading
from unittest.mock import MagicMock, patch
from rate_limiter import (
    RateLimiter, InMemoryBackend, Tier, TierConfig,
    RateLimitResult, DEFAULT_TIERS, RedisBackend,
)


def test_tier_configs_exist():
    assert Tier.FREE in DEFAULT_TIERS
    assert Tier.INTERNAL in DEFAULT_TIERS
    assert DEFAULT_TIERS[Tier.PREMIUM].limit > DEFAULT_TIERS[Tier.STANDARD].limit


def test_basic_allow():
    rl = RateLimiter()
    result = rl.check("user1", Tier.FREE)
    assert result.allowed is True
    assert result.remaining >= 0
    assert "X-RateLimit-Limit" in result.headers()


def test_sliding_window_rejects():
    cfg = TierConfig(limit=3, window_seconds=60, burst_allowance=0)
    rl = RateLimiter(tiers={Tier.FREE: cfg})
    for i in range(3):
        r = rl.check("u", Tier.FREE)
        assert r.allowed is True
    r = rl.check("u", Tier.FREE)
    assert r.allowed is False
    assert r.retry_after is not None
    assert r.remaining == 0


def test_burst_allowance():
    cfg = TierConfig(limit=3, window_seconds=60, burst_allowance=2)
    rl = RateLimiter(tiers={Tier.FREE: cfg})
    for i in range(5):
        r = rl.check("u", Tier.FREE)
        assert r.allowed is True
    r = rl.check("u", Tier.FREE)
    assert r.allowed is False


def test_per_key_isolation():
    cfg = TierConfig(limit=2, window_seconds=60, burst_allowance=0)
    rl = RateLimiter(tiers={Tier.FREE: cfg})
    assert rl.check("a", Tier.FREE).allowed
    assert rl.check("b", Tier.FREE).allowed
    assert rl.check("a", Tier.FREE).allowed
    assert rl.check("a", Tier.FREE).allowed is False
    assert rl.check("b", Tier.FREE).allowed


def test_custom_limit_per_key():
    rl = RateLimiter()
    rl.set_custom_limit("vip", TierConfig(limit=10000, window_seconds=60))
    r = rl.check("vip", Tier.FREE)
    assert r.allowed
    assert r.limit == 10000


def test_block_key():
    rl = RateLimiter()
    rl.block_key("bad", 300)
    assert rl.is_blocked("bad")
    r = rl.check("bad", Tier.FREE)
    assert r.allowed is False
    assert r.retry_after is not None


def test_block_expiry():
    rl = RateLimiter()
    rl.block_key("tmp", 1)
    assert rl.is_blocked("tmp")
    time.sleep(1.1)
    assert rl.is_blocked("tmp") is False


def test_abuse_detection_blocks():
    cfg = TierConfig(limit=1, window_seconds=60, burst_allowance=0)
    abuse_cb = MagicMock()
    rl = RateLimiter(
        tiers={Tier.FREE: cfg},
        abuse_threshold=3,
        abuse_window=60,
        on_abuse=abuse_cb,
    )
    for _ in range(4):
        rl.check("abuser", Tier.FREE)
    assert rl.is_blocked("abuser")
    abuse_cb.assert_called_once()
    call_key, call_info = abuse_cb.call_args[0]
    assert call_key == "abuser"
    assert "blocked_until" in call_info


def test_gateway_middleware_hook():
    rl = RateLimiter()
    allowed, result = rl.gateway_middleware_hook("req1", Tier.STANDARD)
    assert allowed is True
    assert isinstance(result, RateLimitResult)


def test_health():
    rl = RateLimiter()
    h = rl.health()
    assert "blocked_keys" in h
    assert h["backend"] == "InMemoryBackend"


def test_result_headers():
    r = RateLimitResult(allowed=True, limit=100, remaining=99, reset_at=1234.5)
    h = r.headers()
    assert h["X-RateLimit-Limit"] == "100"
    assert "Retry-After" not in h
    r2 = RateLimitResult(allowed=False, limit=100, remaining=0, reset_at=1234.5, retry_after=30)
    h2 = r2.headers()
    assert h2["Retry-After"] == "30"


def test_in_memory_backend_clear():
    b = InMemoryBackend()
    b.add_and_count("k", 60, time.time())
    b.clear()
    assert b.add_and_count("k", 60, time.time()) == 1


def test_redis_backend_structure():
    mock_redis = MagicMock()
    pipe = MagicMock()
    pipe.execute.return_value = [0, None, 5, True]
    mock_redis.pipeline.return_value = pipe
    rb = RedisBackend(mock_redis, prefix="test:")
    count = rb.add_and_count("user1", 60, time.time())
    assert count == 5
    mock_redis.pipeline.assert_called_once()


def test_concurrent_access():
    cfg = TierConfig(limit=500, window_seconds=60, burst_allowance=0)
    rl = RateLimiter(tiers={Tier.FREE: cfg})
    results = []

    def worker():
        r = rl.check("concurrent", Tier.FREE)
        results.append(r.allowed)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 50
    assert all(results)


if __name__ == "__main__":
    test_tier_configs_exist()
    test_basic_allow()
    test_sliding_window_rejects()
    test_burst_allowance()
    test_per_key_isolation()
    test_custom_limit_per_key()
    test_block_key()
    test_block_expiry()
    test_abuse_detection_blocks()
    test_gateway_middleware_hook()
    test_health()
    test_result_headers()
    test_in_memory_backend_clear()
    test_redis_backend_structure()
    test_concurrent_access()
    print("All tests passed!")