===
Sliding-window rate limiter with configurable tiers, per-key limits,
in-memory and Redis-backed storage, and gateway integration hooks.
"""

import time
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass, field
from enum import Enum
import threading
import hashlib


class Tier(Enum):
    FREE = "free"
    STANDARD = "standard"
    PREMIUM = "premium"
    INTERNAL = "internal"


@dataclass
class TierConfig:
    limit: int
    window_seconds: int
    burst_allowance: int = 0


DEFAULT_TIERS: Dict[Tier, TierConfig] = {
    Tier.FREE: TierConfig(limit=60, window_seconds=60, burst_allowance=10),
    Tier.STANDARD: TierConfig(limit=300, window_seconds=60, burst_allowance=30),
    Tier.PREMIUM: TierConfig(limit=1000, window_seconds=60, burst_allowance=50),
    Tier.INTERNAL: TierConfig(limit=5000, window_seconds=60, burst_allowance=100),
}


@dataclass
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_at: float
    retry_after: Optional[int] = None

    def headers(self) -> Dict[str, str]:
        h = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(int(self.reset_at)),
        }
        if not self.allowed and self.retry_after:
            h["Retry-After"] = str(self.retry_after)
        return h


class StorageBackend:
    """Abstract base for storage backends."""

    def add_and_count(self, key: str, window: int, now: float) -> int:
        raise NotImplementedError

    def get_reset_time(self, key: str, window: int, now: float) -> float:
        raise NotImplementedError


class InMemoryBackend(StorageBackend):
    def __init__(self):
        self._data: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def add_and_count(self, key: str, window: int, now: float) -> int:
        cutoff = now - window
        with self._lock:
            entries = self._data.get(key, [])
            entries = [t for t in entries if t > cutoff]
            entries.append(now)
            self._data[key] = entries
            return len(entries)

    def get_reset_time(self, key: str, window: int, now: float) -> float:
        cutoff = now - window
        with self._lock:
            entries = self._data.get(key, [])
            entries = [t for t in entries if t > cutoff]
            self._data[key] = entries
            if not entries:
                return now + window
            return entries[0] + window

    def clear(self):
        with self._lock:
            self._data.clear()


class RedisBackend(StorageBackend):
    """Redis-backed storage using sorted sets for sliding window."""

    def __init__(self, redis_client, prefix: str = "rl:"):
        self._redis = redis_client
        self._prefix = prefix

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def add_and_count(self, key: str, window: int, now: float) -> int:
        rkey = self._key(key)
        pipe = self._redis.pipeline()
        cutoff = now - window
        pipe.zremrangebyscore(rkey, "-inf", cutoff)
        pipe.zadd(rkey, {str(now): now})
        pipe.zcard(rkey)
        pipe.expire(rkey, window + 1)
        results = pipe.execute()
        return results[2]

    def get_reset_time(self, key: str, window: int, now: float) -> float:
        rkey = self._key(key)
        cutoff = now - window
        self._redis.zremrangebyscore(rkey, "-inf", cutoff)
        earliest = self._redis.zrange(rkey, 0, 0, withscores=True)
        if not earliest:
            return now + window
        return earliest[0][1] + window


class RateLimiter:
    """Sliding-window rate limiter with tier-based configuration."""

    def __init__(
        self,
        backend: Optional[StorageBackend] = None,
        tiers: Optional[Dict[Tier, TierConfig]] = None,
        key_prefix: str = "",
        abuse_threshold: int = 5,
        abuse_window: int = 300,
        on_abuse: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.backend = backend or InMemoryBackend()
        self.tiers = tiers or DEFAULT_TIERS
        self.key_prefix = key_prefix
        self.abuse_threshold = abuse_threshold
        self.abuse_window = abuse_window
        self.on_abuse = on_abuse
        self._blocked: Dict[str, float] = {}
        self._block_lock = threading.Lock()
        self._violation_counts: Dict[str, int] = {}
        self._custom_limits: Dict[str, TierConfig] = {}

    def _make_key(self, key: str, tier: Tier) -> str:
        raw = f"{self.key_prefix}{tier.value}:{key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def set_custom_limit(self, key: str, config: TierConfig):
        self._custom_limits[key] = config

    def block_key(self, key: str, duration: int):
        with self._block_lock:
            self._blocked[key] = time.time() + duration

    def is_blocked(self, key: str) -> bool:
        with self._block_lock:
            exp = self._blocked.get(key)
            if exp is None:
                return False
            if time.time() > exp:
                del self._blocked[key]
                return False
            return True

    def check(self, key: str, tier: Tier = Tier.FREE) -> RateLimitResult:
        if self.is_blocked(key):
            cfg = self._custom_limits.get(key, self.tiers[tier])
            return RateLimitResult(
                allowed=False,
                limit=cfg.limit,
                remaining=0,
                reset_at=time.time() + self.abuse_window,
                retry_after=self.abuse_window,
            )

        cfg = self._custom_limits.get(key, self.tiers[tier])
        effective_limit = cfg.limit + cfg.burst_allowance
        now = time.time()
        store_key = self._make_key(key, tier)
        count = self.backend.add_and_count(store_key, cfg.window_seconds, now)
        reset_at = self.backend.get_reset_time(store_key, cfg.window_seconds, now)
        remaining = max(0, effective_limit - count)
        allowed = count <= effective_limit

        result = RateLimitResult(
            allowed=allowed,
            limit=effective_limit,
            remaining=remaining,
            reset_at=reset_at,
        )

        if not allowed:
            result.retry_after = max(1, int(reset_at - now))
            self._record_violation(key)

        return result

    def _record_violation(self, key: str):
        cnt = self._violation_counts.get(key, 0) + 1
        self._violation_counts[key] = cnt
        if cnt >= self.abuse_threshold:
            self.block_key(key, self.abuse_window)
            self._violation_counts[key] = 0
            if self.on_abuse:
                self.on_abuse(key, {
                    "violations": cnt,
                    "blocked_until": time.time() + self.abuse_window,
                })

    def gateway_middleware_hook(self, request_key: str, tier: Tier = Tier.FREE):
        """Hook for gateway integration. Returns (allowed, result)."""
        result = self.check(request_key, tier)
        return result.allowed, result

    def health(self) -> Dict[str, Any]:
        with self._block_lock:
            blocked_count = len(self._blocked)
        return {
            "blocked_keys": blocked_count,
            "backend": type(self.backend).__name__,
            "tiers_configured": list(self.tiers.keys()),
        }