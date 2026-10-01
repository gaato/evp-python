# Replay protection

The nonce on the form is the first line of defence: store it server-side and consume it once.
Some setups cannot do that:

- **Client-side sessions** such as Starlette's signed-cookie `SessionMiddleware`. An attacker who
  captured a token can resend it with the old cookie, which still contains the nonce.
- **Concurrent requests** racing on the same session.

A replay guard remembers every accepted token until it would expire anyway, and rejects a
second use with `ErrorCode.TOKEN_REPLAYED`. Replay protection is off by default; enable it by
passing a guard:

```python
from evp import AsyncVerifier, InMemoryReplayGuard

verifier = AsyncVerifier.default(audience="https://example.com", replay_guard=InMemoryReplayGuard())
```

The guard is only consulted after every other check has passed, so rejected tokens never fill
the store. Errors raised by the guard itself, such as a store outage, propagate unchanged.

## Shared stores

{class}`~evp.InMemoryReplayGuard` only protects a single process. With several workers,
implement {class}`~evp.ReplayGuard` or {class}`~evp.AsyncReplayGuard` as an atomic "add if
absent":

```python
class RedisReplayGuard:
    def __init__(self, redis):
        self.redis = redis

    def mark_used(self, key, expires_at):
        return bool(
            self.redis.set(f"evp:used:{key}", 1, nx=True, pxat=int(expires_at.timestamp() * 1000))
        )
```

With Django, `cache.add()` is atomic on the Redis and Memcached backends. See
`DjangoCacheReplayGuard` in {doc}`frameworks`.
