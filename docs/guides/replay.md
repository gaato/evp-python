# Replay protection

The nonce on the form is the first line of defence: store it server-side and consume it once.
Some setups cannot do that:

- **Client-side sessions** such as Starlette's signed-cookie `SessionMiddleware`. An attacker who
  captured a token can resend it with the old cookie, which still contains the nonce.
- **Nonces kept in a cookie** by APIs without a server session (see {doc}`spa`).
- **Concurrent requests** racing on the same session.

A replay guard remembers every accepted token until it would expire anyway, and rejects a
second use with `ErrorCode.TOKEN_REPLAYED`. Replay protection is off by default; enable it by
passing a guard:

```python
from pyevp import AsyncVerifier, InMemoryReplayGuard

verifier = AsyncVerifier.default(audience="https://example.com", replay_guard=InMemoryReplayGuard())
```

The key identifies the presentation, not its bytes: it is a hash of the KB-JWT header and
payload, which carry the nonce, audience and a hash of the EVT. Re-encoding a signature, for
example turning an ECDSA `s` into `n - s`, therefore does not produce a new key.

The guard is only consulted after every other check has passed, so rejected tokens never fill
the store. Errors raised by the guard itself, such as a store outage, propagate unchanged.
Freshness is checked before any I/O, so a token that expires while DNS and HTTP are in flight
is rejected with `ErrorCode.TOKEN_EXPIRED` after it has been marked: its record may already be
gone, and a replay would not find it.

## Shared stores

{class}`~pyevp.InMemoryReplayGuard` only protects a single process. With several workers,
implement {class}`~pyevp.ReplayGuard` or {class}`~pyevp.AsyncReplayGuard` as an atomic "add if
absent":

```python
import math


class RedisReplayGuard:
    def __init__(self, redis):
        self.redis = redis

    def mark_used(self, key, expires_at):
        # Round up: the key must not disappear before the token expires.
        pxat = math.ceil(expires_at.timestamp() * 1000)
        return bool(self.redis.set(f"evp:used:{key}", 1, nx=True, pxat=pxat))
```

The store must keep each record until it expires. Do not build a guard on a cache that evicts
under memory pressure: once the record is evicted, the token is accepted again. For Redis this
means `maxmemory-policy noeviction` (the `volatile-*` policies evict exactly these keys, which
have a TTL), so that a full Redis rejects the write and verification fails instead. With Django, use {class}`~pyevp.contrib.django.EVPReplayGuard`,
which keeps records in a database table; see {doc}`frameworks`.
