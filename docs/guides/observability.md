# Logging and metrics

Pass `observer=` to a verifier to receive one {class}`~evp.VerificationEvent` per `verify()` call.
An event carries:

- `ok`
- `code`: the {class}`~evp.ErrorCode` on failure
- `issuer`: on success
- `email_domain`: the claimed domain, read before verification
- `profile`
- `duration`

```python
from evp import LoggingObserver, Verifier

verifier = Verifier.default(audience="https://example.com", observer=LoggingObserver())
```

{class}`~evp.LoggingObserver` writes one line per verification to the `evp` logger. For metrics,
write a small callable:

```python
from prometheus_client import Counter, Histogram

VERIFICATIONS = Counter("evp_verifications_total", "EVP verifications", ["result", "issuer"])
LATENCY = Histogram("evp_verification_seconds", "EVP verification latency")


def observe(event):
    VERIFICATIONS.labels(event.code or "ok", event.issuer or "").inc()
    LATENCY.observe(event.duration.total_seconds())
```

Observers should be fast. Exceptions raised by an observer are logged to the `evp` logger and
ignored, so monitoring can never break sign-in.

Watching these numbers per `email_domain` and `code` shows quickly when an issuer changes its
behaviour (a spike of `unsupported_alg`, for example). That is the same drift that
`evp discover` checks for (see {doc}`cli`).
