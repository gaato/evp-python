# DNS, HTTP and caching

Verification needs one DNS TXT lookup and two HTTPS GETs (metadata and keys). Both are pluggable
through {class}`~pyevp.TxtResolver` / {class}`~pyevp.JsonFetcher` and their async counterparts.
`Verifier.default()` picks the adapters below. Any constructor argument can be overridden:

```python
Verifier.default(audience=..., resolver=..., fetcher=..., cache=...)
```

## HTTP: httpx2 or httpx

{mod}`pyevp.adapters.httpx` works with [httpx2](https://github.com/pydantic/httpx2) (pydantic's
maintained fork) or httpx, and prefers httpx2 when both are installed. Install one of:

```sh
pip install "pyevp[dns,httpx2]"
pip install "pyevp[dns,httpx]"      # same as pyevp[all]
```

A client from either library can be passed explicitly, for example to share connection pools
or set proxies: `HttpxFetcher(httpx2.Client(...))`. Redirects are never followed, even when the
client was configured to follow them. Responses are requested uncompressed, compressed ones
are refused, and bodies are size-capped.

## DNS: system resolver

{mod}`pyevp.adapters.dnspython` uses the system resolver configuration. With
`require_dnssec=True`, answers must carry the AD flag. That flag is only meaningful when you
trust a validating resolver, such as one on localhost.

## DNS over HTTPS

Where plain DNS is unavailable or untrusted, as on serverless platforms or in locked-down
networks, {mod}`pyevp.adapters.doh` resolves TXT records through a DoH JSON API using only the HTTP
client:

```python
from pyevp.adapters.doh import CLOUDFLARE, AsyncDohResolver

verifier = AsyncVerifier.default(audience=..., resolver=AsyncDohResolver())  # Google
verifier = AsyncVerifier.default(audience=..., resolver=AsyncDohResolver(CLOUDFLARE))
```

`require_dnssec=True` trusts the provider's AD flag. Unsigned zones such as gmail.com never pass
it. With `dnspython[doh]` installed, an RFC 8484 resolver can be used instead:

```python
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["https://cloudflare-dns.com/dns-query"]
DnsPythonResolver(resolver)
```

## Caching

Issuer metadata and key sets are cached for 10 minutes (`cache_ttl`) in a process-local
{class}`~pyevp.InMemoryCache`. Pass any {class}`~pyevp.Cache` implementation to share it between
workers; the Django example has one backed by Django's cache. When a signature does not verify,
the keys are fetched again to pick up key rotation, at most once per `min_refresh_interval`
and URL, even when the fetch fails or verifications run concurrently.
