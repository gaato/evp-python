"""Issuer diagnostics: what a relying party sees when it discovers a domain's issuer.

Used by ``evp discover``, by the weekly drift check, and by issuer operators who
want to check their DNS record, metadata and keys against a profile.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field, replace
from typing import Any, TypeAlias

from evp import _jose, discovery
from evp.core import Effect, FetchJson, ResolveTxt
from evp.errors import DiscoveryError, EVPError
from evp.ports import AsyncJsonFetcher, AsyncTxtResolver, JsonFetcher, TxtResolver
from evp.profile import DEFAULT_PROFILE, Profile
from evp.types import IssuerMetadata, JSONObject
from evp.verifier import _unreachable

__all__ = ["IssuerReport", "KeySummary", "adiscover", "discover", "discovery_steps"]


@dataclass(frozen=True, slots=True)
class KeySummary:
    kty: str | None
    crv: str | None
    alg: str | None
    kid: str | None
    use: str | None

    @classmethod
    def of(cls, jwk: JSONObject) -> KeySummary:
        def text(name: str) -> str | None:
            value = jwk.get(name)
            return value if isinstance(value, str) else None

        return cls(text("kty"), text("crv"), text("alg"), text("kid"), text("use"))


@dataclass(frozen=True, slots=True)
class IssuerReport:
    domain: str
    profile: str
    dns_name: str
    records: tuple[str, ...] = ()
    issuer: str | None = None
    metadata: IssuerMetadata | None = None
    keys: tuple[KeySummary, ...] = ()
    problems: tuple[str, ...] = field(default=())

    @property
    def ok(self) -> bool:
        return not self.problems


# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
ReportSteps: TypeAlias = Generator[Effect, Any, IssuerReport]


def _normalize_domain(target: str) -> str:
    if "@" in target:
        return discovery.email_domain(target)
    return discovery.email_domain(f"user@{target}")


def discovery_steps(target: str, profile: Profile = DEFAULT_PROFILE) -> ReportSteps:
    """Sans-I/O issuer check for an email address or domain.

    Content problems are collected in :attr:`IssuerReport.problems`; transport
    failures surface as :class:`~evp.DiscoveryError` from the driver.
    """
    domain = _normalize_domain(target)
    dns_name = f"{profile.dns_label}.{domain}"
    report = IssuerReport(domain=domain, profile=profile.name, dns_name=dns_name)

    def done(problem: str, **changes: Any) -> IssuerReport:
        return replace(report, problems=(problem,), **changes)

    records = tuple((yield ResolveTxt(dns_name)))
    try:
        issuer = discovery.parse_txt_records(records)
    except DiscoveryError as exc:
        return done(exc.args[0], records=records)
    report = replace(report, records=records, issuer=issuer)

    try:
        metadata = discovery.validate_metadata(
            (yield FetchJson(discovery.metadata_url(issuer, profile), "metadata")), issuer
        )
    except DiscoveryError as exc:
        return done(f"metadata: {exc.args[0]}")
    report = replace(report, metadata=metadata)

    try:
        jwks = discovery.validate_jwks((yield FetchJson(metadata.jwks_uri, "jwks")))
    except DiscoveryError as exc:
        return done(f"JWKS: {exc.args[0]}")

    problems: list[str] = []
    advertised = metadata.signing_alg_values_supported
    if advertised is None:
        # Like the verifier: an absent list does not restrict the profile's algorithms.
        advertised = tuple(sorted(profile.evt_algorithms))
    accepted = [a for a in advertised if a in profile.evt_algorithms]
    if not advertised:
        # Unlike an absent list, an empty one makes every token fail verification.
        problems.append("issuer advertises an empty signing_alg_values_supported")
    elif not accepted:
        problems.append(
            f"issuer signs with {', '.join(advertised)}; profile {profile.name} accepts "
            f"{', '.join(sorted(profile.evt_algorithms))}"
        )
    usable = [k for k in jwks if any(_jose.key_supports(a, k) for a in accepted)]
    if accepted and not usable:
        problems.append(f"no key in {metadata.jwks_uri} can verify {', '.join(accepted)}")
    if profile.require_kid and any(not k.get("kid") for k in usable):
        problems.append(f"profile {profile.name} requires kid, but some keys have none")

    return replace(report, keys=tuple(KeySummary.of(k) for k in jwks), problems=tuple(problems))


def discover(
    target: str,
    *,
    resolver: TxtResolver,
    fetcher: JsonFetcher,
    profile: Profile = DEFAULT_PROFILE,
) -> IssuerReport:
    """Run :func:`discovery_steps` with synchronous ports (no caching)."""
    steps = discovery_steps(target, profile)
    try:
        effect = next(steps)
        while True:
            if not isinstance(effect, ResolveTxt | FetchJson):
                raise TypeError(f"unexpected effect {effect!r}")
            try:
                if isinstance(effect, ResolveTxt):
                    result: object = resolver.resolve_txt(effect.name)
                else:
                    result = fetcher.fetch_json(effect.url)
            except EVPError:
                raise
            except Exception as exc:
                raise _unreachable(effect, exc) from exc
            effect = steps.send(result)
    except StopIteration as stop:
        return stop.value
    finally:
        steps.close()


async def adiscover(
    target: str,
    *,
    resolver: AsyncTxtResolver,
    fetcher: AsyncJsonFetcher,
    profile: Profile = DEFAULT_PROFILE,
) -> IssuerReport:
    """Async counterpart of :func:`discover`."""
    steps = discovery_steps(target, profile)
    try:
        effect = next(steps)
        while True:
            if not isinstance(effect, ResolveTxt | FetchJson):
                raise TypeError(f"unexpected effect {effect!r}")
            try:
                if isinstance(effect, ResolveTxt):
                    result: object = await resolver.resolve_txt(effect.name)
                else:
                    result = await fetcher.fetch_json(effect.url)
            except EVPError:
                raise
            except Exception as exc:
                raise _unreachable(effect, exc) from exc
            effect = steps.send(result)
    except StopIteration as stop:
        return stop.value
    finally:
        steps.close()
