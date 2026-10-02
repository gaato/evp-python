# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows the compatibility policy described in the README.

## [Unreleased]

### Added

- Experimental issuer side, `pyevp.issuer`: validate the browser's signed issuance request
  (RFC 9421 HTTP Message Signatures with an `hwk` Signature-Key, `Content-Digest`), mint EVTs,
  and produce the metadata, JWKS and DNS records to publish. Issuance profiles `chrome-153`
  (default) and `draft-hardt-02`; `Signer` protocol for KMS / HSM keys; optional replay guard
  and observer. Private email is not supported yet. Tested end to end with Chrome 154.
- `pyevp.issuer.web_identity_document()` and `accounts_document()` for the FedCM account check
  that Chrome performs before issuing.
- `pyevp issuer keygen` and `pyevp issuer documents` CLI commands.
- `FakeBrowser.issuance_request()` for testing issuers.
- `examples/issuer_fastapi`.
- `examples/flask`, a Flask relying party using the synchronous `Verifier`.

### Changed

- The project is now named `pyevp` everywhere: `pip install pyevp`, `import pyevp`, the `pyevp`
  command and the `gaato/pyevp` repository. Nothing was published under the old name.
- `build_kb` / `FakeBrowser.present` accept an EVT that already ends in `~`, as issuers return
  it in `issuance_token`.

## [0.1.0]

### Added

- Relying-party verification of EVP presentation tokens (`EVT~KB-JWT`) with
  `Verifier` and `AsyncVerifier`, built on a sans-I/O core (`pyevp.core`).
- Issuer discovery via DNS (`_email-verification` TXT), metadata and JWKS, with caching and
  rate-limited key refresh. Internationalised email domains are mapped with IDNA2008 (UTS #46).
- Profiles `compat-2026-10` (default; accepts Gmail as deployed) and `draft-hardt-02` (strict).
- Stable `ErrorCode`s on every failure.
- dnspython and httpx / httpx2 adapters (`pyevp[dns]`, `pyevp[httpx]`, `pyevp[httpx2]`, `pyevp[all]`);
  httpx2 is preferred when installed.
- Opt-in replay protection (`replay_guard=`, `InMemoryReplayGuard`, `ErrorCode.TOKEN_REPLAYED`).
  Presentations are keyed by the KB-JWT signing input, so re-encoded signatures are still
  detected.
- Observer hook for logging and metrics (`observer=`, `VerificationEvent`, `LoggingObserver`).
- DNS-over-HTTPS TXT resolvers (`pyevp.adapters.doh`, Google and Cloudflare JSON APIs).
- `Verifier.default()` / `AsyncVerifier.default()` accept `resolver=` / `fetcher=` overrides.
- Issuer diagnostics (`pyevp.diagnostics`) and an `pyevp` command (`pyevp[cli]`) with `discover`,
  `inspect` and `verify`.
- Profile registry: `PROFILES` and `Profile.named()`.
- Test doubles in `pyevp.testing`: `FakeIssuer`, `FakeBrowser`, in-memory DNS / HTTP.

[Unreleased]: https://github.com/gaato/pyevp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gaato/pyevp/releases/tag/v0.1.0
