# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows the compatibility policy described in the README.

## [Unreleased]

## [0.1.0]

### Added

- Relying-party verification of EVP presentation tokens (`EVT~KB-JWT`) with
  `Verifier` and `AsyncVerifier`, built on a sans-I/O core (`evp.core`).
- Issuer discovery via DNS (`_email-verification` TXT), metadata and JWKS, with caching and
  rate-limited key refresh.
- Profiles `compat-2026-10` (default; accepts Gmail as deployed) and `draft-hardt-02` (strict).
- Stable `ErrorCode`s on every failure.
- dnspython and httpx / httpx2 adapters (`evp[dns]`, `evp[httpx]`, `evp[httpx2]`, `evp[all]`);
  httpx2 is preferred when installed.
- Opt-in replay protection (`replay_guard=`, `InMemoryReplayGuard`, `ErrorCode.TOKEN_REPLAYED`).
- Observer hook for logging and metrics (`observer=`, `VerificationEvent`, `LoggingObserver`).
- Test doubles in `evp.testing`: `FakeIssuer`, `FakeBrowser`, in-memory DNS / HTTP.

[Unreleased]: https://github.com/gaato/evp-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gaato/evp-python/releases/tag/v0.1.0
