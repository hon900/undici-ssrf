# Changelog

## 0.9.0 — 2026-10-04

- Adopt hostfence 1.3.0 destination-policy hardening and standalone CI.

### Added

- `createSsrfInterceptor(policy)` for isolated, configurable origin policies.
- Coverage for legacy and modern handler errors, blocked and allowed requests,
  origin mutation, DNS failure, and an Undici MockAgent integration.

### Fixed

- Return a synchronous boolean from the interceptor instead of an async Promise.
- Deliver failed policy checks and downstream throws through the error handler.
- Snapshot the routing origin before DNS work so caller mutation cannot replace
  a checked target with another destination.
- Copy supported header/query metadata before DNS and dispatch the validated
  canonical origin while preserving request-body identity.

### Documentation

- Specify asynchronous acceptance, backpressure and lifecycle limitations, and
  the preflight DNS and redirect-composition security boundary.
