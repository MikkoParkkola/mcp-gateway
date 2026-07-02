# ADR-007: End-user identity propagation to backend MCP servers

- **Status**: Accepted (revised after adversarial architecture review)
- **Date**: 2026-07-02
- **Ticket**: MIK-6704 (release gate for the Trust Fabric major version bump)
- **Deciders**: operator + gateway maintainers
- **Composes with**: MIK-6648 (OIDC verify), MIK-6688 (identity → control-plane role), ADR-001 (message signing / `GatewayKeyPair`), MIK-6700 (signed transparency log)

## Context

mcp-gateway authenticates the end user (OIDC) and authorizes them **at the
gateway** — capability grants (`grant_subject_from_verified_identity`) and
control-plane RBAC (MIK-6688). But it does **not** propagate that identity to
connected backend MCP servers. Outbound calls
(`src/transport/http/mod.rs::build_mcp_headers`) carry only protocol headers
plus a **static, per-backend credential** that is identical for every caller. A
multitenant backend (email, memory, calendar) that itself requires OIDC/OAuth
therefore sees only "the gateway"; it cannot tell which user is calling, so it
cannot enforce per-user access nor produce a per-user audit trail.

The operator requirement (2026-07-02): propagate identity to connected services
that require OIDC/OAuth so the backend acts as the **real user**, not a shared
service account.

Three strategies were considered:

1. **OAuth 2.0 Token Exchange (RFC 8693)** — gateway swaps the user's token for
   a backend-audience token per (user, backend). Cleanest for OAuth-native
   backends; requires the IdP to support token-exchange.
2. **Per-user credential vault** — gateway stores each user's backend refresh
   token / delegated grant and mints access tokens on their behalf. Most
   flexible, heaviest (secure storage + refresh lifecycle).
3. **Signed identity assertion** — gateway mints a short-lived signed JWT
   (`sub`/`email`/`tenant`/`aud`) with `GatewayKeyPair`; backends that trust the
   gateway verify it. No external IdP dependency; reuses ADR-001 signing.

## Decision

**Framework-first, strategy-deferred.** Ship a strategy-agnostic identity-
propagation framework whose *safety invariants* are the release gate, with a
**signed-assertion reference strategy** to prove the framework end-to-end. The
token-exchange and credential-vault strategies become fast-follow / demand-gated
children behind the same trait.

Rationale: the three strategies need different things from the backends, and the
operator's own backends' auth models are not all fixed yet. Gating the version
bump on the *invariants* (fail-closed, tenant-isolation, session isolation,
cache-awareness, audit) rather than one auth model means the release ships a
correct, safe foundation that any strategy plugs into, and a wrong per-backend
strategy choice later cannot regress the safety contract.

> This ADR was revised after an adversarial architecture review (2026-07-02).
> The review verdict was REVISE, not reject: framework-first is sound, but the
> first draft treated request-scoped identity as a header-building detail on a
> shared backend transport. The revisions below (R1–R5) fix that.

### Architecture

- **`IdentityPropagation` trait** (R1) — new, `src/identity_propagation/`,
  **async** and metadata-rich. Given a `VerifiedIdentity` + a backend descriptor
  (id + audience), it returns a `PropagatedCredential` on success and a typed
  `PropagationError` otherwise. `PropagatedCredential` carries the outbound
  header set **and** the metadata every real strategy needs, so the first OAuth
  strategy does not force trait churn:
  `{ headers, expires_at, subject_key, audience, scopes, cache_binding }`.
  `cache_binding` is the value identity-aware caches key on (see R5). The
  `PropagationError` taxonomy separates *refuse* (fail-closed) from
  *misconfigured*, so callers never silently downgrade. Async because
  token-exchange (IdP round-trip) and vault (storage + refresh) are inherently
  async; the signed-assertion reference impl is sync-inside-async.
- **Full identity through dispatch** (R2) — today the router collapses
  `VerifiedIdentity` to a `GrantSubject` in `MetaMcpCallerContext`
  (`handlers.rs`); the transport has no request context. The framework carries a
  request-scoped identity handle (the full `VerifiedIdentity`) from the router
  through `meta_mcp` dispatch to the backend-invoke boundary, so the strategy
  runs with the real identity, not a lossy projection.
- **Per-backend opt-in config** — a backend gains an optional
  `identity_propagation` section (strategy + audience + required flag). Absent →
  today's static-credential behavior is unchanged (IDP.5).
- **Enforcement point** — outbound header construction (`build_mcp_headers`, the
  single source of truth) consults the configured strategy when the request
  carries a `VerifiedIdentity` and the backend requires propagation.
- **Session isolation** (R3, the critical fix) — `HttpTransport` today owns ONE
  MCP `session_id` per backend, reused across all callers. Correct per-user
  headers do **not** prevent a leak if the backend binds state to that shared
  MCP session (user B could inherit user A's backend-side session). Therefore an
  identity-propagating backend MUST satisfy one of: (a) per-user transport/
  session instances keyed by `(backend_id, stable_actor_id, audience)`;
  (b) an explicit `stateless` (no session affinity) contract in config. An
  identity-required backend that is neither per-user-scoped nor declared
  stateless is a **fail-closed misconfiguration** — the gateway refuses rather
  than reuse a shared session (IDP.7).
- **Cache identity-awareness** (R5) — response cache / idempotency keys are
  identity-blind today. For an identity-propagating backend, cache keys MUST
  include `cache_binding` (per-user credential subject/audience); failing that,
  the cache MUST be bypassed, so user A's cached backend result is never served
  to user B (IDP.8).
- **Fail-closed** (IDP.2) — a backend that *requires* propagation with no
  per-user credential obtainable → call **refused**, never a static-credential
  downgrade.
- **Tenant-isolation** (IDP.3) — a credential for (user U, backend B, audience
  A) is scoped to exactly that tuple; never cross-presented. No credential cache
  keyed only by backend.
- **Audit** (IDP.4) — each propagation event → transparency log (user, backend,
  audience), **never the token**. Audit-write failure is itself fail-closed for
  a required backend (a propagation we cannot record is a propagation we do not
  make). Reuses the MIK-6700 signed transparency log.
- **Credential hygiene** (IDP.6) — minted/exchanged credentials carry short TTL
  with `exp`/`nbf`/`jti`; the reference signed-assertion strategy sets an
  explicit audience and short lifetime to bound replay; key rotation follows the
  `GatewayKeyPair` model (ADR-001). Third-party strategies validate issuer +
  audience to prevent confusion.

### Invariant ordering (fail-fast)

IDP.2 (fail-closed), IDP.3 (tenant-isolation), and IDP.7 (session isolation) are
implemented and tested first: a propagation feature that leaks a token, leaks a
backend session across tenants, or silently uses a shared account is worse than
none.

### Honesty about the reference strategy (R4)

The signed-assertion reference strategy serves **first-party / gateway-trusting
backends** (e.g. an operator-owned memory service that trusts the gateway key).
It is NOT a substitute for OAuth-native third-party backends (Gmail, Microsoft
Graph); those are unblocked by the token-exchange child (MIK-6729). The release
therefore ships *real per-user propagation for first-party backends* plus the
framework + invariants for all. The operator's email use-case specifically lands
with MIK-6729 (fast-follow). Stated plainly, so "identity propagation in the
release" is not over-claimed.

## Consequences

- **Positive** — unblocks first-party multitenant backends immediately with real
  per-user access + per-user audit; the safety invariants are proven once at the
  trait boundary for every future strategy. The async, metadata-rich trait
  absorbs token-exchange and vault without churn.
- **Negative** — OAuth-native third-party backends (email/calendar) wait for the
  token-exchange child. Per-user session scoping adds transport lifecycle
  complexity for identity-required backends (mitigated by the stateless-contract
  opt-out).
- **Rejected** — a sync headers-only trait (would not survive real OAuth); a
  shared per-backend credential fallback (violates IDP.2); reusing one MCP
  session across users for an identity-required backend (violates IDP.3/IDP.7).

## Child decomposition

- **MIK-6728 IDP-FRAMEWORK** (release gate) — async trait + rich
  `PropagatedCredential`; full identity carried through dispatch; per-backend
  opt-in config; enforcement + fail-closed (IDP.2); tenant-isolation (IDP.3);
  session isolation / stateless-contract (IDP.7); identity-aware-else-bypassed
  cache (IDP.8); audit incl. audit-write-failure policy (IDP.4); credential
  hygiene TTL/exp/nbf/jti/audience (IDP.6); backward-compat (IDP.5); plus the
  signed-assertion reference strategy proving IDP.1 against a test backend that
  echoes caller identity. Scoped honestly to first-party/gateway-trusting
  backends.
- **MIK-6729 IDP-TOKENEXCHANGE** (fast-follow) — `TokenExchangeStrategy`
  (RFC 8693); unblocks OAuth-native third-party backends (the operator's email
  use-case). Reuses the framework's invariants.
- **MIK-6730 IDP-VAULT** (demand-gated) — `CredentialVaultStrategy` (per-user
  refresh-token storage + minting).

The version bump ships when IDP-FRAMEWORK (MIK-6728) is merged; the strategy
children are added per-backend as demand requires.
