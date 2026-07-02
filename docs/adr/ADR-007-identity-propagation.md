# ADR-007: End-user identity propagation to backend MCP servers

- **Status**: Accepted
- **Date**: 2026-07-02
- **Ticket**: MIK-6704 (release gate for the Trust Fabric major version bump)
- **Deciders**: operator + gateway maintainers
- **Composes with**: MIK-6648 (OIDC verify), MIK-6688 (identity → control-plane role), ADR-001 (message signing / `GatewayKeyPair`)

## Context

mcp-gateway authenticates the end user (OIDC) and authorizes them **at the
gateway** — capability grants (`grant_subject_from_verified_identity`) and
control-plane RBAC (MIK-6688). But it does **not** propagate that identity to
connected backend MCP servers. Outbound calls
(`src/transport/http/mod.rs::build_mcp_headers`) carry only protocol headers
plus a **static, per-backend credential** that is identical for every caller. A
multitenant backend (email, memory, calendar) that itself requires OIDC/OAuth
therefore sees only "the gateway" — it cannot tell which user is calling, so it
cannot enforce per-user access or produce a per-user audit trail.

The operator requirement (2026-07-02): propagate identity to connected services
that require OIDC/OAuth so the backend acts as the **real user**, not a shared
service account.

Three strategies were considered:

1. **OAuth 2.0 Token Exchange (RFC 8693)** — gateway swaps the user's token for a
   backend-audience token per (user, backend). Cleanest for OAuth-native
   backends, but requires the IdP to support token-exchange.
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
bump on the *invariants* (fail-closed, tenant-isolation, audit, backward-compat)
rather than one auth model means the release ships a correct, safe foundation
that any strategy plugs into — and a wrong per-backend strategy choice later
cannot regress the safety contract.

### Architecture

- **`IdentityPropagation` trait** (new, in `src/security/` or
  `src/identity_propagation/`): given a `VerifiedIdentity` + a backend
  descriptor (id + audience), returns a `PropagatedCredential` (an outbound
  header set — bearer token or assertion header) or an error. Implementations:
  `SignedAssertionStrategy` (reference, this epic), `TokenExchangeStrategy` and
  `CredentialVaultStrategy` (children).
- **Per-backend opt-in config**: a backend's config gains an optional
  `identity_propagation` section (strategy + audience + required flag). Absent →
  today's static-credential behavior is unchanged (IDP.5).
- **Enforcement point**: `build_mcp_headers` (the single source of truth for
  outbound headers) consults the configured strategy when the current request
  carries a `VerifiedIdentity` and the backend requires propagation. The
  identity must be threaded from the request extensions to the transport layer.
- **Fail-closed (IDP.2)**: if a backend *requires* propagation and no per-user
  credential can be produced, the call is **refused** — never a silent fallback
  to the shared static credential.
- **Tenant-isolation (IDP.3)**: a credential minted for (user U, backend B,
  audience A) is scoped to exactly that tuple and is never presented for a
  different user or a different backend audience. No cross-request credential
  cache keyed only by backend.
- **Audit (IDP.4)**: each propagation event is written to the transparency log
  (which user, which backend, which audience) — **never the token/credential
  itself**. Reuses the MIK-6700 signed transparency log.

### Invariant ordering (fail-fast)

IDP.2 (fail-closed) and IDP.3 (tenant-isolation) are implemented and tested
first: a propagation feature that leaks a token across tenants or silently uses
a shared account is worse than none.

## Consequences

- **Positive**: unblocks multitenant SaaS backends as first-class MCP servers
  with real per-user access + per-user audit — a core enterprise trust-fabric
  capability. The invariants are proven once, at the trait boundary, for every
  strategy.
- **Negative**: the signed-assertion reference strategy only helps backends that
  trust the gateway's key; OAuth-native third-party backends wait for the
  token-exchange child. This is acceptable — the framework + reference strategy
  is a shippable, safe increment.
- **Rejected**: shipping one concrete strategy as the gate (couples the release
  to one auth model); a shared per-backend credential fallback (violates IDP.2).

## Child decomposition (all gate TFR.2 except demand-gated)

- **IDP-FRAMEWORK** (release gate): the trait, per-backend opt-in config,
  `build_mcp_headers` enforcement, fail-closed (IDP.2), tenant-isolation
  (IDP.3), audit (IDP.4), backward-compat (IDP.5), + the signed-assertion
  reference strategy proving IDP.1 against a test backend that echoes caller
  identity.
- **IDP-TOKENEXCHANGE** (fast-follow): `TokenExchangeStrategy` (RFC 8693).
- **IDP-VAULT** (demand-gated): `CredentialVaultStrategy` (per-user refresh
  token storage + minting).

The version bump ships when IDP-FRAMEWORK is merged; the strategy children are
added per-backend as demand requires.
