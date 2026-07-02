# ADR-008: Multi-user OAuth isolation — credential-agnostic by default

- **Status**: Accepted (supersedes the gateway-brokered-first draft on MIK-6742)
- **Date**: 2026-07-03
- **Ticket**: MIK-6742 (P0 release blocker for v3.0.0)
- **Deciders**: operator + gateway maintainers
- **Composes with**: ADR-007 (identity propagation / the chokepoint this generalizes), ADR-001 (`GatewayKeyPair`), MIK-6648 (OIDC verify), MIK-6704 (per-user credential minting)

## Context

A shared / multi-user ("team") gateway stores **one** OAuth token per backend
and attaches it to **every** caller's request. Tokens are keyed by
`(backend, resource)` — not by user — at `src/oauth/storage.rs` `storage_key`,
and the token is held on `HttpTransport.oauth_client` and attached
caller-agnostically (`src/transport/http/mod.rs`). So on a shared gateway, user
A's call to a personal-OAuth backend (Gmail, Superhuman) can be served with user
B's login: **cross-user credential exposure**. The v3.0.0 identity-propagation
feature (ADR-007) is a separate, additive path that the classic `oauth:` backend
does not use and does not fail closed on.

This is a pre-existing defect, not a v3.0.0 regression — but it makes a
multi-user v3.0.0 unsafe to ship, so it holds the release (version walked back to
`3.0.0-dev`; no `v3.0.0` tag exists).

The operator's design steer (2026-07-03): make the user experience smooth and
automate consent; and reconsider whether the **gateway** should hold tokens at
all — authentication/authorization may be better handled **out of band** from the
gateway's point of view (the MCP client, or an external broker, owns the
credential; the gateway just routes).

## Decision

**The gateway is credential-agnostic by default.** It authenticates *who* the
caller is and authorizes *whether* they may reach a backend, but it does not, by
default, own *how* the caller proves themselves to that backend. The party that
performs the OAuth flow holds the token; a token is **never copied across the
client↔gateway boundary**.

We generalize the ADR-007 chokepoint (`resolve_caller_credential`) rather than
build a parallel subsystem. Credential resolution returns one of:
`Attach { headers, cache_binding }` · `Passthrough` · `NoCredential` · `Refuse`.

### The preference ladder (gateway auto-selects the highest rung that works, per backend)

1. **SSO reuse (zero prompts)** — the caller's gateway login already carries the
   backend's provider scopes (e.g. Google login → Gmail/Calendar/Drive). Reuse it.
2. **Client-native OAuth (one click, client holds the token)** — the gateway
   advertises the backend's auth requirement (RFC 9728 protected-resource
   metadata); a capable MCP client runs the browser login itself and attaches
   the token per request (**passthrough**). Gateway stores nothing. *Target path
   for capable clients.*
3. **Gateway-brokered consent (one click, gateway holds the token, per-user)** —
   for thin/headless clients that cannot run their own OAuth: the signed-state
   consent-journey flow, token stored **keyed by principal**. *Fallback only.*
4. **Static / service account (zero per-user prompts)** — explicitly shared
   backends (`oauth.shared_account = true`), operator-blessed and logged.

### Principal model

Every request carries a `Principal`: `User(stable_actor_id)` (OIDC) ·
`ApiKey(key_name)` · `Local` (auth off). A single-user gateway is always `Local`,
so shared+single-user collapse to the same code path.
`is_multi_user = auth.enabled && (api_keys > 1 || oidc configured)`.

### Invariants

- **INV-1** — a per-user backend NEVER falls back to a shared or other-principal
  token. Required + unresolved = **refuse**, never fall through.
- **INV-2** — a multi-user gateway must not serve a gateway-held OAuth token to
  an arbitrary caller. Refuse unless a per-user credential is resolved OR the
  operator sets `oauth.shared_account = true` (logged).
- **INV-3** — per-principal cache isolation: the `cache_binding` (user + audience)
  is mixed into response + idempotency cache keys.
- **INV-4** — the gateway stores tokens ONLY for the gateway-brokered rung (3).
  Passthrough (rung 2) and SSO reuse (rung 1) store nothing.

## Consequences

The most secure gateway is the one that never stores your Gmail token. Making
out-of-band the default:

- **Collapses most of the roadmap.** Rungs 1–2 need no gateway token store and no
  consent-journey engine. Slice B (principal-keyed token store) and Slice C
  (gateway-brokered consent) become demand-gated follow-ups — built only when a
  thin/headless client that cannot self-OAuth actually shows up.
- **Reduces blast radius.** No per-backend token honeypot; a request carries only
  its own caller's credential; a gateway compromise leaks no stored logins.

**Honest catch:** passthrough (rung 2) is only smooth if the client knows to
obtain a backend-audience token. That requires the gateway to *advertise*
per-backend auth requirements (RFC 9728), which the gateway does not do today
(it validates inbound Bearer tokens but publishes no protected-resource
metadata). That advertisement is new work — standards-based, client runs the
browser dance, gateway stores nothing — and it is what makes rung 2 the default
instead of an austere refusal.

## Release gate (both single- and multi-user gateways safe)

- **A — fail-closed guard (INV-1/INV-2), MIK-6743.** Unconditional floor. A
  per-user backend refuses rather than serving a shared/other-user token;
  `shared_account: true` required to share. **Ships first (this slice).**
- **D — client-supplied passthrough, MIK-6746.** Promoted to primary: caller
  attaches its own credential via `request_with_headers`; gateway stores nothing.
- **Inbound auth-requirement advertisement (new).** Gateway publishes per-backend
  OAuth requirements so capable clients self-serve. Makes D smooth (not austere).

Release gate = **A + D + advertisement**. That is a safe, working multi-user
gateway: per-user backends work via the caller's own credential or refuse
cleanly; cross-user leak is structurally impossible; the gateway holds no token
honeypot. Then restore `3.0.0` and tag.

## Demand-gated follow-ups (not release-gating)

- **B — principal-keyed token store, MIK-6744.** Needed only when the gateway
  holds a token (rung 3): key by `(principal, backend, resource)`; migrate
  single-user files on load.
- **C — gateway-brokered consent journey, MIK-6745.** Signed single-use short-TTL
  state binding `(principal, backend, nonce)` via `GatewayKeyPair`; delivered via
  MCP elicitation or actionable-refusal error carrying the consent URL; only
  gateway-built URLs (anti-phishing); tokens encrypted at rest; grants/revokes
  audited. Build when a thin client demands it.
- Non-gating accelerators: SSO/`google_inbound` reuse (rung 1), token exchange
  (MIK-6729), credential vault (MIK-6730), connection isolation (MIK-6735).

## Rejected alternatives

- **Gateway-brokered-first (the earlier draft).** Builds the consent-journey
  engine as the default. Rejected: more code, larger attack surface (token
  honeypot), and unnecessary for any client that can run its own OAuth.
- **Per-gateway mode flag** (one gateway = one ownership model). Rejected: a
  single gateway legitimately mixes a shared team Slack with personal Gmail.
  Ownership is per-backend.
- **Separate multi-user subsystem.** Rejected: duplicates the ADR-007 chokepoint.
- **Copying the gateway-held token to the client.** Rejected: doubles the attack
  surface for zero benefit. If the client must hold a token, it originates it.

## Caveat

Google's device-code flow does not permit Gmail scopes, so a hosted-callback
redirect remains the only Gmail path for the gateway-brokered rung (C).
