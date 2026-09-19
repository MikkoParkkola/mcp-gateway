# MIK-6744 — finding: caller identity never reaches OAuth credential selection

**Status:** open. Unfixed on this branch *and* on `codex/v4-release-delivery`.
**Recorded:** 2026-09-10, branch `fix/gh517-protocol-negotiation`.

## The gap

The gateway verifies a caller's identity and then throws it away before it
picks which OAuth token to use. A verified caller subject exists —
`CapabilityExecutionContext::caller_identity: Option<GrantSubject>` at
`src/capability/execution_context.rs:12` — and it is carried into
`execute_with_context` (`src/capability/executor/mod.rs:299`), which validates
it at line 305.

It stops there. Credential fetch is not given the context:

| Site | Signature / call | Identity carried? |
|---|---|---|
| `src/capability/executor/mod.rs:449` | `self.fetch_credential(&capability.auth)` | no |
| `src/capability/executor/mod.rs:591` | `self.fetch_credential(auth)` | no |
| `src/capability/executor/credentials.rs:22` | `fetch_credential(&self, auth: &AuthConfig)` | no context parameter |
| `src/capability/executor/credentials.rs:35` | `self.fetch_oauth_token(provider, auth.token_endpoint.as_deref())` | no |
| `src/oauth/storage.rs:194` | `TokenStorage::load(&self, backend_name, resource_url)` | no |

So the token is selected by `(backend, resource)` alone. Every caller of a
given backend resolves to the same stored token, whoever they authenticated as.

## Independent confirmation

The parked design reaches the same conclusion from the other direction.
`docs/design/2026-09-06-personal-accounts.md` line 45 (on branch
`codex/v4-release-delivery`, commit `e123bb36` — the file does not exist on
this branch):

> `src/capability/executor/credentials.rs::fetch_oauth_token` caches by provider
> and calls `storage.load(provider, provider)`. The caller identity carried in
> `CapabilityExecutionContext` does not select that credential.

## Why this is not fixed by either branch

Keying the store by principal is necessary but not sufficient: a
principal-keyed store still returns the wrong token if the call site passes a
hardcoded principal. During this session an identity-keyed store was
prototyped and reverted (it contradicted the design's key encoding, module
boundary and migration policy). Even in that prototype, the sole production
call site hardcoded the local principal — the store gained an identity
parameter that nothing ever varied. The parked `src/personal_accounts/`
subsystem builds the store and service; it does not touch
`src/capability/executor/` or `src/oauth/`, so the plumbing from
`caller_identity` down to credential selection is unwritten on both branches.

## What a fix has to do

1. Thread `CapabilityExecutionContext` (or just the resolved principal) from
   `execute_with_context` through both `fetch_credential` call sites into
   `fetch_oauth_token`.
2. Decide the behaviour when `caller_identity` is `None` — an unauthenticated
   or single-user deployment. Fail closed, or resolve to a declared shared
   owner. Design line 276 requires an explicit declared mapping, never an
   implicit fallback on first use.
3. Only then does an identity-keyed store change any observable behaviour.

## Acceptance check

A test in which two distinct `caller_identity` values execute the same
capability against the same backend and receive different bearer tokens. No
such test exists on either branch.
