<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Multi-user gap scope — one gateway, many human callers

Deployment scoped: one gateway process, serving many distinct human users over HTTP,
where each user holds their own backend credentials, sees only the tools they are
entitled to, and cannot read or act through another user's session, credentials, or
cached results. This is a scope inventory only; it does not decide whether the gaps
below block v4.0.0.

## Capability status

| # | Capability | Status | Citation |
|---|---|---|---|
| 1 | Human authentication to the gateway | PARTIAL | `src/gateway/auth.rs:83-121,898-1013`; `src/key_server/oidc.rs:106` |
| 2 | Session bound to one principal for its lifetime | MET | `src/gateway/streaming.rs:66-75,188-217`; `src/gateway/router/handlers.rs:370-386` |
| 3 | Per-user backend credentials | PARTIAL | `docs/adr/ADR-008-multi-user-oauth-isolation.md:77-88`; `src/gateway/server/account_bindings.rs:60-116`; `src/personal_accounts/identity.rs:48-69` |
| 4 | Per-user authorization of the tool surface | PARTIAL | `src/gateway/meta_mcp/search.rs:638-706`; `src/gateway/auth.rs:83-85,443-470` |
| 5 | Cache isolation across users | MET | `src/gateway/meta_mcp/invoke.rs:1610,3049-3063,5368-5379`; `src/gateway/meta_mcp/prompt_cache.rs:1-30` |
| 6 | Audit attribution to a human | MET | `src/security/transparency_log.rs:147,283,311`; `src/gateway/router/backend_handlers.rs:309-310` |
| 7 | Admin/operator privilege separation | MET | `src/gateway/router/authorization.rs:112-115`; `src/gateway/meta_mcp/mod.rs:1927,2094` |

Count: 4 MET, 3 PARTIAL, 0 ABSENT.

## 1. Human authentication — PARTIAL

`auth_middleware` (`src/gateway/auth.rs:898-1013`) accepts two credential kinds: a
static bearer key resolved by `validate_token_with_origin` against
`ResolvedAuthConfig`, and a key-server credential — a temporary token or a delegated
OIDC bearer — resolved by `key_server_credential`. Only the second path produces a
`VerifiedIdentity` (`src/key_server/oidc.rs:106`: `subject`, `email`, `issuer`), which
is the one identity shape that is provably one human (an OIDC `sub` claim).

The static-key path produces an `AuthenticatedClient` with a `name` and `principal`
that are per-configured-key, not per-human (`src/gateway/auth.rs:83-121`). Nothing in
the auth middleware or `ResolvedAuthConfig` detects or refuses one static key
configured for and handed to more than one person — `docs/adr/ADR-008-...md:70-75`
names this explicitly as the reason `is_multi_user` classification is fail-closed
("a shared single key... can be handed to a whole team"), but fail-closed
*classification* is not the same as *preventing* the sharing. A deployment that relies
on static keys for its human users has no per-human identity at the gateway boundary;
it has per-key identity.

## 3. Per-user backend credentials — PARTIAL

ADR-008 (`docs/adr/ADR-008-multi-user-oauth-isolation.md`) is the governing design.
Its release-gated floor (INV-1/INV-2, `:77-88`) is implemented and enforced:
`meta_route_isolation_refused` (`src/gateway/meta_mcp/mod.rs:1119`) refuses dispatch
before a shared/other-principal token can reach a per-user-required backend, both for
MCP backends and for capability-backed REST connectors
(`src/capability/execution_context.rs:189`).

Slice B (principal-keyed token store) is substantially built:
`src/personal_accounts/` (vault, storage, worker, consent — ~12.9K lines) is wired
into real gateway startup via `install_account_strategies`
(`src/gateway/server/account_bindings.rs:60-116`, called from
`src/gateway/server/mod.rs:1727` and `:2343`), and `account_key` binds a verified
principal plus a configured descriptor into a storage key
(`src/personal_accounts/identity.rs:76-96`).

The gap: that same file self-declares incompleteness. `IdentityBindingError` carries
two `dead_code`-marked variants — `RuntimeNotImplemented` and `UnknownDescriptor` —
each annotated "per-user OAuth scaffolding, deferred to post-4.0.0 backlog
MIK-6744/6745/6746" (`src/personal_accounts/identity.rs:48-69`). The module doc
comment likewise still reads "P2 TEST slice: refusing scaffold... nothing here
constructs a key yet" (`:1-6`), which is stale relative to the code beneath it but was
never corrected — a sign the finished/unfinished boundary here has not been re-audited
since it moved. What is provably solid is the fail-closed refusal (INV-1/INV-2); what
is unverified is how much of the credential-*minting* path (obtaining and refreshing
the per-user token itself, not just refusing to leak the wrong one) is live end to end
versus scaffold.

## 4. Per-user tool-surface authorization — PARTIAL

`AuthenticatedClient` carries `allowed_tools`/`denied_tools`/`backends`
(`src/gateway/auth.rs:83-85`), enforced by `check_tool_scope`
(`:443-470`) — but only at tool-*invocation* time, through
`router::authorization`. `gateway_list_tools`/`gateway_search_tools`
(`src/gateway/meta_mcp/search.rs:638` `list_tools`, `:706` `search_tools`) take only
`args` and `session_id`; they filter by the session's tool-profile
(`profile.tool_allowed`/`backend_allowed`) and by ADR-008 INV-2 backend isolation
(`meta_route_isolation_refused`, omitting OAuth-isolated backends,
`search.rs:679-684`), never by the calling client's `allowed_tools`/`denied_tools`.
A client whose invocation is scoped away from a tool can still see that tool in the
discovery catalogue — a disclosure gap, not an enforcement bypass (the later
invocation is still refused), but it fails capability 4 as stated: "does tool
discovery/listing differ per user."

## Size of the gap

Three packages, in dependency order:

1. **Human-identity floor** (blocks the other two). Make OIDC/key-server
   authentication (or an equivalent one-identity-per-human mechanism) the thing a
   multi-user deployment is required to run, or add a check that refuses a static-key
   deployment from being declared multi-user-safe. Everything below assumes a
   `VerifiedIdentity` is actually present and unique per human; today that is only
   true on the OIDC path.
2. **Finish or re-scope the per-user credential mint** (`src/personal_accounts/`).
   Depends on (1) for a stable principal to key on. The fail-closed refusal (INV-1/
   INV-2) is already load-bearing and does not need rework; the open question is
   narrowly whether the mint/refresh path behind it (MIK-6744/6745/6746) is
   production-ready or still the scaffold its own error variants say it is — that
   needs a direct read of `service.rs`/`worker.rs`/`consent.rs` against a real OAuth
   provider, not a grep.
3. **Tool-discovery filtering by client scope** (`gateway_list_tools`/
   `gateway_search_tools`). Independent of (1) and (2) — it is a filter over an
   existing field (`AuthenticatedClient.allowed_tools`/`denied_tools`) that already
   exists and is already enforced at invocation; the gap is applying the same
   predicate to the two discovery entry points in `search.rs`.

No ABSENT capability was found: every one of the seven either has a working
implementation with a load-bearing test, or a working implementation with a
concretely named, cited incompleteness.
