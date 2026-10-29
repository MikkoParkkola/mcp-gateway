# ADR-023: Which settings apply without a restart

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (lead's addition: restart-only sections); scopes U19 (MIK-8861) and the restart marks in every Settings tab
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

The design promises "config changes apply by themselves", and marks the exceptions with ↻ "needs a restart" before Save (frames 41c, 41s; D3 decision).

| # | Fact | Where |
|---|---|---|
| F1 | A reload compares each tracked section of the running and wanted config and reports a changed section as outstanding until a restart: auth (all of it except `dashboard_session`), mtls, key_server, agent_auth, security, webhooks, meta_mcp, capabilities, playbooks, routing_profiles, code_mode, streaming, failsafe, error_budget, cache, runtime, tasks, events, accounts, cost_governance. | `src/config_reload/diff.rs:192-244`; `src/config/features/auth.rs:151-157` |
| F2 | Host, port and TLS are read once at start. | `src/gateway/ui/session.rs:154-156` |
| F3 | Backends already apply on reload; that is how Add and Remove work today. | `POST /ui/api/backends`, `DELETE /ui/api/backends/{name}` |

So the settings the new UI edits most (keys, spend limits, firewall rules) are exactly the ones that wait for a restart.

## Options

1. **Hot-apply everything.** Every section would need its own safe swap; some (TLS, the listener, mTLS) cannot change without rebinding, which is a restart in all but name.
2. **Hot-apply the sections the UI edits day to day; mark the rest.** The set U19 already names, chosen for what operators change often and what can be swapped atomically.
3. **Hot-apply nothing new.** Every Settings save says "saved, restart required". Honest, and contradicts the design's main promise.

## Decision

Option 2.

- **Apply on reload in 4.0.0** (partly amended below, 2026-10-26): `auth.api_keys` (with ADR-022's rotation fields), cost_governance budgets and alerts, `security.sanitize_input` and `security.ssrf_protection`, and the policy rules, actions, sensitivity and exceptions U8 writes (U19 API19.1 and API19.3), plus the environment name (frame 28g), which only the UI reads.
- **Each swap is atomic.** A parse or validation failure keeps the running value; a removed key stops working for open sessions (API19.2).
- **The restart check ignores what now applies live.** The comparison that marks a section outstanding leaves the hot-applied fields out, the way `restart_only_json` already leaves out `dashboard_session` (F1), so changing a key does not mark the rest of `auth` as needing a restart.
- **Everything else stays restart-only** and keeps F1's truthful reporting (API19.4). The UI marks those fields ↻ before Save, and Gateway › Actions offers Restart (ADR-019).

**Amended 2026-10-26 (U19).** The firewall's `collusion.sources` and `collusion.allowed_flows` do not go live in U19. The relay tracker classifies each delivery when it is recorded: whether its source was sensitive, and which `allowed_flows` entries it may leave through, one bit per entry by position. A live edit would leave evidence already held classified under the old lists: a source just made sensitive has no sensitive evidence on record, and after entries are reordered or removed a held bit can name a different flow, in some edits letting a copy leave through a flow the new rules forbid. That is a fail-open window, so both lists stay restart-only and are reported as needing a restart. They go live with the policy schema work, once sensitivity and allowed flows are judged against the current rules when a relay is witnessed. New policy fields (sensitivity, exceptions) are defined and made live by that same work, not by U19.

**Amended 2026-10-28 (U19 PR2).** Per-client rate limits no longer use `governor`. A reload that changes a key's `rate_limit` keeps the usage already spent under the new rate, and a `governor` limiter can neither change its rate nor report its usage. The per-client bucket (`gateway/auth_runtime.rs`) runs the same GCRA as `governor`'s `Quota::per_minute(rate)`, in integer nanoseconds, and rows pin it to `governor`'s allow and deny sequence. Do not swap it back without a resize that keeps usage. Buckets and breakers live in one store shared across reloads, keyed by the credential, so rebuilding the key list resets nothing.

## Consequences

- The copy "Reach and role apply at once" and "Limits apply at once" becomes true when U19 ships, and is blocked until then.
- failsafe, cache, streaming, TLS and the listener keep needing a restart; their Settings rows say so (41c "When it fails").
- Adding a section to the hot set later is a U19-style change with its own atomic-swap test, not a UI change.
