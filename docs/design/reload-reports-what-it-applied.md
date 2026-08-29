# Design: a reload must not report a change it did not make

Status: draft for review, 2026-08-26. Found while checking a review claim during
the CWE-346 work. Tracked as MIK-7249.

## SCOPE

FOR: a config reload reports what actually took effect. In particular, enabling
authentication on a running gateway must not report success while doing nothing.

OUT: making any section apply live. That is a larger change per section, and the
evidence below says it is not the one needed.

## Problem

`auth.enabled = true` on a running gateway is the remediation this project
recommends everywhere — the security docs, the startup warning, the changelog
for the CWE-346 fix. Applied to a running process it reports
`"profiles/meta config changed"` and changes nothing.

- The diff tracks the section: `MetaFields.auth` (`src/config_reload/mod.rs:357`)
- So an auth edit sets `profiles_changed`, summarised as
  `"profiles/meta config changed"` (`:152`)
- `restart_required()` is driven by `server_changed` alone, which covers
  `server.host` and `server.port` (`:75`, `:163`)
- Nothing replaces the running auth state: the router snapshots it at
  construction (`src/gateway/router/mod.rs:134`)

A false sense of protection is worse than a known gap, because the operator
stops looking.

## The fail-fast, run before designing

The ticket asked: are most tracked sections snapshotted like `auth`, or is
`auth` the exception? If most, the defect is in the reporting and the fix
belongs there rather than in per-section live-swapping.

Measured. Only three consumers read `live_config` at request time:

| Consumer | Reads |
|---|---|
| `router/well_known.rs:234` | `server.public_url` |
| `router/origin_guard.rs:71,120` | `server` and `public_url` |
| `ui/control_plane.rs:63…237` | `control_plane.role_mapping` |

Every other tracked section — `auth`, `mtls`, `key_server`, `agent_auth`,
`security`, `webhooks`, `meta_mcp`, `capabilities`, `playbooks`,
`routing_profiles`, `code_mode`, `marketplace` — is snapshotted at construction
and cannot change without a restart.

**So `auth` is the rule, not the exception, and the fix is in the reporting.**
Backends are the genuine live path and stay as they are.

## Decision — every field is restart-required until proven otherwise

Three findings from review converge on the same correction, and the design below
is theirs rather than mine.

### Fail closed, do not classify

My first draft derived the live set by reading which sections call
`live_config.get()`. A reviewer pointed out that this is a hand-list wearing a
derivation's clothes: the reading is manual, and the anti-drift test would
encode the same mistake it was meant to catch.

Inverted. **Every tracked field reports restart-required by default.** A field
is reported as applied only when it appears on a short allow-list, and each
entry on that list carries a test proving a request-path read. A new field is
therefore restart-required until someone proves otherwise, which is the safe
direction: the failure mode is telling an operator to restart when they need
not, rather than telling them a change took effect when it did not.

### Field grain, not section grain

A section can hold both kinds of field. `server` is the proof: `public_url` is
re-read per request, while `host` and `port` need a restart. Reporting
`"server changed"` as either applied or restart-required is false half the time.
Classification is per field.

### Track desired configuration apart from the applied baseline

The sharpest finding, and the one my draft missed entirely. The diff compares
the file against a published baseline. If a restart-required edit updates that
baseline, the next reload sees no difference and reports `"no changes"` — so the
warning appears once and never again. An operator who edits `auth`, sees the
warning, gets distracted, and later edits something unrelated is told everything
is fine while authentication has never been on.

Two baselines: what the file asks for, and what the process is actually running.
A field that differs from the running value keeps reporting restart-required on
every reload until a restart makes them agree.

### Unknown fields are reported, not ignored

Fields absent from the diff entirely — `env_files` among them — currently
produce `"no changes detected"` for an edit that changed something. Unknown
counts as restart-required, for the same fail-closed reason.

## Accepted residual

An operator who wants authentication on a running gateway must restart it. That
is the behaviour today; the change makes it visible instead of silent, and keeps
saying so until it is true.

A field wrongly classified as restart-required tells an operator to restart
when they need not. That is the direction this fails in, deliberately.

## Unknowns, closed before this froze

| Question | How | Answer | What it changed |
|---|---|---|---|
| Are most tracked sections snapshotted, or is `auth` unusual? | `rg 'live_config.get()' src/` and read each consumer | Three live consumers; every other section is snapshotted | Turned this from a live-swap change into a reporting change |
| Does the reload already have a restart-required concept? | Read `config_reload/mod.rs:476-486` | Yes, for host and port, with a warning | Reused it rather than inventing a second mechanism |
