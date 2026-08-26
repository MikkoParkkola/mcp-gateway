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

## Decision — report per section whether it applied

A reload already distinguishes one restart-required case and says so
(`config_reload/mod.rs:486`). Extend that to every section that cannot apply:

- `restart_required()` becomes true when a changed section is one nothing
  re-reads, not only when the bind address changed
- the summary names the section and says it takes effect on restart, rather
  than the undifferentiated `"profiles/meta config changed"`
- the live sections keep reporting as applied, because they are

### Which sections are live is derived, not hand-listed

A hand-kept list is a second source of truth that drifts from the code the first
time someone adds a live reader. The set is small and the consequence of drift
is this exact defect returning, so the list carries a test asserting it against
the consumers above rather than a comment asking the next person to remember.

Rejected: making `auth` apply live. It is a bigger change than the defect
warrants — the running auth state is held behind an `Arc` snapshotted into the
router, and swapping it mid-flight raises an atomicity question this ticket does
not need to answer. Reporting honestly costs a line and removes the danger,
which is the operator believing they are protected.

## Accepted residual

An operator who wants authentication on a running gateway must restart it. That
is the behaviour today; the change makes it visible instead of silent.

## Unknowns, closed before this froze

| Question | How | Answer | What it changed |
|---|---|---|---|
| Are most tracked sections snapshotted, or is `auth` unusual? | `rg 'live_config.get()' src/` and read each consumer | Three live consumers; every other section is snapshotted | Turned this from a live-swap change into a reporting change |
| Does the reload already have a restart-required concept? | Read `config_reload/mod.rs:476-486` | Yes, for host and port, with a warning | Reused it rather than inventing a second mechanism |
