# Error budgets: configurable, and blind to throttling

Design for GH #475 (reported by crepererum, affected version 3.5.0), scoped into
4.0.0. Written before any code, to be reviewed as a design.

## Problem

Two problems, one reported and one behind it.

**Reported.** An agent calling the gateway rapidly is rate-limited upstream. The
`429` responses trip both the per-backend and the per-capability circuit
breaker, and recovery takes five minutes. The reporter asks for the thresholds
to be exposed in YAML so they can be tuned.

**Behind it.** The budget records a plain success/failure. A `429` is counted
exactly like a `500`. The invoke path already classifies rate limiting —
`classify_from_detail` returns `ErrorCategory::RateLimited`
(`src/gateway/meta_mcp/invoke.rs:2945`), unit-tested at `:2989` and `:3004` — and
then discards that verdict: the budget call site passes a bare boolean
(`invoke.rs:1369`, `self.record_error_budget(server, tool, dispatch_result.is_ok())`).

A backend that is throttling you is not an unhealthy backend. The error budget
exists to answer "is this backend ill", and throttling is the one failure that
answers "no, it is fine, you are asking too fast".

## Measured constraints

| fact | source |
|---|---|
| `ErrorBudgetConfig` — threshold 0.8, window_size 100, window_duration 5m, min_samples 10 | `src/kill_switch/budget.rs:95`, `impl Default` at `:119` |
| `CapabilityErrorBudgetConfig` — threshold 0.8, window_size 50, window_duration 5m, min_samples 5, cooldown 5m | `src/kill_switch/budget.rs:140`, `impl Default` at `:166` |
| Neither type derives `Serialize`/`Deserialize` | `rg 'serde\|Deserialize\|Serialize' src/kill_switch/budget.rs` — zero hits |
| `set_error_budget_config` / `set_capability_budget_config` have no callers in `src/` or `tests/` | `src/gateway/meta_mcp/mod.rs:961`, `:967` |
| The defaults are therefore the only reachable values | follows from the two rows above |
| Both setters were already recorded as dead, disposed without a ticket | `docs/requirements/RELEASE-4.0.0-criteria-status.md:278-279` |
| The rest of the config parses durations as `5m` via `humantime_serde` | `src/config/mod.rs:1196`, `:1301`, `:1392`; module at `:1676` |
| Existing tests pin both `Default` impls | `src/kill_switch/tests.rs:251`, `:345-370` |
| No YAML or example config uses an `error_budget` key today | `rg error_budget --glob '*.yaml' --glob '*.yml'` — zero hits |

## Decisions

**D1 — a rate-limited response enters neither budget.** Not as a success, not as
a failure. `record_error_budget` takes the existing `ErrorCategory` instead of a
`bool`, and `RateLimited` returns without recording.

The signal must be narrow, and this is the part the first draft got wrong.
`classify_from_detail` matches bare substrings on free error text
(`invoke.rs:2943-2952`): `lower.contains("429")` fires on any message carrying
those three digits — a `500` whose body quotes request id `4291a` — and
`"throttl"` matches "throttling disabled". No structured status code exists at
the call site or anywhere in `invoke.rs` (`rg 'status_code|http_status|StatusCode'`
— zero hits), so free text is the only signal available.

That was cheap when the verdict only chose a retry: a wrong `RateLimited` cost
one retry. D1 promotes it to a health-accounting gate, where the two errors are
not symmetric:

| mistake | consequence |
|---|---|
| counting a real `429` as a failure | the reported bug — a breaker trips early |
| excluding a real failure as a `429` | a sick backend never trips its breaker at all |

The second is strictly worse, so **ambiguity resolves toward counting**. The
exclusion fires only on a rate-limit determination made from a status-shaped or
unambiguous phrase match — `429` as a standalone token, `too many requests`,
`rate limit`/`rate-limit`/`ratelimit`, `RESOURCE_EXHAUSTED` — never on a digit
run inside a larger token, and never on the `throttl` stem, which matches its own
negation. Everything else counts as a failure exactly as it does today.

Tightening that arm of the classifier is therefore IN scope for this change; it
was out in the first draft. Recorded as a scope move rather than a silent edit:
D1 cannot be correct without it, because D1 is what makes a misclassification
expensive.

**The exclusion is observable.** A counter and a debug line record each
suppressed response, so an operator can confirm D1 is firing, quantify how much
throttling a backend is doing, and see the blind spot rather than infer it. This
is also the measurement that answers the deferred per-backend-override question.

Why not count it as a success: that dilutes the measured failure rate, so a
backend that is both throttling and genuinely failing looks healthier than it
is. Why not count it as a failure: that is the reported bug.

Named consequence, stated rather than discovered later: a backend returning
*only* `429`s will never trip its breaker. That is correct. The lever for
throttling is backoff, not amputation, and the breaker exists to stop the
gateway hammering a broken backend — not a busy one.

**D2 — both budgets configurable from YAML.** `Serialize`/`Deserialize` derives
on both types, a top-level `error_budget:` section with `capability:` nested
inside it, durations in the same `humantime` form as the rest of the config.

```yaml
error_budget:
  threshold: 0.8
  window_size: 100
  window_duration: 5m
  min_samples: 10
  capability:
    threshold: 0.8
    window_size: 50
    window_duration: 5m
    min_samples: 5
    cooldown: 5m
```

Every field carries its own serde default, so a partial section merges
field-by-field with today's values: `error_budget: {threshold: 0.5}` changes the
threshold and leaves the other four alone. A section-level default would zero
them and quietly break D4's guarantee for exactly the operator most likely to
write one. The shipped example config gains a commented `error_budget:` block —
the knob was asked for because it was invisible.

**D3 — validated at load, rejected with the field named, never clamped.**
Stated as acceptance, not rejection: `threshold.is_finite() && threshold > 0.0
&& threshold <= 1.0`. A reject-style range test (`t <= 0.0 || t > 1.0`) admits
`.nan`, which YAML can express and against which every later comparison is
false — a breaker that reads as configured and never fires, which is precisely
what D3 exists to prevent. Also refused: `window_size` or `min_samples` below
1; a zero duration; and `min_samples > window_size`, which is the interesting
one — it makes the budget silently never evaluate, so a clamp would hand the
operator a breaker that looks configured and never fires.

**D4 — defaults unchanged.** Every field keeps the value it has today, so an
existing deployment that adds no YAML sees exactly one behaviour change: D1.

## Options rejected

- **Per-backend threshold overrides.** `BackendConfig` (`src/config/mod.rs:1372`)
  makes this cheap to add later. Rejected for now because D1 is believed to be
  what made the global defaults feel wrong; shipping both would leave us unable
  to tell which one fixed it. The reporter has been invited to object.
- **Lengthen the recovery time, or shorten it by default.** Tunes the symptom.
  The reporter's backend was never unhealthy.
- **Count `429` as a success.** Cheapest possible change, and it corrupts the
  measurement the budget exists to make.
- **Expose the setters and stop there** (what #475 literally asks for). Would
  ship a knob that every operator hitting rate limits must discover and tune,
  to work around a classification the code already computes.

## Out of scope

- Per-backend and per-capability overrides (above).
- The other two dead setters recorded alongside these — `enable_idempotency`
  (tracked as MIK-7272.SUB.4) and `with_tool_registry` (still disposed, no
  ticket). This change wires the two the report reaches.
- Retry/backoff behaviour on a `429`. D1 stops the budget mis-reading it, and
  narrows how the verdict is reached (above); what the invoke path *does* with a
  retryable verdict is unchanged.

## Unknowns

Both checkable ones are closed. Recorded in the form the process requires:
question — what was run — what came back — what it changed.

- **Does an existing config already use the `error_budget` key?** —
  `rg error_budget --glob '*.yaml' --glob '*.yml'` — zero hits; the four `.md`
  hits are prose — nothing. The top-level name is free and no migration is owed.
- **Is the rate-limit verdict available where the budget is recorded?** —
  read `src/gateway/meta_mcp/invoke.rs` at the call site and the classifier —
  `classify_from_detail` at `:2945` returns `ErrorCategory::RateLimited`, tested
  at `:2989`; `:1369` passes `dispatch_result.is_ok()` — D1 needs no new
  classification, only a signature change to stop discarding one.

Deferred, with its four fields:

- **Will the reporter still want per-backend overrides after D1 ships?** Owner:
  crepererum, on GH #475 (invited to object in
  [this comment](https://github.com/MikkoParkkola/mcp-gateway/issues/475#issuecomment-5551975799)).
  Resolved by: their answer, or silence through the 4.0.0 release. Trigger: the
  4.0.0 release, or any second report of the same shape. If it resolves badly
  (they still need it): additive, `BackendConfig` already carries the shape, and
  nothing in this design forecloses it.

Nothing in this change depends on that answer, so implementation proceeds.

## What this changes for a reader of the release notes

One behaviour change and one new configuration surface. Rate limiting no longer
counts against backend health; every threshold that governs it is now writable,
validated, and defaulted exactly as before.

## D5 — the upgrade path

D1 changes behaviour for every existing deployment that upgrades, without any
config edit on their part. That is precisely the case the repository's
post-upgrade migration framework exists to announce.

The framework is real and reachable: `mcp-gateway upgrade`
(`src/cli/mod.rs:436-457`) applies pending migrations and updates a version
stamp at `~/.mcp-gateway/version.stamp`; `check_upgrade` also runs on every
`serve` startup (`src/commands/upgrade.rs:7-8`). The registry is a static
slice, `MIGRATIONS` (`:97`).

`MIGRATIONS` currently holds exactly one entry, `applies_below: "3.0.0"`
(`:98`). There is no 4.0.0 entry. That is a release-wide gap, not one this
design created, and it is recorded separately; this design adds the entry its
own change requires.

The 3.0.0 entry is the pattern to follow: an informational notice about a
changed default, which "NEVER edits the file" (`:107`). D4 keeps every default
identical, so nothing needs migrating — only announcing.

```
applies_below: "4.0.0"
description: rate-limited responses no longer count against backend or
             capability error budgets; every budget threshold is now
             configurable under `error_budget:` (config unchanged)
```

Two properties this inherits from the existing entry and must keep: it never
writes to the user's config, and it is idempotent — the version stamp means a
second `upgrade` run says nothing a second time.

## Review record

| leg | vendor | verdict | state |
|---|---|---|---|
| 1 | Claude Code CLI / synthetic-review | SHIP-WITH-FIXES | findings incorporated below |
| 2 | Codex / GPT | — | running; verdict not yet recorded |

Leg 1 raised two blocking findings, both verified at source before acting on
them and both accepted:

- **The classifier-fidelity precondition D1 depends on** (HIGH). Confirmed and
  found worse than reported: the match is on bare substrings, so a `500` can be
  read as a `429`. Response was not to state the precondition — that leaves the
  defect describable — but to narrow what D1 keys on and name the asymmetry that
  makes the direction of doubt matter. Pulled the classifier's rate-limit arm
  into scope as a recorded scope move.
- **`.nan` passes a reject-style range check** (MEDIUM). D3 restated as
  acceptance-in-range with `is_finite`. The failure it admitted — a breaker that
  reads as configured and never fires — is the exact one D3 was written to stop.

Three improvements accepted as written: the exclusion is observable, partial YAML
sections merge field-by-field via per-field serde defaults, and the example
config gains a commented block.

This change ships no code yet, so no leg has reviewed an implementation. Leg 2's
verdict and any resulting amendment land before that starts.
