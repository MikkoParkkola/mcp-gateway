# MIK-7630 follow-up — three more event sources for 4.0.0

Status: design and test plan. The 2026-10-01 scope split deferred these
sources to 4.0.1; the operator moved them back into 4.0.0 on 2026-10-06.
Tracked by MIK-7720 (sources) and MIK-7811 (`lifecycle_key`).
Parent design: `docs/design/2026-10-01-mik-7630-mcp-events.md` (the parent).
Section numbers below prefixed "P" point into the parent.

## 1. Problem

The parent ships three event sources. Three more were asked for and deferred:

| Source | Event names | What it gives a subscriber |
|---|---|---|
| REST capability watch | `watch.<capability>.changed` | "tell me when the answer to this read-only call changes", for any REST capability, with no upstream webhook |
| Gateway operational | `gateway.budget.threshold`, `gateway.budget.exhausted`, `gateway.backend.health_changed`, `gateway.kill_switch.changed` | the gateway's own state changes, for operators and for budget owners |
| Scheduler time | `schedule.tick` | a wake-up on a cron expression, so an agent can run a standing instruction on a timetable |

The constraint that matters: each must be **one new `EventSource`
implementation and nothing else**. The parent's core (catalogue, subscription
service, fan-out, firewall, outbox, delivery, dead letters, audit) must not
change. Each section below proves that against the trait in P§4, and row
U10 makes the proof executable.

Out of scope here: replay cursors (these remain emit-only, `cursor: null`),
and push or poll delivery.

## 2. REST capability watch (poll and diff)

**Descriptor.** One per REST capability marked read-only. The gateway already
classifies every exposed capability as read-only or side-effecting as data
(MIK-7216.IDEM.1). A side-effecting capability is never watchable, because
polling it would repeat its effect. `inputSchema` is `{arguments: <the
capability's own input schema, unchanged>, interval: seconds (default 300,
minimum 60), fields?: [JSON pointer]}`. Nesting keeps the watch options from
colliding with a capability that already takes an `interval` or `fields`
argument.
`payloadSchema` is `{capability, changed: [pointer], digest_before,
digest_after, observed_at}`. The payload carries **digests and changed
pointers, not values**. A subscriber reads the new value through the
capability itself, under its own authorization. That keeps watch payloads
minimal (P§7.3) and stops a watch from becoming a side channel around the
capability's own response policy.

**authorize.** `may_invoke(capability)` for the principal, the same predicate
`tools/list` uses (P§3.7). Re-run at every fan-out, as for every source.

**lifecycle_key / on_first_subscriber / on_last_subscriber.** The source
overrides `lifecycle_key` (P§4): for a credential-free capability the key is
JCS of `(capability, arguments)`, so two principals watching the same
arguments share one poller; for a credentialed capability the key also
includes the principal. The hooks start and stop one poll task per key, and
`on_first_subscriber` receives the principal whose credential a credentialed
poller runs under. Sharing applies only to credential-free
capabilities. For a credentialed capability the poll key also includes the
principal and the poll runs under that principal's credential, so one
principal's credential never answers for another's subscription.

**Poll.** Each poll calls the capability through the normal executor, so it
picks up the firewall, budget and rate limits a tool call gets. It then takes
a JCS digest of the selected `fields` (or of the whole result) of the
**firewall-approved application value**, taken before per-call metadata such
as `_meta` and the provenance receipt is attached, so a stamp that changes
every call cannot fake a change (U12). It emits on a digest change. The first poll sets the baseline and emits nothing. Equal
consecutive digests emit nothing. `upstream_id` is a fresh
random 128-bit id minted per detected transition, so every transition,
including a flap A→B→A→B and one after a poller restart, is a distinct
occurrence; the parent stores it in the outbox record, so retries and replays
keep it. Polls run with jitter. Cost: a
credentialed (unshared) poller charges each poll to its one principal under
`events:watch:<cap>`; an exhausted budget stops that poller. A shared,
credential-free poller is charged to the gateway's global budget, not split
across subscribers, because a split would let one subscriber's exhaustion
stop polling for the others. Each subscriber still pays per delivery through
the parent's per-attempt budget check (P§3.2 step 7), which refuses only the
exhausted principal's deliveries. `events.watch.max_pollers` (default 100) is
a global pool with a per-principal sub-cap
`events.watch.max_pollers_per_principal` (default 10), counted on keys a
principal holds alone. A poll
failure is not an event. After 5 consecutive failures the poller backs off to
the maximum interval and records an audit entry.

**matches.** True for the poller's own key only. The occurrence's `scope`
is `Visibility::Backend(<capability's backend>)`, and the parent re-runs
`authorize` (here `may_invoke`) for every recipient at every attempt, so
sharing a poller never widens who receives its events.

**Capability removed or reclassified.** If a watched capability disappears
or stops being read-only on a reload, its descriptor leaves the catalogue
(`catalogue_changed`), its pollers stop, and its subscriptions are deleted,
so the next refresh answers `-32011`.

**Volatile fields.** A result carrying a timestamp or request id changes on
every poll. The descriptor's `fields` argument is the remedy and its
description says so. With no `fields`, the source excludes top-level keys
named `timestamp`, `requestId`, `request_id` and `generatedAt` from the
digest by default.

**Core changes needed:** none. Config gains `events.sources.rest_watch`
(default off) and `events.watch.max_pollers` (default 100); both live in the
source's config struct, not in the core.

## 3. Gateway operational events

**Descriptors.**

- `gateway.budget.threshold {scope, percent}`: a budget crossed 50/80/100 %.
- `gateway.budget.exhausted {scope}`.
- `gateway.backend.health_changed {backend, from, to}`: a circuit breaker or
  health transition.
- `gateway.kill_switch.changed {backend, state}`.

`scope` names a principal's own budget or a global one.

**authorize and visibility.** The parent's `Visibility::Operator` (reserved
in P§4) is used here: admin standing (`CallerStanding`, the same check
`/ui/api/*` uses) sees all four. A non-admin sees only `gateway.budget.*`
filtered to their own budget scope. Health and kill-switch events reveal
backend topology, so they are operator-only.

**Producers.** Each is a single emit call at a point that already exists:

- the cost enforcer's committed spend (`BudgetEnforcer::record_spend`,
  `src/cost_accounting/enforcer.rs:500`) for budgets. `check` sees only the
  projected spend of a call that may still be refused or fail, so a crossing
  read there could report one that never happened, and again on every
  refused retry;
- the backend health and circuit-breaker transition for health;
- the kill-switch flip (`gateway_kill_server` / revive) for the kill switch.

These are always-on producers, so the lifecycle hooks are no-ops. Emitting
into the bounded queue is non-blocking (P§3.2), so a full events queue cannot
slow a budget check or a breaker.

**Feedback loop guard.** Event deliveries are themselves charged to budgets
(P§3.7). A `gateway.budget.*` delivery is therefore exempt from the
per-delivery charge; otherwise exhausting a budget would emit an event whose
delivery charges the exhausted budget again. This exemption lives in this
source's descriptor (`charge: false`), which is the one field this design
adds to `EventDescriptor`. The parent ships that field from 4.0.0 with
default `true`, so these sources leave the core unchanged.

**Core changes needed:** one, corrected 2026-10-06: the parent never shipped
`charge`; it lands as `EventSource::charges(name)`, default `true`, read by the worker.

## 4. Scheduler time events

**Descriptor.** `schedule.tick` with `inputSchema {cron: string, timezone?:
string (IANA, default UTC), label?: string}` and `payloadSchema
{scheduled_for, label}`. The `label` comes back in each payload so a
subscriber with several schedules can tell them apart. It is the
subscriber's own text, length-capped at 64 characters, and scanned like any
payload.

**Reuse.** `CronExpression::parse` and `matches` from `src/scheduler/mod.rs`
(:206, :227). The cron syntax is the one the scheduler already documents:
five fields, no seconds.

**authorize.** Any authenticated principal. The bounds:

- the parent's per-principal subscription cap;
- a minimum period of 5 minutes, refused with `-32602` and
  `data.field = "arguments.cron"` when the expression can fire more often
  (judged on the minute and hour fields as though every day matched);
- `events.schedule.max_timers` (default 1000, global), enforced in
  `on_first_subscriber`, with a per-principal sub-cap
  (`max_timers_per_principal`, default 20) enforced in `authorize` by
  counting the principal's distinct live timers in the store: lifecycle
  hooks keyed per timer cannot count per principal (MIK-7744).

**Timezone and daylight saving.** Fields are read on the zone's wall clock
(`chrono-tz`). A local time the clock skips fires once, at the first minute
after the jump; a repeated local time fires on its first occurrence only. A
tick less than 5 real minutes after the timer's previous one is dropped, so
neither rule breaks the floor.

**on_first_subscriber / on_last_subscriber.** Start or stop one timer per
canonical `(cron, timezone, label)`. Timers share one minute-boundary ticker
task rather than one task each.

**Emit.** The source persists, per timer key, the last `scheduled_for` it
emitted (one small file in its own state directory under the events store,
written before the emit). On restart a timer fires only for a boundary later
than that value, so a restart within the same minute does not double-fire;
the outbox is not relied on for this, because it forgets delivered records.
`upstream_id = cron ‖ timezone ‖ label ‖ scheduled_for` keeps the event id
stable if the same tick is ever re-emitted. A missed tick
while the gateway was down is not emitted late (emit-only).

**matches.** Exact equality on the canonical arguments.

**Core changes needed:** none.

## 5. Fit summary

| Trait member (P§4) | REST watch | Operational | Schedule |
|---|---|---|---|
| `kind` | `RestWatch` | `GatewayOperational` | `Schedule` |
| `descriptors` | per read-only capability | 4 fixed | 1 fixed |
| `authorize` | `may_invoke` | admin standing / own budget | authenticated + cron floor |
| `matches` | own poll key | field equality | canonical-argument equality |
| `lifecycle_key` | arguments, plus principal when credentialed | default | default |
| `on_first_subscriber` | start poller | no-op | start timer |
| `on_last_subscriber` | stop poller | no-op | stop timer |
| descriptor `charge` | true | false for `budget.*` | true |

All three `SourceKind` variants and `Visibility::Operator` are reserved in
the parent, so records and configs these sources write need no
migration.

## 6. Security notes specific to these sources

- **Watch as an amplifier.** A watch turns one subscribe into recurring
  upstream calls. It is bounded by the interval floor, `max_pollers`, the
  per-principal subscription cap, and the budget charge per poll, and it
  shares pollers across principals only for credential-free capabilities.
- **Watch as a side channel.** Payloads carry digests and pointers, not
  values, and the value is fetched through the capability under the reader's
  own authorization.
- **Operational events as reconnaissance.** Health and kill-switch events are
  operator-only.
- **Time events as a wake-up flood.** The 5-minute floor and the timer cap
  bound them; delivery uses the parent's limiter.

## 7. Test plan

Same rules as the parent's §10: driven through `/mcp` and config, red at
their own assertion on CI before the source lands. Each row names its
criterion in the follow-up ticket.

| # | Test name | Observable | Fails first because |
|---|---|---|---|
| U1 | `watch_is_offered_only_for_read_only_capabilities` | `events/list` shows `watch.<cap>.changed` for a read-only REST capability and not for a side-effecting one; subscribing to the latter → `-32011` | no watch descriptors exist |
| U2 | `watch_emits_on_digest_change_only` | a mock REST endpoint answers A, A, B, B, A → events after the 3rd and 5th polls; first poll emits nothing; payload holds pointers and digests, no values | no watch source |
| U3 | `watch_pollers_are_shared_per_canonical_arguments_and_credential` | two principals, credential-free capability, same arguments → one poller (mock sees one call per interval), charged to the global budget; credentialed capability → two pollers, each under its own credential; a flap A→B→A→B → three events with three distinct `eventId`s | no watch source |
| U4 | `watch_polls_are_budgeted_and_floored` | `interval: 10` → `-32602`; on a **credentialed** capability each poll charges `events:watch:<cap>` to its one principal and an exhausted budget stops that poller; on a **shared** credential-free capability each poll charges the global budget, and one subscriber's exhausted budget stops only that subscriber's deliveries while the poller keeps running for the other | no watch source |
| U5 | `operational_events_are_operator_only_except_own_budget` | an admin sees all four descriptors; a non-admin sees only `gateway.budget.*` and receives only events for their own budget scope | no operational source |
| U6 | `budget_events_are_not_charged_to_the_budget_they_report` | exhausting a principal's budget delivers `gateway.budget.exhausted` exactly once and the ledger shows no charge for that delivery | no operational source |
| U7 | `health_and_kill_switch_transitions_become_events` | killing and reviving a backend → two `kill_switch.changed` events; tripping a breaker → one `health_changed` | no operational source |
| U8 | `schedule_ticks_fire_on_cron_and_respect_the_floor` | a test clock crossing `*/5 * * * *` fires one tick per boundary; `* * * * *` → `-32602`; restart within the same minute does not double-fire (the persisted last-fired value is read back; the receiver sees one POST) | no schedule source |
| U9 | `schedule_label_is_capped_and_scanned` | a 65-character label → `-32602`; a label carrying a blocked injection pattern is dead-lettered `firewall_blocked` | no schedule source |
| U10 | `deferred_sources_need_no_core_change` (structural guard, exempt from red-first) | a CI check that a PR adding a source touches no file under `src/events/` other than the source's own module and the registry line | lands as its own PR **before** the first of these sources and is shown to fail on a synthetic diff that edits a core file; it guards structure and has no behaviour to see red |
| U11 | `watch_stops_when_its_capability_is_removed_or_reclassified` | reclassifying a watched capability as side-effecting on reload → poller stops (mock sees no further calls), subscription deleted, refresh answers `-32011` | no watch source |
| U12 | `watch_ignores_default_volatile_fields_and_metadata` | a result whose only change is `timestamp` → no event; with `fields` naming `/timestamp` → an event; with provenance stamping on, ten unchanged polls → no event; a restarted poller's first transition gets an `eventId` different from every earlier one | no watch source |

## 8. Increments

Each source is one independently releasable PR, after the parent's I4 (the
point where the trait and its hooks are public), and each defaults to off.
Order: scheduler (smallest, exercises the timer hooks), then operational
(always-on producers, exercises `charge: false`), then REST watch (largest,
exercises shared pollers and budget per poll).

## 9. Review record

| Round | Seat | Verdict | Material findings and disposition |
|---|---|---|---|
| 1 | A (on the parent packet) | SHIP-WITH-FIXES | Hooks keyed without the principal could not run credentialed pollers (fixed with `lifecycle_key` in the parent trait); `digest_after` alone repeated on a flap (fixed with a change counter). |
| 1 | B | SHIP-WITH-FIXES | Shared-poller charging rule (global budget for shared polls, per-delivery charge per subscriber); flap id; U10 relabelled as a structural guard landing first; occurrence scope, pool caps, capability removal and volatile fields specified; rows U11–U12. |
| 2 | A | SHIP-WITH-FIXES | Watch options nested apart from capability arguments; digest taken before per-call metadata; random per-transition id survives poller restarts. |
| 2 | B | SHIP-WITH-FIXES | Scheduler double-fire prevented by a persisted last-fired value, not the outbox; U4 split into shared and credentialed cases. |
| 3 | A, B (combined packet) | no findings against this document | Both seats reviewed it in round 3 alongside the parent and raised nothing on it; its round-2 dispositions stand. Approved with the parent at round 5. |
