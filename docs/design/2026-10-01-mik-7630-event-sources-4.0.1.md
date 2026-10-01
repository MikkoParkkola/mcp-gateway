# MIK-7630 follow-up — event sources deferred to 4.0.1

Status: design and test plan; no product code. Deferred from 4.0.0 by the
2026-10-01 scope split. Tracked by the 4.0.1 follow-up ticket related to
MIK-7630.
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
polling it would repeat its effect. `inputSchema` is the capability's own
input schema plus `interval` (seconds, default 300, minimum 60) and an
optional `fields` list (JSON pointers) naming what counts as a change.
`payloadSchema` is `{capability, changed: [pointer], digest_before,
digest_after, observed_at}`. The payload carries **digests and changed
pointers, not values**. A subscriber reads the new value through the
capability itself, under its own authorization. That keeps watch payloads
minimal (P§7.3) and stops a watch from becoming a side channel around the
capability's own response policy.

**authorize.** `may_invoke(capability)` for the principal, the same predicate
`tools/list` uses (P§3.7). Re-run at every fan-out, as for every source.

**on_first_subscriber / on_last_subscriber.** Start or stop one poll task per
canonical `(capability, arguments)`. Two principals watching the same
canonical arguments share one poller, which is why the hook is keyed on
arguments and not on subscriptions. Sharing applies only to credential-free
capabilities. For a credentialed capability the poll key also includes the
principal and the poll runs under that principal's credential, so one
principal's credential never answers for another's subscription.

**Poll.** Each poll calls the capability through the normal executor, so it
picks up the firewall, budget and rate limits a tool call gets. It then takes
a JCS digest of the selected `fields` (or of the whole result) and emits on a
digest change. The first poll sets the baseline and emits nothing.
`upstream_id` = digest_after, so a flap A→B→A→B produces distinct events but
a repeated identical observation does not. Polls run with jitter. Each poll
is charged to the subscribing principal's budget under `events:watch:<cap>`,
so a watch's cost is visible and bounded by the existing governor. A poll
failure is not an event. After 5 consecutive failures the poller backs off to
the maximum interval and records an audit entry.

**matches.** True for the poller's own key only.

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

- the cost enforcer's threshold evaluation (`BudgetEnforcer::check`,
  `src/cost_accounting/enforcer.rs:183`) for budgets;
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
default `true`, so the core is unchanged at 4.0.1.

**Core changes needed:** none, given the `charge` field lands with the parent
(added to P§4 for this reason).

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
  `data.field = "arguments.cron"` when the expression can fire more often;
- `events.schedule.max_timers` (default 1000).

**on_first_subscriber / on_last_subscriber.** Start or stop one timer per
canonical `(cron, timezone, label)`. Timers share one minute-boundary ticker
task rather than one task each.

**Emit.** `upstream_id = cron ‖ timezone ‖ label ‖ scheduled_for`, so a
gateway restart within the same minute does not double-fire. A missed tick
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
| `on_first_subscriber` | start poller | no-op | start timer |
| `on_last_subscriber` | stop poller | no-op | stop timer |
| descriptor `charge` | true | false for `budget.*` | true |

All three `SourceKind` variants and `Visibility::Operator` are reserved in
the parent at 4.0.0, so records and configs written by 4.0.1 need no
migration and a 4.0.0 gateway reading them refuses only the source config it
does not know, by name.

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
| U3 | `watch_pollers_are_shared_per_canonical_arguments_and_credential` | two principals, credential-free capability, same arguments → one poller (mock sees one call per interval); credentialed capability → two pollers | no watch source |
| U4 | `watch_polls_are_budgeted_and_floored` | `interval: 10` → `-32602`; each poll charges `events:watch:<cap>` to the subscriber; an exhausted budget stops polling | no watch source |
| U5 | `operational_events_are_operator_only_except_own_budget` | an admin sees all four descriptors; a non-admin sees only `gateway.budget.*` and receives only events for their own budget scope | no operational source |
| U6 | `budget_events_are_not_charged_to_the_budget_they_report` | exhausting a principal's budget delivers `gateway.budget.exhausted` exactly once and the ledger shows no charge for that delivery | no operational source |
| U7 | `health_and_kill_switch_transitions_become_events` | killing and reviving a backend → two `kill_switch.changed` events; tripping a breaker → one `health_changed` | no operational source |
| U8 | `schedule_ticks_fire_on_cron_and_respect_the_floor` | a test clock crossing `*/5 * * * *` fires one tick per boundary; `* * * * *` → `-32602`; restart within the same minute does not double-fire | no schedule source |
| U9 | `schedule_label_is_capped_and_scanned` | a 65-character label → `-32602`; a label carrying a blocked injection pattern is dead-lettered `firewall_blocked` | no schedule source |
| U10 | `deferred_sources_need_no_core_change` | a CI check that the diff introducing each source touches no file under `src/events/` other than the source's own module and the source registry line | the check does not exist; it is added with the first 4.0.1 source and fails if the core is edited |

## 8. Increments

Each source is one independently releasable PR, after the parent's I4 (the
point where the trait and its hooks are public), and each defaults to off.
Order: scheduler (smallest, exercises the timer hooks), then operational
(always-on producers, exercises `charge: false`), then REST watch (largest,
exercises shared pollers and budget per poll).
