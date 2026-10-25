# ADR-026: A "day" is the gateway host's day

- **Status**: Decided, recorded here, 2026-10-25 (lead ruling on the D11 copy; implemented by MIK-8901). Not reopened by this ADR.
- **Ticket**: MIK-8839 (lead's addition); binding on MIK-8901, U1 (MIK-8854, via ADR-017's daily buckets) and U10 (MIK-8863)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

The new UI says daily spend limits reset at midnight in the gateway's time zone (Costs, the key page, about ten tooltips).

| # | Fact | Where |
|---|---|---|
| F1 | The budget enforcer counts days since the epoch in UTC. | `src/cost_accounting/enforcer.rs:42`, `:153-155` |
| F2 | Today's spend is restored after a restart only on the same UTC day it was saved. | `src/cost_accounting/persistence.rs:16-17` |

For a gateway in Europe/Amsterdam, limits reset at 01:00 or 02:00 local time, and the copy is wrong.

## Decision

- Every "day" the gateway counts (budget windows, `costs.json` restore, ADR-017's daily buckets, "today" in the UI) is local midnight to local midnight in the host's time zone, taken from the system. No new setting.
  - Amendment, MIK-8901 (lead, 2026-10-25): a per-key budget's rolling window (`BudgetWindow` Day, Week and Month: the last 24 hours, 7 days or 30 days) is a duration, not a calendar day, and keeps rolling. "Budget windows" above means the enforcer's daily limits.
- The costs API names the zone it counts in, so the UI prints it.
- A test covers both daylight-saving days (in Europe/Amsterdam, 25 hours on 2026-10-25 and 23 hours on 2027-03-28): one reset at local midnight, no double reset, no skipped day.
- A host in UTC behaves exactly as today.

## Consequences

- The copy is true for every operator once MIK-8901 ships; until then it is a known gap, marked on MIK-8901.
- `costs.json` (F2) gains a `day_basis` field. A snapshot without it was saved under UTC days; the gateway keeps resetting that open day at UTC midnight as before, and starts counting local days only after that one UTC reset. The open day's allowance therefore neither shrinks nor grows at the upgrade, and no spend moves between days.
- A restart just after local midnight starts a fresh day, as the operator expects.
- A host whose zone changes between saves restores by the zone at load; the saved timestamp is unchanged.
