# MCP Events

The gateway offers event types to clients through the MCP events extension:
`events/list` shows the types you may subscribe to, `events/subscribe`
registers a webhook (an HTTPS callback URL and a `whsec_` secret), and
`events/unsubscribe` ends it. Every delivery is signed, scanned by the
response firewall, rate limited, budgeted and audited. Events are served over
HTTP only, and only to an authenticated caller.

Events are off by default:

```yaml
events:
  enabled: true
  store_dir: ~/.mcp-gateway/events
```

The design is `docs/design/2026-10-01-mik-7630-mcp-events.md`. The sources
below are opt-in; each is off until its `events.sources.*` switch is on.

## Scheduled wake-ups: `schedule.tick`

A tick on a five-field cron expression (minute, hour, day of month, month,
weekday; no seconds) read on the wall clock of an IANA timezone, so an agent
can run a standing instruction on a timetable.

```yaml
events:
  enabled: true
  sources:
    schedule: true
  schedule:
    max_timers: 1000              # distinct timers across all principals
    max_timers_per_principal: 20  # distinct timers one principal may hold
```

Subscribe with:

```json
{"name": "schedule.tick",
 "arguments": {"cron": "0 9 * * 1-5", "timezone": "Europe/Helsinki", "label": "weekday standup"},
 "delivery": {"mode": "webhook", "url": "https://agent.example/hook", "secret": "whsec_..."}}
```

Each tick's `data` carries the UTC instant it fired and your label:
`{"scheduled_for": "2026-10-06T06:00:00Z", "label": "weekday standup"}` (09:00
in Helsinki is 06:00 UTC in October).

Rules:

- **At most one tick every 5 minutes.** An expression that could fire more
  often is refused with `-32602` and `data.field = "arguments.cron"`. The
  check reads the minute and hour fields as though every day matched, so an
  expression whose ticks are 5 or more minutes apart only because of its day
  fields (for example across midnight) is also refused.
- **Timezone.** `timezone` is an IANA name such as `Europe/Helsinki`; omitted
  means `UTC`. An unknown name is refused with
  `data.field = "arguments.timezone"`.
- **Daylight saving.** A local time the clock skips (spring forward) fires
  once, at the first minute after the jump; several skipped matches, such as
  `*/5` through the skipped hour, fire as that one tick. A local time the
  clock repeats (fall back) fires only the first time. Either way no two ticks
  of one schedule are ever less than 5 minutes apart in real time: a tick
  that would come sooner is dropped.
- **Label**: up to 64 characters, returned in every tick so a subscriber with
  several schedules can tell them apart. It is your own text and is scanned
  by the response firewall like any payload; a blocked label is
  dead-lettered `firewall_blocked`.
- **Caps**: subscriptions with the same cron, timezone and label share one
  timer. A principal holding `max_timers_per_principal` distinct timers is
  refused a new one with `-32013`, and so is any subscribe past `max_timers`.
- **Missed ticks are not sent late.** A tick due while the gateway was down
  is skipped, and so is one the gateway could not check in its own minute
  while running (a stalled runtime or a clock step): there is no catch-up. A restart within the same minute does not repeat a tick: the
  last tick sent per timer is kept under `<store_dir>/schedule/`.
