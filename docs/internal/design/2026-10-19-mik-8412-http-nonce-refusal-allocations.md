# MIK-8412: what a signed nonce refusal costs on `POST /mcp`

Status: P1a ratified (gpt-20261019T010924Z-21036 SHIP-WITH-FIXES,
agy-20261019T010924Z-21037 SHIP); the lead's ALLOC.2 cap ruling
(2026-10-19) is recorded below. P1b under review. Measurement-first ticket:
ALLOC.1/ALLOC.2 measure and assert; ALLOC.3 (a fix) only if a row exceeds
its cap. Base: origin/docs/ranking-1-release-line.

## P1a: problem

### The question

MIK-8400 bounded what a refused signed call may allocate on stdio: at most 2
large allocations (>= 2 KiB) totalling 12 KiB, and 8 KiB of small ones,
measured on `dispatch_single_staged` with the request already parsed
(`src/gateway/server/tests/signing_nonce_allocations.rs`). On stdio the nonce
is checked before the route stage, so a refusal never reaches the caller
verdict. On `/mcp` the caller verdict (`MetaMcp::caller_verdicts`,
`router/handlers/dispatch_tools_call.rs:428`) runs before
`prepare_signing_for_call` (`:631`). The ticket asks whether that order lets
a large refused payload cost more than the stdio caps allow (the
denial-of-service cost MIK-8400 bounds), and says the gap may be zero.

### Measured so far (probe, Spark, current-thread runtime, signed fixture
`stored_read_busy_nonce_tests::signed_fixture`: managed-account backend
`work-mail`, surfaced `read`, nonce required)

| payload | refusal | total B | allocs | large (n / B) | small B | custody lookups |
|---|---|---|---|---|---|---|
| 0 | missing (cold) | 188,035 | 1,077 | 12 / 68,496 | 119,539 | +2 |
| 0 | malformed | 84,999 | 469 | 9 / 41,168 | 43,831 | +2 |
| 0 | replayed | 85,012 | 470 | 9 / 41,168 | 43,844 | +2 |
| 1 MiB | missing / malformed | 7,221,527 | 28,668 | 16 / 226,608 | 6,994,919 | +2 |
| 1 MiB | replayed | 7,221,546 | 28,671 | 16 / 226,608 | 6,994,938 | +2 |
| 3 MiB | missing / malformed | 21,626,167 | 85,054 | 18 / 732,592 | 20,893,575 | +2 |
| 3 MiB | replayed | 21,626,186 | 85,057 | 18 / 732,592 | 20,893,594 | +2 |

Observations (verified by the probe): the verdict does run before every
refusal (+2 custody lookups each); the three refusals cost the same at a
given size; cost grows about 6.9 bytes per payload byte.

Probe 2 (verified): missing-nonce refusal, warmed, same body on a per-user
target and on a plain backend with no account (the verdict has nothing to
judge; +0 custody lookups), plus a parse-only control:

| payload | parse-only | plain target | per-user target | verdict share |
|---|---|---|---|---|
| 1 MiB | 3,980,864 B | 7,197,148 B | 7,221,702 B | 24,554 B: 3 large / 11,096 B, 13,458 B small |
| 3 MiB | 12,056,400 B | 21,601,788 B | 21,626,342 B | 24,554 B: 3 large / 11,096 B, 13,458 B small |

The verdict adds a fixed 24,554 B per refused call with no payload term.
The payload-proportional cost (about 3.2 MB per MiB beyond the parse) is
paid on the plain target too: HTTP intake, filed as MIK-8499.

### Constraints

- K1. The stdio caps measure a refusal after parse; an HTTP row comparable to
  them must separate parse from what the handler does after it.
- K2. No production seam for measurement (ticket fail-fast: ask first).
- K3. Rows are lib tests using the existing per-thread `alloc_meter`,
  packaged-crate safe (no repo files read at run time).

### Acceptance signal

ALLOC.1: rows for missing, malformed and replayed nonce refusals on `POST
/mcp` at 1 and 3 MiB, per-user target, surfaced name, verdict shown to run.
ALLOC.2 (lead ruling 2026-10-19): the stdio caps (2 large, 8 KiB small) do
not apply literally: they bound a whole refusal after parse, while the
verdict's share is fixed per refused call, with no payload term. The HTTP
cap is asserted on the per-user minus plain delta: equal at 1 and 3 MiB
within 1 KiB; at most 4 large allocations, 16 KiB large and 96 KiB small
(the small cap re-proposed after the all-threads measurement below; the
first ruling's 16 KiB was set on an undercount).
Rows for missing, malformed and replayed nonces at 1 and 3 MiB, plus the
positive meter control. ALLOC.3 is not needed; moving the nonce check
before the verdict is declined (the MIK-8353 witness ordering is worth more
than the verdict's fixed share: about 24 KB per refusal as first measured,
about 73 KB with the blocking pool counted).

### Exclusions

The stdio rows (MIK-8400). HTTP intake's payload-proportional cost (not
caused by the verdict order): MIK-8499.

### P1a dispositions

- Shared-future growth would not show in a per-user minus plain delta
  (gpt): accepted. Each row also bounds the per-user refusal of an empty
  payload: at most 10 large allocations / 48 KiB (measured 9 / 41,168 B).
- The surfaced-name path (gpt): declined, with evidence. A direct call to a
  surfaced name is signed only under the hardened scope
  (`SigningScope::EveryToolCall`, nonce in `params._meta`, `signing.rs:212`),
  and a malformed meta nonce is refused at intake before the verdict
  (`dispatch_intake_run.rs:266`). Under the default posture the signed
  call to the surfaced name is `gateway_invoke` (`Origin::GatewayInvoke`),
  which is where the verdict precedes signing admission; the fixture
  surfaces `read`, so the verdict judges the surfaced name.
- Evidence pinning (gpt): the rows run on the PR head; the probes ran at
  40f27c404 on Spark (`spark-cargo test --lib`, default features).
- Per-kind plain baselines and an unmetered warm-up (agy): both in the rows.

## P1b: solution

Measurement rows only (no production change):
`src/gateway/router/stored_read_account_tests/http_nonce_alloc.rs`. Each of
the three refusal kinds runs one current-thread runtime on the signed
fixture with a plain backend registered beside it, warms both targets (and
spends each replayed nonce) unmetered, then meters the refusal on each
target at 1 and 3 MiB with `alloc_meter::measure_async` from the request to
the answer's bytes. Each reading pins the refusal text and the premise that
custody is read on the per-user target only. The share is per-user minus
plain, asserted against the ruled cap; the share's bytes at 3 MiB must be
within 1 KiB of 1 MiB. A positive control shows the meter sees a deep copy
of the 1 MiB payload and one known large allocation.

Isolation (superseded by the all-threads correction below): each row
re-runs itself in an isolated child process and meters every thread there
(`alloc_meter::measure_async_process_wide`). Visibility changes, all in the
test-only meter module: `measure_async` from `pub(super)` to `pub(crate)`;
`measure_async_process_wide` and `isolate` new `pub(crate)`.

How the rows bite: see the mutants under Evidence, and the plain-target
slope bound added after the final review (a payload copy in the shared
verdict loop is paid by both targets, so it cancels out of the share).

### Evidence (Spark, 2026-10-19)

- Green: the four rows pass (missing, malformed and replayed refusals at 1
  and 3 MiB, and the meter control); share measured 3 large / 11,096 B and
  13,283 B small, equal at both sizes.
- Mutants, each killed by all three refusal rows: A, a 32 KiB allocation on
  the per-user verdict's acting path (the empty-refusal bound fires:
  117,767 B, 10 large); B, the stdio caps literally (2 large): the share's 3
  large allocations fail it, which is why those caps do not apply; C, a 32
  KiB allocation on the shared verdict loop both targets pay, invisible to
  the share and caught by the empty-refusal bound.

### All-threads correction (P1b finding, gpt-20261019T014050Z-75299)

Custody work runs in `spawn_blocking` (`personal_accounts/worker.rs:179`),
so the per-thread meter missed it. The rows now meter every thread
(`alloc_meter::measure_async_process_wide`, opt-in, only inside an
`isolate`d child that runs one test). Measured share: 3 large / 11,096 B and
62,210 to 62,260 B small, identical at 1 and 3 MiB; empty-payload refusal
9 large (largest 9,456 B). `isolate` moved from
`signing_nonce_allocations_support` into `alloc_meter` (re-exported there).
Visibility: `alloc_meter::isolate` and `measure_async_process_wide` are
`pub(crate)` in a test-only module.

### Final review round 1 (gpt-20261019T024807Z-55419 SHIP-WITH-FIXES, agy-20261019T024807Z-55421 SHIP)

- A payload-dependent allocation in the shared verdict loop cancels out of
  the share and escapes the empty-payload bound (gpt, MEDIUM): accepted.
  Each row now bounds the plain target's growth per extra MiB of payload,
  at most 7,600,000 B (measured 7,202,320 B); mutant D, a copy of the call's
  arguments inside `caller_verdicts`' loop, must fail it.
- Process-wide counters are zeroed before the mode is armed (agy); the
  empty-payload refusal's text is asserted; the positive control also runs
  all-threads, and a consecutive scope must start from zero.
