# Finding: MIK-7387 silently broke the stdio elicitation guard

## Verdict
The two red rows (ac_mrtr_7a / ac_mrtr_7b) are NOT test flakiness and NOT a broken
admission cap. They are a real regression introduced by the MIK-7387 concurrent-dispatch
package, and the source comment at src/gateway/meta_mcp/invoke.rs:2247 predicted it
verbatim before it happened.

## Evidence chain (all verified at source / in CI output)
1. CI run 35248322170 census, printed by the tests themselves:
   - 7a (65 calls): elicitation/create = 58, plain results = 7, -32003 = 58
   - 7b (1025 calls): elicitation/create = 58, plain results = 966, -32003 = 11, -32000 = 2
   Prompts pinned at 58 across a 16x load change; plain results scale with load.
2. Collection ended "the budget expired" (30s) in both, so the child went quiet. This is
   not a clipped stream.
3. The fixture backend is stateless and deterministic: any tools/call WITHOUT
   inputResponses returns input_required plus an elicitation
   (tests/mik_7212_mrtr7_stdio_acs.rs:147-172). There is NO fixture path that answers a
   first call plainly. Therefore every plain `result` frame is gateway-manufactured.
4. The config written by the test carries no idempotency section, and read_only_tools
   defaults to empty ("An omitted section permits no exceptions",
   src/config/features/idempotency.rs:7). The idempotency cache is definitively not engaged.
5. Admission permits are moved into the spawned task and dropped on every exit path
   (src/gateway/server/mod.rs:2645). No permit leak.
6. src/gateway/meta_mcp/invoke.rs:2270 has an EMPTY match arm for
   BridgeError::Delivery{DeliveryError::NoSession}. Falling through leaves `interim` set,
   so the ask goes out as a MINTED CONTINUATION (invoke.rs:2358) instead of a bridged
   elicitation, i.e. a plain result frame carrying a requestState envelope.
7. The comment at invoke.rs:2247 states the invariant that made this safe: stdio could
   never reach that arm, because stdio_caller_context declares Declared::NONE and `plan`
   refuses before `ask`, landing as Refused and never as NoSession. It then names the
   lift, "MIK-7387 the only thing that lifts it", names the missing test row
   "MIK-7212.WIRE.10", and warns "Until it lands, an edit to either half breaks this
   silently."

## Mechanism
MIK-7387 made stdio dispatch concurrent. Concurrent dispatches now reach the bridge
without the guaranteed pre-refusal the single-reader design relied on. Those that do not
win a live session fall through the NoSession arm and are answered with a continuation
envelope rather than asking the client. About 58 win the race and elicit; the remainder
are silently downgraded.

## Why this matters beyond the red rows
The downgrade is silent and client-visible: a caller that asked for a bridged
elicitation receives a continuation envelope instead. The invariant is currently pinned
by NO test (the code says so), which is why CI surfaced it as a confusing count mismatch
rather than as a named failure.

## Open decision for the operator
MIK-7387 is parked In Review awaiting an include/exclude call. This evidence is directly
decision-relevant: including MIK-7387 in 4.0.0 requires the NoSession arm to be handled
for the concurrent stdio caller AND the MIK-7212.WIRE.10 row written. Excluding it leaves
both red rows moot.
