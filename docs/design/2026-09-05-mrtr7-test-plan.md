# MRTR.7 wiring — test plan

Companion to `docs/design/2026-09-05-mrtr7-bridge-wiring.md`. Written before any
test code, to be reviewed **as a plan**: every acceptance criterion gets a case
or a stated reason it has none, and every named case must be able to fail.

## What the existing rows already cover, and what they cannot

`tests/mik_7212_mrtr7_bridge_acs.rs` holds 21 tests: 18 acceptance rows of the
MRTR.7 block in `docs/requirements/RELEASE-4.0.0-test-plan.md`, and 3 that check
a fixture is what the parser reads. Named rather than counted, because a count
cannot show an omission and this mapping does — rows 312, 323 and 324 are absent
here, and they are the three stdio rows carried, `#[ignore]`d, by
`tests/mik_7212_mrtr7_stdio_acs.rs` against MIK-7387.

| row | test |
|---|---|
| 308 | `ac_mrtr_7a_elicitation_params_reach_the_client_whole` |
| 309 | `ac_mrtr_7a_a_method_outside_the_closed_set_is_refused_unsent` |
| 310 | `ac_mrtr_7a_wire_methods_and_id_prefixes_match_the_admitted_set` |
| 311 | `ac_mrtr_7a_an_undeclared_variant_is_not_asked_under_an_empty_slice` |
| 313 | `ac_mrtr_7b_an_accepted_answer_is_filed_under_the_backend_key` |
| 314 | `ac_mrtr_7b_a_decline_fails_the_call_as_a_refusal_by_a_person` |
| 315 | `ac_mrtr_7b_an_error_reply_fails_the_call_as_a_client_refusal` |
| 316 | `ac_mrtr_7b_an_unusable_accept_fails_as_malformed` |
| 317 | `ac_mrtr_7b_content_violating_the_requested_schema_is_forwarded_unchanged` |
| 318 | `ac_mrtr_7b_the_retry_bound_cuts_off_after_three_retries` |
| 319 | `ac_mrtr_7b_the_request_budget_is_checked_before_a_batch_is_sent` |
| 320 | `ac_mrtr_7b_an_unanswered_prompt_ends_its_round_not_the_call` |
| 321 | `ac_mrtr_7b_answered_rounds_are_ended_by_the_aggregate_deadline` |
| 322 | `ac_mrtr_7b_a_batch_of_three_answers_arrives_in_one_retry` |
| 325 | `ac_mrtr_7a_a_session_declared_capability_is_asked_with_no_slice` |
| 326 | `ac_mrtr_7a_sampling_and_roots_each_complete_an_accepted_round` |
| 327 | `ac_mrtr_7b_cancel_unnamed_action_and_no_member_fail_distinguishably` |
| 328 | `ac_mrtr_7ab_a_bridged_round_is_counted_without_the_answer_body` |
| — (fixture) | `ac_mrtr_7b_the_shipped_bounds_are_the_documented_ones` |
| — (fixture) | `ac_mrtr_7b_the_asking_fixture_is_what_the_parser_reads` |
| — (fixture) | `ac_mrtr_7a_the_capability_fixture_declares_what_it_names` |
| 312 | `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` — in `mik_7212_mrtr7_stdio_acs.rs`, `#[ignore]`d, MIK-7387 |
| 323 | `ac_mrtr_7a_bridged_request_follows_the_initialize_response` — same file, `#[ignore]`d, MIK-7387 |
| 324 | `ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames` — same file, `#[ignore]`d, MIK-7387 |

`tests/mik_7212_mrtr7_bridge_acs.rs` drives `InputBridge::run` through trait
fakes and receives the capability value as a **parameter**. That is the right
shape — no fixture reimplements a capability store, so none of those rows can
pass by testing its own scaffolding. It is also the limit: every one of them
begins after the decision the wiring change actually makes. Nothing in that file
observes which value the caller passed, where it came from, or whether the caller
exists at all. All 18 stay green whether or not this change ships.

So the delta below is entirely at the **call site**, and one row is end-to-end.

## Rows

| AC | criterion | case | level | type | how it can fail |
|---|---|---|---|---|---|
| `MIK-7212.WIRE.1` | A modern request that declared at `initialize` but declares nothing about the asked capability in its own `_meta` is still refused | drive `invoke` with a well-formed modern request — `_meta` carrying `protocolVersion` and a `clientCapabilities` object that omits the capability the backend asks for (`src/protocol/meta.rs:542-549`) — session declaration present; assert MRTR.9 refuses and nothing is asked | integration | negative | an unconditional merge makes it bridge; the assertion is on the refusal AND on zero client frames. An **absent** `_meta` would not classify as `Modern` at all, so the fixture must declare — declaring nothing is `Declared::NONE` on a Modern shape, which is the condition this row is about |
| `MIK-7212.WIRE.2` | A legacy request with a session declaration is bridged | same call site, legacy shape, session declaration present; assert the client is asked | integration | positive | a shape check inverted, or the session store never read, leaves the client unasked |
| `MIK-7212.WIRE.3` | A legacy request with no session declaration is refused | legacy shape, empty session; assert refusal | integration | negative | fail-open on an absent declaration bridges instead of refusing |
| `MIK-7212.WIRE.4` | A modern request reads only its own `_meta` | modern shape, `_meta` declares sampling, session declares elicitation. **Two invokes, not one mixed batch**: `undeclared()` refuses the whole interim on its first undeclared entry (`src/protocol/mrtr.rs:302-311`), so a batch mixing the two can only ever show the refusal. Invoke one: backend asks sampling — assert a **continuation is minted and zero client frames are sent**, because a modern caller that declared the capability on this request is served the continuation, not bridged. Invoke two: backend asks elicitation — assert the MRTR.9 refusal | integration | boundary | two independent mutants die here. The merge leaking into the modern path admits elicitation (invoke two). A wiring that bridges *every* capable caller, modern included, passes WIRE.1-3 and dies on invoke one, whose assertion is on the continuation and the silent client — never on "the client was asked" |
| `MIK-7212.WIRE.5` | Every backend attempt is accounted exactly once, including bridge retries, and governance is re-checked before each | one call that bridges and retries twice; assert the backend was invoked three times and that each sink — invocation metrics, error budget, cost tracker, spend record — carries three, not one. **Second fixture, same row**: a budget sized to admit the first attempt and reject the second; assert the retry never reaches the backend, records no spend, **and that the governance refusal is what the caller receives** | integration | positive | the pre-factoring code counts only the first attempt — this row fails against today's tree, which is what makes it load-bearing. Accounting alone would pass a wiring that bills three attempts an operator's limit forbade; the budget fixture is the half that refuses to. The third assertion is what makes the fixture unfalsifiable by silence: the two negatives alone are also satisfied by a wiring that swallows the rejection and answers with a fabricated success. There is no trait change behind it — `BackendInvoker::invoke` returns a `Value`, not a `Result` (`src/gateway/input_bridge.rs:299-302`), and the bridge returns that value to the caller verbatim (`src/gateway/input_bridge.rs:366-369`), so the refusal already has a channel and the row asserts its shape |
| `MIK-7212.WIRE.6` | The retry bound is enforced against the accounted attempts, not a separate counter | drive past the bound; assert refusal and that accounting agrees with the attempt count | integration | boundary | two counters drifting apart passes a bound check while over-billing |
| `MIK-7212.WIRE.7` | A declaration dies with its session | capture at `initialize`, **bridge once successfully under that declaration** so the capture is proven live, then DELETE the session; assert the same request under a reused identifier is now refused | integration | negative | a declaration outliving its session grants inherited permissions — assert on the **refusal**, not on a map being empty, or the row passes against a store nobody reads. Without the successful bridge first, a capture that never worked at all satisfies the refusal too: the row would go green on a no-op |
| `MIK-7212.WIRE.8` | The whole path composes over real HTTP | one test: `initialize` declaring a capability, a **legacy-shaped** tool call (a modern one would be served a continuation and never exercise the bridge at all), a backend that asks, delivery over live SSE, the answer POSTed back and correlated, the backend retried with it, then session cleanup | system | end-to-end | every fake in rows 1-7 is replaced by the production transport; this is the only row that can fail because an adapter was never constructed |
| `MIK-7212.WIRE.9` | A successful bridge retry is judged on its own result | a backend that asks once and then succeeds; assert the idempotency key is settled as completed, the response is returned, and the settled result is cached — an equivalent follow-up call carrying a *different* idempotency key and the same response-cache key is served without a further backend invocation, since the cache gate at `src/gateway/meta_mcp/invoke.rs:1769` is the second consumer of the same verdict. The two assertions are separate on purpose: a follow-up reusing the settled key would be answered by the idempotency entry and would pass without the cache gate running at all | integration | regression | `src/gateway/meta_mcp/invoke.rs:1475` computes `stopped_to_ask` from the *first* result, so a passing test here proves the verdict is re-derived after the retry — against today's tree the key stays unsettled and the row fails |
| `MIK-7212.WIRE.10` | An initialized stdio caller is still refused | stdio session declares elicitation at `initialize`, backend asks; assert the MRTR.9 refusal returns **inside a 2-second `tokio::time::timeout` wrapping the call** — an order of magnitude under the bridge's 30-second prompt timeout, so a regression that reaches the prompt path fails the deadline rather than eventually returning the right answer — no client request is sent, and no retry occurs | integration | regression | this row is not `#[ignore]`d: the refusal is stdio's behaviour until MIK-7387 lands, and a transport-scope regression would turn it into a 30–120s stall |
| `MIK-7212.WIRE.11` (also satisfies `MIK-7388.BRIDGE.2`) | The production `ClientChannel` strands no pending entry when the prompt's outer timeout cancels the send | spawn `send_request` against a **live** peer that accepts the frame and never answers — a `NoSession` or an inner timeout would empty the map on its own and pass this row vacuously; wait until the pending map holds the id (precondition asserted under a 5s deadline, not slept for), `abort()` the task, **await the `JoinHandle` until it reports cancelled**, then assert the map is empty for that id |  integration | negative | an impl that inserts into the map and awaits without an RAII guard passes every other row here and fails only this one — neither the success nor the error path runs on cancellation, so the entry leaks for the life of the connection. Mirrors `cancelled_request_does_not_strand_pending_entry` (`src/transport/stdio.rs:815`), including its live-peer staging and its join-after-abort — inspecting the map while the aborted task is still unwinding is how correct cancellation-safe code fails in CI |

`WIRE.8` is the row the reviewers asked for, and the only one that proves the
*composed production HTTP round*. It is not the only row that needs the call site
to exist: `WIRE.2`, `WIRE.5`, `WIRE.6`, `WIRE.7` and `WIRE.9` all fail without one
(the present-tree table below says so row by row). What none of rows 1-7 can do is
prove the wiring holds through the real HTTP surface rather than through a
hand-built harness.

## Riskiest assumption, and the order the rows are written in

**Riskiest assumption (G10):** that the production `ClientChannel` implementation
can be built over the existing HTTP pending-sampling surface
(`src/gateway/proxy.rs:76,105,128,153`) *and* be cancellation-safe, without
reshaping that surface. Impact is high — every other row assumes the type exists
— and uncertainty is the highest of any assumption here, because no impl exists
to inspect. Second: that the call site can distinguish shapes at the point where
the bridge is reachable.

**Cheapest-first execution order (G11):** the riskiest assumption is also the
cheapest to falsify, so it goes first.

1. `WIRE.11` — cancellation contract, direct against the new type, no HTTP fixture.
   Fails or compiles; either answer is bought in minutes.
2. `WIRE.1`-`WIRE.4` — call-site shape and declaration gate, fakes only.
3. `WIRE.5`-`WIRE.7`, `WIRE.9` — accounting, bound, budget, lifecycle.
4. `WIRE.10` — stdio refusal, bounded.
5. `WIRE.8` — full HTTP composition, the most expensive fixture in the set, last.

Running `WIRE.8` first would spend the largest fixture on the assumption that is
already assumed by every row above it.

## The two questions a plan review answers

**Does every acceptance criterion have a case, or a stated reason it has none?**
Yes, with one qualifier. The eleven `MIK-7212.WIRE.*` rows above each carry a case.
The criteria this change does not add a case for are named in the section below,
each with its reason, not skipped. The qualifier is gone: the twenty-one existing
MRTR.7 rows in `tests/mik_7212_mrtr7_bridge_acs.rs` are now mapped by name in
the table above, not accounted for by count, so a duplicate or an omission
inside that set shows. That mapping is what turned up the three stdio rows
living in another file.

**Can each named case actually fail?** Yes — the rightmost column of the table
is that answer, per row, and it is the reason the column exists.

An earlier draft of this paragraph claimed `WIRE.1` and `WIRE.3` fail against
today's tree. **They do not, and both reviewers said so.** Today nothing bridges,
so every row whose assertion is *a refusal* passes on the unwired tree — and
passes for the wrong reason. Corrected, per row, on the present tree:

| row | present tree | what a green tells you |
|---|---|---|
| `WIRE.1`, `WIRE.3`, `WIRE.10` | **pass** | nothing. They also pass on a correct shape-conditional merge, and on no merge at all. They fail only if this change merges the session declaration into the Modern path, or fail-opens Legacy — which is the regression they exist to catch, not a baseline they establish |
| `WIRE.2` | **fails** | this is the red half of the gate: a legacy caller with a session declaration must be *asked*, and no call site asks anyone today |
| `WIRE.4` | passes (both invokes) — same absent call site: nothing bridges, so invoke one's interim is sealed into a continuation (`mint_continuation`, `src/gateway/meta_mcp/invoke.rs:376`) with no client frame sent, and invoke two is refused under MRTR.9 | not a baseline falsifier — a mutant killer. It dies against a wiring that bridges every capable caller, which nothing else here catches |
| `WIRE.5`, `WIRE.6`, `WIRE.9` | **fail** | attempts counted once, the bound read off a second counter, the verdict computed from the first result (`src/gateway/meta_mcp/invoke.rs:1475`) |
| `WIRE.7`, `WIRE.8` | **fail** | no bridging call site exists, so neither the successful pre-DELETE bridge nor the composed HTTP round can happen |
| `WIRE.11` | does not compile | the production `ClientChannel` type does not exist yet |

Marked **I**, not V: the outcomes are derived from the absent call site
(`src/gateway/meta_mcp/invoke.rs` reaches `InputBridge` from no production path), not from
a recorded run — the tests do not exist yet, which is the point of writing the
plan first. `cargo test --quiet -- mik_7212_wire` on the first red commit is the
command that converts this column to V, and its output belongs in that commit
message. A claimed red that nobody ran is exactly the evidence this table was
wrong about once already.

`WIRE.11` is stated differently again on purpose: the
type it drives does not exist yet, so today it does not compile. Once it does,
it fails against the obvious implementation — insert into the map, then await —
and only an RAII guard turns it green, which is the property being pinned rather
than the absence of the type. No row's fixture constructs the condition it then asserts, and no
row is staged so that its assertion is true before the production code runs —
the failure mode `test-plan-honesty` exists to catch. `WIRE.8` is the one row
whose failure would be an environment failure as easily as a defect, because it
drives real HTTP; it is kept because nothing else proves the path composes, and
its diagnosis cost is the price of that proof.

## Criteria with no case, and why

- **MRTR.7a/7b on legacy stdio** — no drivable surface in this change. The three
  rows exist in `tests/mik_7212_mrtr7_stdio_acs.rs`, are `#[ignore]`d against
  MIK-7387, and become that package's acceptance evidence.
- **The `input_bridge.rs` reply-projection defect** (`:454`) — confirmed, out of
  scope for a wiring change, and disposed in the design's finding table. It is
  **MIK-7388**, which merges before this wiring, and its acceptance case belongs
  to that ticket rather than to this plan. The two findings once counted
  alongside it (`:433`, `:409`) died at requirement rows 320 and 308; the design
  says where.
- **MIK-7388's stranded-pending-entry defect** (`:430`) — *not* absent from this
  plan. It was filed against `input_bridge.rs`, which holds no pending state; the
  obligation belongs to the `ClientChannel` implementor this change creates, per
  the trait's cancellation contract at `src/gateway/input_bridge.rs:268-287`.
  `WIRE.11` above is its case, and the design records the call.

## What this plan does not claim

That rows 1-7 prove the feature works. They prove the **decision** is right at
the call site. `WIRE.8` is the only row that proves the wiring, and a plan that
shipped rows 1-7 alone would report full coverage of a disconnected bridge.
