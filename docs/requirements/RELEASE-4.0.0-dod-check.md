# DoD check — MCP 2026-07-28 support (branch `feat/mcp-2026-protocol`)

**Date**: 2026-08-29 · **Base**: `main` at 3.5.0 (`cdd52622`) · **Commits**: 43
**Requirements**: `docs/requirements/RELEASE-4.0.0-requirements.md`
**Plan**: `docs/requirements/RELEASE-4.0.0-test-plan.md` · **Design**: `docs/design/RFC-0061-…md`

Gates were **run**, not asserted. Where a verdict is N/A it carries its reason, because an N/A
without one is a skipped gate wearing a label.

---

## §3 Static checks — PASS

| Gate | Command | Result |
|---|---|---|
| Linter | `cargo clippy --all-targets -- -D warnings` | 0 warnings |
| Formatter | `cargo fmt --check` | clean |
| Compiler | `cargo build` | clean |
| Secret scan | private-key / API-key patterns over the branch diff | 0 |

## §4 Testing — PASS

- **4,430 tests passing across 44 binaries.** Zero failures.
- **161 new acceptance-criterion tests**, one per criterion, each named for the criterion and asserted in its polarity.
- **41 doc-tests pass.**
- One test is `#[ignore]`d with its reason: `ac_discover_1_advertises_the_target_revision` asserts the gateway advertises 2026-07-28, which it deliberately does not until the switch is on. Scheduled, not suppressed.

### Falsification — every non-trivial control was made to fail

The rule this release ran on: a control you cannot make fail is not a control. Fourteen probes, each
failing **only** the rows that observe it:

| Control | Probe | Rows that failed |
|---|---|---|
| Era classifier, legacy side | default flipped to modern | 4 |
| Era classifier, modern side | positive-evidence arms removed | 2 |
| Era cache | probe moved outside the lock | 1 (the concurrent one) |
| Warm-start schedule | `initial_gap` 2s → 5s | 1 — the existing tests, being relative, all stayed green |
| Era discriminator | absence read as malformed | 2 |
| Era discriminator | any `_meta` read as modern | 2 |
| Header validation | check removed from the HTTP path | 3 |
| `cacheScope` | filtered list declared public | 3 |
| Continuation binding | check made to always succeed | 2 |
| Consumed ledger | check-and-consume split in two | 1 — the racing one; a sequential pair passes either way |
| In-flight routing | holder ignored | 1 |
| In-flight table | capacity check dropped | 1 |
| Anomaly detection | unobservable collapsed to a neutral score | 1 |
| Lifecycle reaping | reap made to reclaim nothing | 2 |
| Task settling | settled task allowed to reopen | 1 |
| `application_type` | field dropped | 1 |
| Trace context | shape validation removed | 1 — **after** the test was fixed; see below |
| Registration body | — | the inline copy was found and removed before it could pass |

**Two probes found holes in my own tests rather than in the code**, which is the point of running
them:

- The trace-context probe **passed** at first: every malformed case I had written was caught by the arity check, so the hex-and-length validation was untested. Adding six right-arity/wrong-content rows made the probe fail as it should.
- The registration-body test asserted a helper while `register_client` still built its own body inline. The test would have stayed green while the wire never changed — the same defect class that shipped an invented discovery document earlier in this branch.

## §5 Change safety — PASS

Every modern behaviour has a **legacy regression row** beside it: session header still sent, `ping`
still served, `initialize` byte-identical against a captured golden, no `resultType` or `_meta` added
to a 2025 result, headers not required of a client that never sent one, disconnect cleanup still
firing. The legacy path is the thing most likely to break, so it is the thing most tested.

## §7 Documentation — PASS

CHANGELOG `[Unreleased]` written; README version claims corrected; requirements, plan and design
updated as decisions were made rather than afterwards. Six fixes that shipped **unlisted in 3.5.0**
were also written up.

## §8 Security — PASS

- `cargo audit`: **0 vulnerabilities**, 425 dependencies. One `yanked` warning, identical on `main` — pre-existing and not introduced here.
- `#![deny(unsafe_code)]` holds; no dependency added (the continuation envelope uses `ring`, already vendored and previously unused).
- NFR.SEC.4's fixtures exist: tamper, expiry, replay, wrong principal, wrong request, key rotation, unknown key, garbage input — each failing closed.

## §11 Stop-the-line — none open

No failing test, no known user-visible defect, no security regression. **Not deployed**, and not
claimed to be.

---

## Requirements coverage — 89 of 89 addressed

| Area | Requirements | State |
|---|---|---|
| 3.1 Discovery | 7 | Implemented |
| 3.2 Stateless | 10 | Implemented |
| 3.3 Headers | 6 | Implemented |
| 3.4 Results & errors | 4 | Implemented |
| 3.5 Cacheability | 7 | Implemented |
| 3.6 MRTR | 10 | Implemented |
| 3.7 Controls | 8 | Implemented |
| 3.8 Identity | 5 | 4 implemented, 1 verified as pre-existing (IDENT.3) |
| 3.9 Subscriptions | 4 | Modelled; wiring noted below |
| 3.10 Authorization server | 3 | Implemented |
| 3.11 Exploitation | 5 | Implemented |
| NFR | 20 | See below |

## What is honestly NOT finished

Stated plainly, because a DoD report that hides its gaps is worth less than no report.

1. **Two protocol surfaces are modelled and unit-tested but not yet wired to the transport**: `subscriptions/listen` (the types, opt-in and tagging exist; the stream itself is not served) and the tasks extension (the task model exists; no `tasks/get` endpoint). Both sit behind `modern_protocol`, which is off, so neither is reachable by a client — but neither is complete either. **This is why the switch must stay off.**

2. **NFR.PERF.1 and NFR.PERF.2 are unmeasured.** Latency budgets need a benchmark this branch has not run, and header-first routing was deliberately *not* implemented for that reason: NFR.PERF.2 says a performance change without a number does not ship. Routing on headers remains a stated opportunity, not a claim.

3. **NFR.COMPAT.4 is partly met.** Every requirement is verified in the role the gateway plays for it, but the conformance matrix crossing *both* roles × transports × all five revisions does not exist. Increment 1's era-detection rows cover the client role for discovery; the rest is server-side.

4. **U6 is closed by the conformance matrix; U1 is open and blocks nothing here.** U1 asks which revisions our clients actually speak, and its own row says it blocks *only* narrowing the compatibility window — which §7 puts explicitly out of scope for this release. Listing it as a gap overstated it, and this corrects that. U7 and U8 were resolved during the work and are recorded.

5. **Review carries one vendor, and did not run against the final code.** The operator set single-vendor review (codex/gpt) for this session. GPT reviewed the design (13 findings, 4 CRITICAL, all folded in) and the test plan (3 findings, all folded in). Four subsequent review runs died at zero bytes under concurrent load, so **increments 1–10 carry self-review and falsification only**. That is a gap in the process, not a passed gate.

## Verdict

**The scope of `RELEASE-4.0.0-requirements.md` is implemented and its gates pass**, with the five
exceptions above named rather than absorbed. The release is **not** ready to tag: item 1 must be
finished, item 5 must be discharged against the final diff, and items 2 and 3 are §9 acceptance
criteria that have not been met.

`server.modern_protocol` defaulting to **off** is what makes that an honest state to be in rather
than a broken one.
