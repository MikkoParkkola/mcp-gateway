# DoD check — MCP 2026-07-28 support (branch `feat/mcp-2026-protocol`)

**Date**: 2026-08-29 · **Base**: `main` at 3.5.0 (`cdd52622`) · **Head**: `c4f4781a`
**Requirements**: `RELEASE-4.0.0-requirements.md` · **Plan**: `RELEASE-4.0.0-test-plan.md`

Gates were **run**, not asserted. Where a verdict is N/A it carries its reason, because an N/A
without one is a skipped gate wearing a label. Where a gate was run against an *earlier* commit than
the head, that is said in the same line rather than rounded up.

## Verdict, first

**The 2025 path is done and shippable. The 2026 core path has no unbuilt piece left; what remains is
gated on production topology, a tasks extension this release deliberately does not advertise, and
one parsed protocol field with no consumer.**

Eight independent review rounds produced **42 findings, a later scope audit added a forty-third, and
the confirmation pass on this document found two more that had never been written down. Thirty-eight
are closed**, each with a probe that makes its own fix fail and only its own fix. Of the seven recorded
open, two are gated on multi-replica production, two are conformance gaps in a tasks extension this
release does not advertise, one is a parsed protocol field with no consumer, one misreports whether a
config reload needs a restart, and one is test hygiene. Seven is what is currently recorded open,
which is not the same claim as seven being all there are. The first five are unreachable by a client
while the switch defaults off. The reload finding is not a protocol path and the switch does not
bound it; the last exists only in a test.

An earlier revision of this paragraph said two of them could not be verified against a specification
page returning 404. That was a wrong path rather than a missing document: the page was found and
fetched, and both findings are now stated against it. The claim is corrected here rather than left
standing beside the body that contradicts it.

Two findings were closed by **removing** a mechanism rather than repairing it, because in both cases
what existed was worse than nothing: retry fields merged into tool arguments while forwarding the
client's own sealed envelope, and a `tasks/get` that answered every handle with a fabricated
success. Both are recorded below as decisions.

The single most valuable result of these rounds was not a defect but a **process finding**: the
conformance matrix compared the code against a requirements document written from the same
incomplete reading of the specification, so both agreed and it went green over four wire-format
errors. Three protocol areas had been implemented without ever fetching their own specification
pages.

## §3 Static checks — PASS at head

| Gate | Command | Result |
|---|---|---|
| Linter | `cargo clippy --all-targets -- -D warnings` | 0 warnings |
| Formatter | `cargo fmt --check` | clean |
| Secret scan | private-key / API-key patterns over the branch diff | 0 |

Run on the Linux build host, not this laptop: a local guard halted every `cargo` command at 4.6 GB
free disk. Clearing another session's build cache was not this session's to decide, so verification
moved to the machine with room for it — which is where heavy builds belong regardless. Only this
branch's own debug artifacts were removed locally, which is housekeeping the rules already assign to
the change that created them.

## §4 Testing — PASS at head

- **4,463 tests passing across 45 binaries, 0 failing** — measured at the head commit with `--no-fail-fast`, so no binary was skipped because an earlier one failed.
- **41 doc-tests pass.**
- **23 tests are `#[ignore]`d.** Twelve are doc-test examples and ten are pre-existing integration tests needing Docker or a live API. **One is this branch's**: `ac_discover_1_advertises_the_target_revision`, which asserts the gateway advertises 2026-07-28 — deliberately false while the switch is off. The previous revision of this document said "one test is ignored" and meant one of *mine*; as written it was a false claim about the suite, and this corrects it.

### Falsification — every control was made to fail, and two could not be

The rule this release ran on: a control you cannot make fail is not a control. Thirty-one probes
across the branch. The fourteen from earlier increments are unchanged; the thirteen run against this
round's security repairs are below, each failing **only** the rows that observe it.

| Control | Probe | Rows that failed |
|---|---|---|
| `Payload` redaction | `Debug` derived again | 1 |
| Routing under contention | `route` back to `try_lock` → `Gone` | 1 |
| Explicit completion | `complete` releases nothing | 2 |
| Ledger capacity policy | evict the soonest live entry again | 1 |
| Keyring construction | duplicate key ids allowed | 1 |
| Client-facing error | internal cause leaked into the message | 1 |
| Mint budget | budget never exhausts | 2 |
| Mint budget | ceiling clamp removed | 1 |
| Mint budget | counter never advances | 3 |
| Envelope bound, opening | size check removed | 1 |
| Envelope bound, minting | size check removed | 1 |
| Envelope bound, value | bound lowered below real backend state | 13 — it is load-bearing on the ordinary path |
| Mirrored field selection | `resources/read` reads `name` again | 2 — the helper row and the router row |
| Decoy-name bypass, end to end | name-then-`uri` fallback restored in the handler | 1 |
| Repeated header line | first occurrence taken, as before | 1 |

**A probe that reported less than it found**, worth recording because it nearly passed for a
methodology reason rather than a code one: running two test binaries in one `cargo test` invocation
stops after the first one fails, so the second never runs and its rows are silently absent from the
result. One probe appeared to leave the router row untouched. Re-run against that binary alone, it
failed it — 19 passed, 1 failed. **A falsifier must name one binary, or pass `--no-fail-fast`**;
otherwise an unrun test reads exactly like an insensitive one.

**Two probes exposed holes in the controls rather than in the code**, which is the point of running
them:

- The **mint budget shipped with no control at all**. The first probe disabled it and nothing failed. The bound was 2^32 envelopes, which no test can reach, so it was untestable by construction. It now has a clamped builder and a remaining-budget reader, and three probes that fail.
- The **constant-time comparison has no honest failing row, and this is recorded rather than papered over**. Reverting `redeemable_by` to the short-circuiting slice comparison passes all rows — verified by running it, not assumed. A unit test cannot observe timing. The behavioural row beside it was renamed to `a_wrong_binding_of_any_length_is_refused_identically`, which is what it actually proves; the timing property itself is assured by reading the code, and that is a weaker assurance, stated as one.

## §5 Change safety — PASS

Every modern behaviour has a **legacy regression row** beside it: session header still sent, `ping`
still served, `initialize` byte-identical against a captured golden per revision, no `resultType` or
`_meta` added to a 2025 result, headers not required of a client that never sent one. The legacy
path is the thing most likely to break, so it is the thing most tested.

## §8 Security — PASS on tooling, with open findings below

- `cargo audit`: **0 vulnerabilities**, 425 dependencies. One `yanked` warning, identical on `main`.
- `#![deny(unsafe_code)]` holds; no dependency added.
- Nine security findings from review were closed in this round; two remain open and are listed below.

## §12 Review — one vendor, eight rounds, findings recorded

The operator set single-vendor review (codex/gpt) for this session, so the dual-vendor gate is
**deliberately not met** and this is a known, authorised deviation rather than a passed gate.

Reviews are chunked per module. An earlier attempt sent the whole 2,893-line diff and died at zero
bytes five times; the cause was payload size, diagnosed by a minimal smoke test returning in seconds.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 1 | `src/protocol/continuation.rs` | 7 — 3 CRITICAL, 2 HIGH, 1 MEDIUM, 1 LOW | SHIP-WITH-FIXES |
| 2 | repairs to round 1 | 1 CRITICAL (BEFORE-PRODUCTION) | **SHIP** |
| 3 | `src/gateway/router/handlers.rs` | 10 — 1 CRITICAL, 7 HIGH, 2 MEDIUM, all CERTAIN | SHIP (none gated NOW) |

**A process failure worth recording**: round 1's findings were first read from a truncated tool
output showing only the last three. Work proceeded on three findings while four — including two
CRITICAL — sat unread in the authoritative run file. They were found only when that file was opened
directly. The lesson is the one already written down: read the source, not a rendering of it.

### Round 1 and 2 — disposition of all eight

Nine repairs, each with a probe above, re-checked by the vendor that raised them (**SHIP**):

| Finding | Repair |
|---|---|
| CRITICAL — ledger evicts a live entry at capacity | refuses instead, reclaiming only entries past a deadline |
| CRITICAL — `for_test()` ships a publicly known key in production builds | constructor deleted; tests build their own keyring |
| CRITICAL — process-local ledger across replicas | **open**, gated BEFORE-PRODUCTION, documented in the module |
| HIGH — `open` decodes an unbounded client token | 8 KiB bound checked before decoding, enforced at both ends |
| HIGH — `Payload` derives `Debug` over sealed state | hand-written redacting `Debug` |
| MEDIUM — `route` maps lock contention to `Gone` | awaits the lock; the old code contradicted its own comment |
| LOW — binding comparison short-circuits on length | compares SHA-256 digests of both sides |
| (round 2) CRITICAL — mint budget resets on restart | **open**, gated BEFORE-PRODUCTION; the doc comment that overclaimed a per-key guarantee was corrected to say it bounds one process |

Four improvements were also taken: per-key mint budget, explicit completion release, duplicate-key-id
rejection, and one generic client-facing refusal message.

## Findings by area

The totals are stated once, at the top of this document; this section only says where the closed
findings fell and what each area got wrong. The ones still open are named under "What is honestly
NOT finished".

| Area | Closed | What was wrong |
|---|---|---|
| Continuation envelope | 6 | live replay window at capacity; a public constructor shipping a known key; an unbounded client token; sealed state in `Debug`; lock contention answered as a lost exchange; a length-leaking comparison |
| Request path | 9 | a header-declared modern request classified legacy; retry fields merged into tool arguments; `resultType` overwritten; a destructive call running unconfirmable; a session minted per stateless request; the modern revision missing from discovery; notifications answered before validation; a session header on modern refusals; a fabricated `tasks/get` success |
| Mirrored headers | 3 | a decoy `name` validated while `uri` executed; a repeated header line reduced to its first value; malformed retry fields accepted inconsistently |
| Era classifier | 5 | capabilities present but unusable; modern-only keys read as legacy; a partial document read as a discovery document; a failed probe cached as legacy; an attacker-sized subtree copied per request |
| Subscriptions | 5 | filter read at the wrong level; `resourceSubscriptions` read as a boolean; a minted id instead of the request's own; the tag written where no client looks; a valid empty filter refused |
| Security controls | 3 | an anomaly check that could not observe and allowed anyway; lifecycle deadlines that accumulated and reclaimed live callers; a non-atomic score-and-update |

### Two were closed by removing the mechanism, not repairing it

Both are recorded as decisions rather than omissions, because in both cases the thing that existed
was worse than nothing:

- **Multi-round-trip retry forwarding.** The fields were merged into the tool `arguments` object. The specification makes them siblings of `arguments`, so a backend read them nowhere — and a tool with an argument of either name had it silently overwritten. Worse, the `requestState` forwarded was the **client's own envelope**, which `continuation.rs` exists specifically to keep from being passed onward. Forwarding correctly means unsealing the gateway's envelope and sending the *backend's* state, which needs the keyring reachable from request state and a retry parameter threaded to the dispatcher. Neither exists, so a retry now fails visibly instead of corrupting a call.
- **`tasks/get`.** It answered every handle with a `not_found` **success** — a status absent from the protocol's task model, reported as though a lookup had happened against a store that does not exist. It now returns method-not-found, which is true. The extension's own specification has since been fetched and the gap inventory below is stated against it.

## Round 8 — the repairs reviewed, and what that found

The fixes above were themselves submitted for review, split in two so neither payload was large
enough to die silently.

| Material | Findings | Verdict |
|---|---|---|
| the protocol modules | 2, both BEFORE-PRODUCTION | **SHIP** |
| the request path and security controls | 6, one gated NOW | SHIP-WITH-FIXES |

**The NOW-gated finding was the pattern this branch keeps producing, turned back on its author.**
`SessionLifecycle` — the registry meant to reclaim per-caller state — had its deadline map carefully
repaired here, and **nothing in production ever calls it**. Verified: nothing constructs it outside
its own module, and `track` and `reap` have no callers. It is pre-existing rather than introduced
(added in `ba268ca9`, already dead on `main` at the base commit), so the wire-or-delete decision
belongs to a human and is filed as **MIK-7291** rather than absorbed into this change.

What *was* closed here is the leak it would have prevented: the anomaly detector's identity map now
carries a ceiling. A stateless caller never disconnects, because it never connected, so there is no
disconnect event to reclaim on even in principle.

Three further repairs to the repairs:

- **The stateless anomaly identity was still the display name.** It is operator-configured, two API keys may share one, and every anonymous caller presents the same one — so scoring on it lets one caller poison another's history. The handler now passes a validated credential key and passes nothing at all for an unauthenticated caller. A `session_owner()` helper one function away already carried this exact reasoning in its own comment.
- **A rule could downgrade the fail-closed refusal.** Refusing an unscoreable call raised a High finding, which an ordinary Allow rule could soften. Refusal is now forced before rule resolution.
- **Session suppression was too narrow**, recognising only an exactly-supported modern version, and a duplicated `MCP-Protocol-Version` header could hide a modern declaration behind a legacy one.

**Two slips of my own, both caught immediately by the compiler**, and worth recording because they
share one cause: a text substitution matched two functions where one was meant. The parameter added
to `check_request` landed on `check_response` too, and a forced-block landed in the wrong function
entirely. Verifying each batch rather than at the end is what turned both into build errors instead
of shipped defects.

### Round 8's own controls, and the two that were not controls

Seven probes against the round-8 repairs. Five failed only their own rows on the first attempt.
The other two are the reason this step exists:

| Control | Probe | Rows that failed |
|---|---|---|
| Unscoreable calls refused | blind no longer forces a block | 1 |
| Identity is real or absent | empty string used as an identity | 2 |
| Modern era declared broadly | only exactly-served versions count | 1 |
| Identity map bounded | ceiling removed | 1 |
| Duplicate header refused | resolved to the first value instead | 1 |

- **The bound probe found a deadlock in the fix it was testing.** The eviction path held a shard guard from the map's iterator and then asked the same shard for a write, so the thread blocked against itself. It could only run once the map reached 100,000 entries, which no ordinary test does — the row written to prove the ceiling existed is the only thing that reached it, and it hung for six minutes rather than failing. Fixed by binding the victim in its own statement so the guard drops first.
- **The duplicate-header row was not a control at all.** It passed whether or not the fix was present, because its body declared itself modern and the request was therefore refused by the duplicate check *inside* the modern block — a different mechanism from the classification the row is named for. Rewritten to use a body with no protocol metadata, which is the only shape where misreading the header actually sends the request down the legacy path. It now fails when reverted.

A hung test also taught something about reading a build: `cargo test` with a live test binary and no
compiler children emits nothing, so a log filtered for `^test result` looks identical to a job that
died. That was misread twice here before anyone looked at the process tree.

## What is honestly NOT finished

Seven findings are recorded open: six numbered here, and one test-hygiene item after them.
Findings 1 to 5 are unreachable by a client while `server.modern_protocol` defaults off. Finding 6
is in config reload, which the switch does not bound. The seventh is unreachable because it lives in
a test, not because of the switch.

1. **The consumed-continuation ledger is process-local.** A second replica would let one continuation be spent once on each. Gated BEFORE-PRODUCTION; needs a shared atomic insert-if-absent store.

2. **The mint counter is process-local.** It bounds envelopes sealed by *this process* since it started, not by the key over its life, so a restart resets it. That is a real ceiling on a single runaway process and not the per-key guarantee the NIST bound describes. Gated BEFORE-PRODUCTION; the module says so in as many words.

3. **The task model is short of the specification, now that the specification has been
   read.** The 404 was a wrong path, not a missing document: tasks moved out of the core
   revision into an extension, and the page lives at
   `https://modelcontextprotocol.io/extensions/tasks/overview` (fetched 2026-08-29). The
   core schema for 2026-07-28 carries no `Task` type at all — only the capability key
   `io.modelcontextprotocol/tasks` under `capabilities.extensions`. Against that source,
   `src/protocol/tasks.rs:21-28` defines three statuses where the specification defines
   five: `input_required` and `cancelled` are absent, and with them the whole mid-flight
   input exchange (`tasks/update`, `inputRequests`) and cooperative cancellation. The
   `Task` struct at `:32-38` carries neither `ttlMs` nor `pollIntervalMs`; the paragraph
   below corrects which of the two the schema actually requires. Nothing verifies that the
   client declared the extension in its per-request capabilities before a task is
   returned, which the specification states as a MUST.

   That paragraph read the overview page, and the overview is not the schema. Against
   `https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks` (fetched
   2026-08-30) the normative `interface Task` requires **`createdAt: string` and
   `lastUpdatedAt: string`** — a reviewer claim this document previously dismissed, wrongly
   — declares **`pollIntervalMs?: number` as optional**, not required, and names a **third
   method, `tasks/cancel`**, alongside a `notifications/tasks` notification. Neither the
   third method nor the notification appears in `ADDED_IN_2026_07_28`, so the constant that
   documents what the revision added is itself short by one.

   MIK-7311's acceptance criteria were derived from the overview and inherit these errors.
   They are corrected against the schema before that ticket is worked, because an
   implementation built to this inventory would have shipped two missing timestamps and a
   wrongly-required poll interval.

4. **The failed-task payload is a string where the specification says a JSON-RPC error.**
   `src/protocol/tasks.rs:37` holds `error: Option<String>`; the specification's terminal
   states put the final `result` on `completed` and the JSON-RPC `error` object on
   `failed`. A client parsing the error would get a message where an object is required.

5. **The per-request `logLevel` is parsed and never read.** `classify_request` lifts
   `io.modelcontextprotocol/logLevel` into `RequestFields::log_level`
   (`src/protocol/meta.rs:196-199`), and no consumer exists: the only other `log_level`
   symbols in the tree are the CLI's own flag and the legacy global `LoggingLevel` behind
   `logging/setLevel` (`src/gateway/meta_mcp/protocol.rs:279`), which is an unrelated
   mechanism and is itself refused on the modern path. Requirement STATELESS.7 is a
   MUST-NOT — do not emit `notifications/message` for a request that declared no level —
   and it holds only because the modern path emits none at all. Nothing positive was built,
   so the requirement is satisfied vacuously and the field is dead on the parse side.

   The key's *presence* is load-bearing and stays: `meta.rs:150` counts it as an era
   declaration, so a request carrying `logLevel` and omitting the required pair is
   malformed rather than quietly legacy. Only the lifted value has no reader.

   The vacuous satisfaction is a standing trap for the next change: the moment anything on
   the modern path emits a `notifications/message`, STATELESS.7 becomes a live MUST-NOT and
   the parsed level has to be read. Whoever wires log delivery closes this finding in the
   same change or breaks the requirement silently.

   Same disposition as `gateway_declares()` below, for the same reason: the repair is to
   consume it, and consuming it means building per-request log delivery, which is a feature
   this release did not set out to add. Recorded rather than repaired. Deleting the field
   was rejected — it is the protocol's own key, and the next release that wires log
   delivery needs the parse it would remove.

6. **Restart detection for `HOME` is wrong in both directions.** A reload reports
   `restart_required` whenever startup recorded a `~` entry and the overlay assigns `HOME`, changed
   or not. `changed_startup_env_keys` filters every other key on whether its resolved value actually
   differs from startup, then pushes `HOME` past that filter on presence alone:
   `if env.env_paths().has_tilde_entry() && evaluated.overlay.assigns("HOME")`
   (`src/config_reload/mod.rs:1311-1312`). The sequential `HOME` + `~/…` layout that branch
   exists to serve therefore makes every later reload report a restart it does not need.

   It errs in both directions, and the second direction was missed when this finding was first
   written down. `HOME` is not in `IMPLICIT_STARTUP_ENV_KEYS` (`:1279-1283`), and it reaches the
   value filter only if the config happens to name it as a secret reference. So an overlay that
   *removes* a HOME assignment startup had — leaving the recorded `~` entries to resolve
   somewhere else on a restart — pushes nothing and is compared against nothing. The common case
   over-reports and is merely noisy; the removal case under-reports and is the one that matters.
   Gated BEFORE-DEPLOY.

   This document does not prescribe the repair, having got it wrong once: comparing the overlay's
   final HOME against startup's is not sufficient. `~` resolves at the point each env file is
   applied, and `EnvPaths` keeps those paths in application order
   (`src/config/env_overlay.rs:45-48`), so moving an unchanged `HOME` assignment across a tilde
   entry changes where that entry resolves while every value comparison still reports equal. What
   the check has to be sensitive to is the HOME in force *at each tilde-spelled entry*, against what
   was in force there at startup — assignment, removal and reordering alike.

   **Repaired.** The rule is now a comparison of the HOME actually in force —
   `startup.resolve("HOME") != evaluated.overlay.resolve("HOME")`, still conjoined with
   `has_tilde_entry()` — in place of the presence check. A re-stated HOME resolves equal and
   reports nothing; a removed assignment falls through to the process environment, resolves
   different, and reports. The paragraph above overstated what defeats a value comparison: the
   reordering case it describes is an edit to the `env_files` list, which the restart-field diff
   already reports as `env_files` (`src/config_reload/mod.rs:571-572`, inside
   `pending_restart_fields`, not `compute_diff`), so it never needed this rule to
   catch it. Nothing resolves `~` a second time, so `RecordingHome`'s one-resolution assertion
   (ENVFILE.19e) still holds. New rows ENVFILE.19g (re-stated HOME reports nothing) and
   ENVFILE.19h (removed assignment reports HOME) were written first and observed failing on the
   presence check — 19g reporting `HOME` with nothing moved, 19h omitting it with everything
   moved. `config_reload` is 79/79.

   **Closure re-check found the layer is wrong (2026-08-30).** Both vendors returned
   SHIP-WITH-FIXES on the repair commit and converged on one defect: comparing the *final* HOME
   still misses a HOME that changes before a later `~` entry and is restored by a file after it —
   the paths move, both finals compare equal, and the `env_files` list is untouched, so nothing
   reports. Verified at source: `~` is substituted with the home in force at that point in the
   sequence (`src/config/mod.rs:456-466`, `expand_home` at `:475-484`), and the only consumer of
   overlay HOME is a later env-file entry — `fallback_config_path` reads `dirs::home_dir()`
   directly (`:268`). The same reading condemns the tests, including one that predates this
   change: a HOME assignment inside the *sole* `~/x.env` entry moves nothing, because that entry
   was expanded from the process home before its own assignments applied. ENVFILE.19h asserts a
   restart for exactly that, and so does ENVFILE.19e, whose premise sentence — "a `HOME`
   assignment against a `~` entry moves where a restart would read" — is false whenever the
   assignment sits in the last, or only, tilde entry. The rule being encoded is not "did HOME
   change" at any layer; it is *would a restart open different files than startup did*. That
   question is answered by the recorded paths, not by HOME, and it needs an owner decision
   because the design deliberately forbids resolving `~` a second time.

   **Closed conservatively; the semantics question stays open.** ENVFILE.19i was written first and
   observed failing on the value comparison — two entries, the first moving HOME and the file the
   second names restoring it, finals equal, `HOME` absent from the report. The rule now fires on
   either an assignment or a value change beside a tilde entry
   (`src/config_reload/mod.rs:1325-1332`), which is statable in one line: *a restart notice about
   HOME may be early, never absent*. This is a deliberate design event, not a repair: ENVFILE.19g
   now asserts the notice it previously asserted away, because nothing available at reload can tell
   its harmless case apart from 19i's real one without re-expanding `~`, which the design forbids.
   19h keeps its assertion and loses its false premise — its sole entry relocates nothing; it is
   the value branch's test, not the relocation case. `config_reload` is 80/80; lib 3762/3762;
   clippy and fmt clean.

   What remains for the owner is one question, and it is about behaviour rather than mechanism:
   *should setting HOME in an env file be able to move where a later env file is looked for?*
   If no, the coupling goes and `~` always means the real home directory — the branch, the
   `so_far` parameter on `HomeResolver`, and the ENVFILE.19 family all delete, and the rule
   becomes one an operator never has to think about. If yes, the check has to be path-based
   ("a restart is required when it would open different files than startup did"), which means
   relaxing ENVFILE.19e's one-resolution fixture. Either answer is its own change with its own
   design review; neither gates 4.0.0, because the conservative rule cannot be silent.

One further finding is open and gates nothing: the OAuth metadata tests release an ephemeral port
before rebinding it — once inline at `src/oauth/metadata.rs:322-324` and once in the `free_addr`
helper at `:332-337` — so a concurrent process can take it in between.
Graded LOW / UNLIKELY / LATER. It is test hygiene rather than a shipped defect, recorded because it
was found and never written down.

### Disposition of 3 and 4 — the extension ships not implemented

4.0.0 does not advertise the tasks extension, and the code already behaves that way.
`ExtensionSet::gateway_declares()` (`src/protocol/extensions.rs:52-56`) is the only site
that names `Extension::Tasks`, and it has no caller outside its own module, so the
capability key never reaches an advertised capabilities object. `tasks/get` and
`tasks/update` appear only in the documentation constant `src/protocol/meta.rs:240`, which
lists what the revision added; no dispatcher routes either method. No client can negotiate
the extension and none can reach the partial task model.

That is currently true by omission rather than by decision, and this records it as the
decision. It also makes `gateway_declares()` an unwired public symbol, which §2 does not
allow: recorded here rather than repaired, because the repair is to call it, and calling it
is exactly what this disposition declines to do until the implementation is conformant. It
stays in the tree as the entry point that implementation will use.

Chosen over making it conformant before the tag. Conformance is two statuses, the whole
mid-flight input exchange, cooperative cancellation, three required fields, an error payload
change and a per-request capability check — real construction on a branch that had already
converged, and it reopens review rounds on everything it touches. Shipping the subset with
a note was rejected outright: a client reading the extension identifier expects five
states, and an honest release note does not stop that call from breaking.

**This disposition was put to the operator and no answer came back within the window.** It
is the reversible branch — a later release turns the capability on once the implementation
matches the specification, and nothing shipped in 4.0.0 has to be withdrawn to do it. One
line overturns it.

Owner of the conformant implementation: **MIK-7311**, filed before the tag, carrying seven
acceptance criteria and a fail-fast on the capability check. **MIK-7312** owns gaps 1 and 2.

### Closed since: `subscriptions/listen` now streams

The handler returned an acknowledgement that closed, so a client reading it as a
live subscription waited on notifications nothing would send. It now returns the
stream itself: the acknowledgement is its first event, each notification the
client opted into follows on the same body, and every one carries the
subscription id the specification defines as the listen request's own JSON-RPC
id. Falling behind closes the stream rather than delivering a gap, because the
revision removed resumability and a client cannot learn what it missed.

Open streams are bounded by a permit held for the life of the body, so a caller
that opens streams and walks away costs something finite. A count checked before
subscribing would be raced past by concurrent callers; the permit is the
admission.

Four tests drive it over the transport rather than calling the registry
directly. Falsified by changing the published notification's method: exactly the
delivery test failed, 20 of 21 still passed — the control observes the thing it
claims to, and does not stand in for the other three.

### Two fixes have no runtime control, and that is stated rather than hidden

- The **constant-time binding comparison**: reverting it passes every row, verified by running it. A unit test cannot observe timing. The behavioural row beside it proves wrong bindings of any length are refused identically; the timing property is assured by reading the code, which is weaker.
- The **atomic score-and-update**: the probe for it did not compile, so the control is unproven. A race needs a deterministic repro harness, which this does not have.

---

## Rounds 4–7 — and the root cause they expose

Four further module reviews returned **eighteen more findings**, every one gated NOW.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 4 | `meta.rs` + `era.rs` (the era classifier) | 5 — 2 HIGH, 3 MEDIUM | SHIP-WITH-FIXES |
| 5 | `headers.rs` + `mrtr.rs` | 3 — 2 CRITICAL, 1 HIGH | SHIP-WITH-FIXES |
| 6 | `subscriptions.rs` + `tasks.rs` + `extensions.rs` | 7 — 4 HIGH, 2 MEDIUM, 1 LOW | SHIP-WITH-FIXES |
| 7 | the security controls | 3 — all HIGH | SHIP-WITH-FIXES |

### The root cause: three protocol areas were built without their specification

This is the finding that matters, and it was found by checking a reviewer's claim at source
rather than by accepting it.

**The subscription model is wrong in four independent ways, and the specification says so
directly.** Fetching `/specification/2026-07-28/basic/patterns/subscriptions` — a page that was
**never cached during implementation** — confirms all four:

| What the code does | What the specification says |
|---|---|
| parses filters at the `params` root | they nest under `params.notifications` |
| treats `resourceSubscriptions` as a boolean | it is an array of URI strings: `["file:///project/config.json"]` |
| mints a fresh `SubscriptionId` | *"The value is the JSON-RPC ID of the `subscriptions/listen` request"* |
| tags `_meta` at the notification root | the example puts it under `params._meta` |

The scratchpad holds seven cached specification pages. **There is no subscriptions page and no
tasks page**, and `spec-caching.md` is **0 bytes** — a fetch that returned nothing and was never
noticed, because nothing checked. Three protocol areas were implemented from the changelog and the
index rather than from their own pages.

**Why the conformance matrix did not catch this**: it compared the code against the requirements
document, and the requirements document was written from the same incomplete reading. Both agreed,
so the matrix went green. A conformance check that never reaches the specification is checking a
copy of its own assumptions — which is the same defect class as a fixture that reimplements the
production code it is meant to test, recorded earlier in this branch.

### What was checked and found sound

Not everything the reviewers raised survived contact with the source, and saying so is part of the record:

- **`cacheable.rs` is correct.** It defaults to `private`, which is the conservative direction: the specification confirms `public` responses "may be shared between callers even if the Result is coming from an authenticated endpoint". Its doc comment cites the schema, so despite the empty cached page it was not written from nothing. One real gap: the specification requires the same `cacheScope` across all pages of a paginated list, which is not implemented — though a uniform `private` default satisfies it by accident rather than by design.
- **The tasks findings are VERIFIED and the earlier dismissal was wrong.** They were first recorded as unreachable because the index link 404s, then dismissed against the *overview* page. The normative schema lives at `https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks` (fetched 2026-08-30), and against it every disputed claim holds: `interface Task` declares `createdAt: string` and `lastUpdatedAt: string` as required, and all five statuses. Dismissing a correct finding against the wrong page is the same failure this document already records for three other protocol areas — the second occurrence, and the reason the gap inventory below now cites the schema line it rests on.

### Two controls that failed open — both closed, re-verified at head

- **Closed.** `src/security/firewall/mod.rs:355-386` no longer turns an unobservable
  anomaly check into "no finding". `Observation::Unobservable` now sets `anomaly_blind`,
  logs the reason, and pushes a `Severity::High` `SequenceAnomaly` finding, which the
  caller treats as a block (`src/security/firewall/mod.rs:1147`). A detector with no
  identity to key on refuses instead of waving the call through.
- **Closed, with a stated residual.** `src/gateway/session_lifecycle.rs:75-82` records that
  a key re-tracked between reaping's removal and `fire_cleanup` still has its handlers
  fired, and says why: closing it needs an ownership model this module does not have. The
  module is not reached from production at all, tracked as MIK-7291, so the residual is
  bounded by that.

The path in the original finding, `firewall/mod.rs`, does not exist; the file is
`src/security/firewall/mod.rs`.

## The decision, which is the operator's

The 2025 path is unchanged, fully tested and shippable. `server.modern_protocol` defaults **off**,
and that is the isolation for findings 1 to 5 — no client reaches a modern protocol path while the
switch is off. It does not cover the other two. Finding 6 is in config reload, which any
authenticated operator can trigger regardless of the switch; the port race exists only in tests.

Finding 6 has since been repaired rather than accepted, on the operator's instruction that anything
fixable gets fixed and that the rules left standing should be ones any user can state. The rule that
replaced it is one sentence: *a `~` in an env-file path, plus a `HOME` that differs from startup,
means a restart is required.* With it closed, nothing outstanding is reachable while the switch is
off, and the port race is test-only. Two real options remain:

1. **Ship 4.0.0 as the legacy-safe groundwork**, modern path documented as preview with the findings listed. The default-off switch is what makes this honest.
2. **Hold the tag** until the six numbered open findings above are closed and re-reviewed.

Removing the modern path is *not* a third option worth its cost: the switch already achieves the
isolation removal would buy.

What changed since this recommendation was first written is the size of option 2. It was
"twenty-six findings, several of them systematic". It is now the numbered findings above and the
test-hygiene item after them, and this paragraph does not restate them or claim they are all of
them: three revisions tried, two drifted within a round, and the confirmation pass then found two
that had been omitted since the code rounds. What can be said is what was checked — no construction
remains on the transport itself, the `subscriptions/listen` stream having landed, and nothing on the
list waits on a source that cannot be reached, the tasks schema having been read.

## Rounds 9–17 — the confirmation pass on this document

The last nine rounds reviewed this document rather than the code, both vendors on identical
material, scope declared in the prompt each time. Rounds 15 to 17 reviewed this table.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 9 | the tasks gap inventory rewritten against the schema | 1 MEDIUM (gpt), 1 improvement (grok), the same one | SHIP-WITH-FIXES |
| 10 | the repair to round 9 | 2 MEDIUM (gpt), 2 improvements (grok), the same passage | SHIP-WITH-FIXES / SHIP |
| 11 | the closing paraphrase deleted | no finding at any gate; 1 improvement (gpt), 2 (grok) | SHIP / SHIP |
| 12 | two omitted findings added to the inventory | 4 (gpt), 1 + 2 improvements (grok); both vendors on the same false claim | SHIP-WITH-FIXES |
| 13 | the repairs to round 12 | 2 + 1 improvement (gpt); grok found none | SHIP-WITH-FIXES / SHIP |
| 14 | the repairs to round 13 | 1 improvement (gpt), 1 (grok) | SHIP / SHIP |
| 15 | this history table itself | 2 LOW bookkeeping errors (gpt); grok found none | SHIP-WITH-FIXES / SHIP |
| 16 | the repairs to round 15 | 1 LOW (grok); gpt found none | SHIP / SHIP-WITH-FIXES |
| 17 | one clause deleted | none | **SHIP** / **SHIP** |

Rounds 12 to 14 are the same pattern one level down. Round 12 asked whether the document's open
inventory matched the reviews that produced it, and it did not: a MEDIUM config-reload finding and a
LOW test-hygiene one had never been written down, while round 11 had shipped a sentence calling the
list complete. Adding them introduced a fresh false claim — that the `HOME` branch errs only in the
safe direction — which both vendors caught, and then a wrong prescribed repair, which one did. The
safe-direction sentence was corrected, because the finding underneath it is real and had to be
stated accurately. The completeness assertion and the prescribed repair were deleted outright.

Rounds 9 and 10 both found their defect in the previous round's repair, in the same paragraph:
a prose summary of the numbered open-findings list, which fell out of date each time the list
was corrected. Round 11 deleted the summary instead of correcting it a third time, and both
vendors returned SHIP. The pattern is the one the repair protocol names — three rounds spent
patching a mechanism that the first round could have removed.
