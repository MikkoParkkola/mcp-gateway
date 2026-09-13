<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# MIK-6710 — Bounded audit reads with an explicit incompleteness signal

Status: design, not implemented. Scope: `src/control_plane/store.rs`,
`src/security/transparency_log.rs`, and the single production consumer in
`src/gateway/ui/control_plane.rs`.

## What this is for

The acceptance oracle (`docs/requirements/RELEASE-4.0.0-scope-tests.md:62`) is a
conjunction. All four parts must hold at once, and today none of them do for
the path a user actually hits:

| # | Conjunct | Today |
|---|---|---|
| C1 | A documented bound on how much of the log one read examines | absent — `docs/control_plane.md:100` "Current Limits" says nothing about audit read cost |
| C2 | Work proportional to the page, not to the log | fails — `read_audit` parses every line of the file |
| C3 | A filtered query that matches nothing stays bounded | fails — a rare filter scans everything, then returns an empty page |
| C4 | Truncation is signalled, never silent | fails — the caller gets a short page and no way to tell why |

### The defect, stated precisely

`bb99cb77` introduced `MAX_AUDIT_READ_BYTES = 256 MiB`
(`transparency_log.rs:64`) and applied it at the three `bounded_read_to_string`
call sites in that file (`:548`, `:566`, `:685`), covering `verify_log`,
`verify_log_inner` — and therefore `verify_log_signed` — and
`show_session_entries`.

Those are live, user-reachable CLI readers, not dead code. `run_audit_command`
(`main.rs:315`) imports both and dispatches them: `audit verify` calls
`verify_log_signed` (`main.rs:365`) and `audit show` calls
`show_session_entries` (`main.rs:404`). So bb99cb77 capped readers that real
operators reach.

The defect is therefore a gap, not a misfire: **the cap covers the CLI audit
readers and does not cover the reader `GET /ui/api/control-plane` reaches** —
`FileControlPlaneStore::read_audit` (`store.rs:741`), consumed by
`merge_store_into_snapshot` (`gateway/ui/control_plane.rs:626`), is still
uncapped, and C2/C4 fail there.

### Out of scope

- No on-disk index, sidecar, or database (see §9).
- No log rotation. Rotation does not exist in-tree and stays external; this
  design only *detects* that it happened (§3).
- No change to append, chain-hash, or verification semantics. In particular
  `recover_chain_state` and `read_last_nonempty_line` keep their current
  fail-closed behaviour and are not refactored onto the new reader's policy
  (§1) — sharing skip semantics with the write path is how a read optimisation
  becomes a chain-integrity bug.
- **No change to the CLI audit readers** (`audit verify`, `audit show`). This
  is a deliberate scope line, and it does *not* rest on those readers being
  unreachable — they are reachable (see § Today). It rests on their contract:
  `verify_log*` must walk the entire chain to verify it, so a reverse-bounded
  partial scan is meaningless there, and `show_session_entries` is a
  synchronous operator command where a 256 MiB ceiling plus a visible error is
  an acceptable answer. Neither is on the request path that serves a web
  client. Bounding `audit show` the same way `read_audit` is bounded here is a
  reasonable follow-up ticket; it is not this one.
- No edit to `docs/control_plane.md` in this commit — §8 specifies the exact
  line the implementation commit pastes there.

## Today

Read path, as it actually runs:

1. `merge_store_into_snapshot` (`gateway/ui/control_plane.rs:626`) is the sole
   production caller of the trait method. It requests a page for the UI.
2. `ControlPlaneStore::read_audit` (`store.rs:209-213`) takes an
   `&AuditFilter` and returns `Vec<ControlPlaneAuditEvent>` — no notion of a
   cursor, a budget, or an incomplete result.
3. `AuditFilter` (`store.rs:112`) carries `offset` (`:115`) and `limit`,
   clamped by `MAX_AUDIT_LIMIT = 10_000` (`store.rs:57`).
4. `page_audit` (`store.rs:334`) applies the predicates and the offset/limit
   window over an iterator. Both backends share it — in-memory at `:433`, file
   at `:771` — which is the DRY property to preserve.
5. `FileControlPlaneStore::read_audit` (`store.rs:741`) reads the audit file
   **forward, in full**, deserialises each line, maps it through
   `audit_event_from_entry` (`store.rs:310`), collects into a `Vec`, and hands
   that to `page_audit`. Cost is O(log size) for every query, including one
   that returns nothing.

Relevant existing constants and primitives:

- `MAX_AUDIT_READ_BYTES = 256 MiB` (`transparency_log.rs:64`) — the existing
  cap, applied to the CLI readers (`:548`, `:566`, `:685`). Its
  own comment tells the operator to rotate the log, and assumes the log
  "hasn't already rotated".
- `MAX_TAIL_SCAN_BYTES = 4 MiB` (`transparency_log.rs:74`) with
  `read_last_nonempty_line` (`transparency_log.rs:757`) — a **bounded backward
  scan already exists** in this file. The reverse read below is a
  generalisation of this primitive, not new machinery.
- `recover_chain_state` (`transparency_log.rs:64` region) falls back to
  `(0, "genesis")` when there is no last line.
- Both backends pass one conformance suite (`store.rs:9-13`). Anything added
  to the trait must be expressible by `InMemoryControlPlaneStore` (`:352`).

## The change

### 1. Read the file backwards, in blocks — mechanics shared, policy not

A first draft of this design said `read_last_nonempty_line`
(`transparency_log.rs:757`) "becomes the `take(1)` case" of the new reverse
reader, so the repo would hold one bounded backward scan instead of two.
**That is withdrawn, and the reason is a correctness hazard, not taste.**

`read_last_nonempty_line` is what `recover_chain_state` uses to find the tip
of the hash chain before appending. It is deliberately fail-closed: it returns
the last non-empty line *whatever state it is in*, so a torn or oversized
final record fails downstream JSON parsing and recovery refuses (its doc
comment calls this "safe failure, not a memory blowout"). The audit reader
needs the opposite policy — an unterminated tail is a concurrent append
mid-write and must be stepped over, not fatal. Unify them and chain recovery
inherits the skip: it would recover the tip from the record *before* an
unrepaired torn one and append there, and every later audit write would land
in a log that can never verify. A read-path convenience would have created a
write-path integrity bug.

So the split is:

- **Shared, mechanical.** A `ReverseBlockReader` that captures the file length
  **once** at construction, steps backwards from it in fixed 64 KiB blocks,
  carries a partial-line remainder across block boundaries, and yields
  newline-terminated lines newest-first together with each line's start
  offset. It makes no judgements: it does not skip, classify, or parse
  anything. Whether the file's final byte is a `\n` — i.e. whether the last
  record is a terminated line or a trailing fragment — is reported as a fact
  about the captured length, not inferred later by hunting for a preceding
  newline, and not re-`stat`ed mid-scan. One captured length is what makes a
  concurrent append invisible to an in-flight scan instead of shifting it.
- **Per caller, policy.** The audit reader discards an unterminated trailing
  fragment (§ What could go wrong) and applies the budget. **Chain recovery
  keeps its existing fail-closed behaviour, unchanged by this commit.**
  Re-expressing `read_last_nonempty_line` on top of the shared block mechanics
  is permitted only if it preserves that semantics exactly; it is not required
  and buys little, so the safe default for the implementation commit is to
  leave `read_last_nonempty_line` alone.

The DRY claim this design makes is therefore narrower than the first draft's:
**one implementation of "walk a file backwards in blocks", two policies on top
of it.** Skip semantics are never shared.

Newest-first is the natural order for every production query: the UI wants the
most recent events. Reading backwards means a page of 50 events costs roughly
the bytes of those 50 events, which is C2.

### 2. A scan budget: a workload-informed policy number

The reverse scan stops after `MAX_AUDIT_SCAN_BYTES` examined bytes even if it
has not filled the page. The number should read as one policy with the two
constants already in the file:

- `MAX_TAIL_SCAN_BYTES = 4 MiB` (`transparency_log.rs:74`) bounds finding
  **one** line.
- `MAX_AUDIT_LIMIT = 10_000` (`store.rs:57`) bounds how many events a page may
  contain.

**8 MiB is a policy choice informed by that workload, not a derived
guarantee.** It is the smallest power-of-two multiple of the tail-scan budget
that is in the right neighbourhood for a maximum-limit page: 8 MiB ÷
`MAX_AUDIT_LIMIT` = ~838 bytes per entry. No audit log was measured for this
document, so that number is a sizing sanity check and nothing more. The design
does **not** claim "a page of `MAX_AUDIT_LIMIT` events always completes" — it
cannot, since entry size is not bounded by anything in the schema, and a page
that does not complete is a supported outcome (`BudgetExhausted`, §4), not a
failure. Say exactly that in the constant's doc comment: why 8 MiB, what it is
not a promise of, and that raising it is a policy change and not a bug fix.

**A second, per-record bound.** `MAX_AUDIT_RECORD_BYTES` (1 MiB) caps how
many bytes the reverse reader will accumulate looking for one line's leading
newline. It exists so the failure in §3 rule 2 is detectable at all: without
it, a single unterminated multi-megabyte region is indistinguishable from "the
budget ran out", and the scan hands back a cursor that cannot advance. Scaled
so no plausible audit entry approaches it — crossing it means the file is
damaged, not that the workload grew.

**The two bounds are related, and the relationship is checked.**
`MAX_AUDIT_RECORD_BYTES * 2 <= MAX_AUDIT_SCAN_BYTES` is a **required
invariant**, not an accident of the numbers chosen above (1 MiB and 8 MiB
satisfy it with room to spare). A budget that cannot hold two records cannot
paginate: one record's worth is spent validating the cursor anchor (§3), and
if what remains cannot hold another whole record, every resumed page returns
zero events and a cursor identical in effect to the one it was given. A
64 KiB budget with a 48 KiB record cap stalls forever on a log of two 40 KiB
records. The `with_read_bounds` constructor below asserts the invariant and
panics on violation — a test that configures an unpaginable store should fail
at construction, not deadlock in a walk.

**The budget must be injectable.** Proving boundedness with the production
constant would need a fixture in the hundreds of megabytes, and
`cargo test --quiet` is a repo gate. Give `FileControlPlaneStore` a
`with_read_bounds { scan_budget, max_record }` constructor (production path
keeps both defaults) so the acceptance tests can use a 64 KiB budget over a
2 MiB log, and can trip the per-record bound with a kilobyte-scale record
instead of a 1 MiB one. Injecting only the scan budget would leave test 8
needing a megabyte fixture to reach a bound that the scan budget, being
smaller, would always hit first. This is a signature consequence, not a test
detail.

### 3. An opaque cursor, and `StaleCursor`

Pagination cannot be a byte offset in the public type: the in-memory backend
has no bytes. `AuditCursor` is opaque — the caller receives one and passes it
back unchanged; only the backend that minted it interprets it.

- File backend: an **exclusive** byte boundary plus an anchor.
- In-memory backend: index counted **from the start** of the `Vec`
  (index-from-end shifts under concurrent append).

**Exclusive boundaries, so a resume can neither repeat nor skip.** The file
cursor is `{ next_end, anchor }` where `next_end` is the **start offset of the
oldest record this page examined** — the last one the backward scan read to
completion, whether or not it passed the filter — and `anchor` is that
record's `entry_hash`. A resumed scan runs over `[0, next_end)` — strictly
older bytes. The anchored record is the boundary marker, never re-emitted and
never stepped over, and
"where the scan stopped" is a property of a record that was fully read, parsed
and hashed. That is the only kind of record a cursor is ever minted from:
**never from an unterminated trailing fragment, never from a record the scan
did not finish reading, never from a byte position mid-record.**

The anchored record is therefore **not necessarily one of `events`**. A page
whose filter matched nothing still examined records, and it anchors to the
oldest of them — which is what lets acceptance test 3 (no-match page) carry a
cursor at all. Anchoring to the last *returned* record instead would re-read
every non-matching record between it and the stop point on each resume, so a
rare-filter walk would cost O(n²) bytes while advertising a per-page bound.

The anchor must be the entry's `entry_hash`, not its counter. Rotation is
external and `recover_chain_state` restarts at `(0, "genesis")` when the file
has no last line, so a rotated-and-reopened log reuses counter values — an
offset+counter cursor can validate against the wrong entry. The hash cannot
collide that way. Note that `audit_event_from_entry` (`store.rs:310`) drops
both chain fields, so the cursor is minted from the **raw JSON line**, not
from the reconstructed `ControlPlaneAuditEvent`.

**Anchor validation is itself bounded, and its bytes are charged.** Resuming
reads the single record at `next_end` and hashes it — one record, capped by
the same per-record bound below. It is never a scan. The bytes it reads are
added to `stats.bytes_examined` and deducted from the scan budget for that
call, so the documented "at most 8 MiB per read" stays true on a resumed read
and not only on a first page.

Validation demands a **complete, newline-terminated record beginning exactly
at `next_end` that hashes to the anchor**. Anything else is
`StoreError::StaleCursor`: the file is shorter than `next_end`, absent, or
empty; there is a record there but it hashes differently; or — the case an
earlier draft's two-condition check missed — the file is longer than
`next_end` but truncation cut through the anchored record itself, so the bytes
at `next_end` never reach a newline. That last shape is why the test is
"a whole record that hashes right", not "`len >= next_end` and a hash
compare". Note that at the anchor position an unterminated or over-long region
is `StaleCursor`, not `OversizedRecord`: the question being asked is "is this
cursor still valid", and the answer is no. **`StaleCursor` is terminal for that
traversal.** The caller does not "recover" it: a hash anchor does not survive
rotation, so there is no way to locate where the old traversal had reached.
The caller must start a new traversal from the newest end and treat it as
unrelated to the first — whatever it had not yet read from the pre-rotation
log is gone, and the honest thing is to say so rather than to silently stitch
two logs into one result set. Detecting rotation is all this design can do
about it; coordinating with an out-of-band event is impossible.

**Forward progress must be guaranteed, or `BudgetExhausted` is a trap.** A
cursor that cannot advance turns pagination into an infinite loop that
advertises a bound it keeps re-paying. Two rules make progress structural:

1. Every `BudgetExhausted` cursor has a **strictly smaller** `next_end` than
   the cursor the call started from (or, for a first page, strictly smaller
   than the captured file length). The implementation asserts this before
   returning.
2. When the scan cannot complete a single line inside the budget — one record
   larger than `MAX_AUDIT_RECORD_BYTES`, or an unterminated region that never
   yields a newline going backwards — there is no complete record to anchor
   and rule 1 cannot be satisfied. That is **not** `BudgetExhausted`. It is an
   explicit `StoreError::OversizedRecord { offset }`, naming the byte offset
   the scan could not get past, so an operator gets a diagnosis instead of a
   page that silently omits everything older than the bad record.

   **Offset 0 terminates a line.** The oldest record in the file has no
   preceding newline, and it is not malformed for that reason. Rule 2 fires
   only when `MAX_AUDIT_RECORD_BYTES` is exhausted without reaching *either* a
   newline *or* offset 0. Omitting that half would make the oldest record of
   every log an `OversizedRecord` the moment a walk reached it, turning the
   last page of every complete traversal into an error.

### 4. The result type is exhaustive, not `Option`

`Option<AuditCursor>` collapses the two states C4 cares about. "Your limit
filled, click next" and "the budget ran out and this page is incomplete for
your filter" are different facts, and only the second is truncation. A caller
holding `(0 events, Some(cursor))` cannot tell "no matches in the newest
8 MiB" from "page boundary".

```rust
pub struct AuditPage {
    pub events: Vec<ControlPlaneAuditEvent>,
    pub end: AuditPageEnd,
    pub stats: AuditScanStats,
}

pub enum AuditPageEnd {
    /// The scan reached the oldest entry. `events` is the complete answer.
    Complete,
    /// The page filled. More matches may exist; resume here.
    LimitReached(AuditCursor),
    /// The scan budget ran out first. `events` is INCOMPLETE; resume here.
    BudgetExhausted(AuditCursor),
}
```

**The three ends are ordered, so the ambiguous call has one answer.** A page
can fill on the same call that drains the budget. The limit wins:
`events.len() == filter.limit` is `LimitReached`, whatever the budget did,
because a full page is a complete answer to the request that was made and the
resume cursor is the same either way (a resumed call is issued a fresh
budget). `BudgetExhausted` is reserved for a page that did **not** fill and
did **not** reach the oldest entry — the only case where the caller was given
less than it asked for. Without that precedence rule the same log and filter
could report incompleteness or not depending on where a block boundary fell.

An enum, not a bool — the repo rule on behaviour-selecting parameters, and it
makes the incompleteness invariant hold by construction:

> **Completeness invariant.** `Complete` is returned **only** when the scan
> reached the oldest entry in the log *and* every audit-kind record it
> examined parsed. Any other terminating condition either carries a cursor or
> is an error. Therefore a caller that walks cursors until `Complete` has seen
> every matching event, and a caller that stops early knows it stopped.

The "and every record parsed" half is load-bearing, and an earlier draft of
this design broke it. That draft proposed skipping a corrupt-but-complete
record, counting it, and logging a warning. Three variants of "the page ended"
cannot rescue that: a page with evidence quietly omitted would still come back
`Complete`, which is precisely the claim C4 is supposed to make unfalsifiable.

**So malformed records keep today's fail-closed handling — this preserves a
safeguard, it does not add one.** `read_audit` already returns
`StoreError::Corrupt` for an audit line that is not valid JSON
(`store.rs:757`) and for one tagged `AUDIT_KIND` that does not reconstruct
(`store.rs:763`), and the existing source already carries the reasoning in a
comment: "a malformed one fails closed rather than silently vanishing from the
view". The skip-and-warn draft was therefore a **regression of a documented,
already-reasoned safeguard**, not a missing precaution — which is the framing
to review it under, because keeping a decision the codebase already made is a
much lower bar to clear than making a new one. This design does not touch
it. Degraded
reads already have a signalling path to the client — `store_read_degraded`
(`gateway/ui/control_plane.rs:609-614`) — and a corrupt audit log is exactly
what it is for. Lines of other kinds are still skipped, as they are today;
"not ours" and "ours and broken" stay different outcomes.

**The consumer must degrade on an incomplete page, and that is an edit this
design owns.** `store_read_degraded` (computed at
`gateway/ui/control_plane.rs:609-614`, surfaced to the client at `:136`)
exists so "a client cannot mistake a failed read for an authoritative empty
result (MIK-6701)". But `merge_store_into_snapshot` (`:626`) sets `degraded`
only in `Err` arms, and its `read_audit` match (`:669-674`) assigns
`snapshot.audit_events` on **any** `Ok`. `BudgetExhausted` is an `Ok`. Ship
the store change alone and a truncated audit view renders as an authoritative
one — the same defect class MIK-6701 closed, one level down and harder to see,
because "empty" at least looks suspicious while "30 of the newest events"
looks like an answer.

So `merge_store_into_snapshot` changes with the store:

```rust
match store.read_audit(&AuditFilter::new(200)) {
    Ok(page) => {
        degraded |= matches!(page.end, AuditPageEnd::BudgetExhausted(_));
        snapshot.audit_events = page.events;
    }
    Err(e) => { /* unchanged */ }
}
```

`BudgetExhausted` only — **not** `LimitReached`. A page that fills its
requested limit of 200 is exactly what the UI asked for; today's `read_audit`
already returns the newest 200 and nobody calls that degraded. Marking every
log with more than 200 events permanently degraded would make the flag mean
"you have a busy gateway" and train operators to ignore the one signal that
should mean something. Acceptance case 9 covers this at the consumer, not at
the store — a store-level assertion cannot catch a consumer that ignores the
field.

### 5. Ordering ruling

`read_audit` returns **newest-first**, and that is documented on the trait.
Today's file backend returns append order (oldest-first) because it reads
forward; the in-memory backend returns `Vec` order. Reversing is not a
regression to hide in a changelog line — it is the ordering the UI wants and
the only ordering a bounded reverse scan can produce cheaply. The conformance
suite asserts both backends agree on it.

Two facts, kept separate on purpose:

- **The enumerated consumer is safe.** `merge_store_into_snapshot`
  (`gateway/ui/control_plane.rs:626`) is the only in-tree production consumer
  of `read_audit`, and newest-first is the order it wants. An `rg` over the
  tree found no other production consumer that depends on the current
  oldest-first order.
- **It is still a breaking change to a documented contract.** `read_audit` is
  `pub` on a `pub` trait; "no in-tree consumer breaks" is not "no consumer
  breaks". The ordering flip is an API change, gets said so on the trait, in
  the changelog, and in the migration note alongside the cursor change
  (Blast radius) — not waved away because the one caller we can see is fine.

### 6. Where the bound lives

In the **backend**, behind the trait — not in a shared helper, and not in the
caller. Only the file backend knows what a byte costs; the in-memory backend
enforces the same contract in records. `page_audit` (`store.rs:334`) stays
shared and keeps doing exactly what it does now — predicates plus limit over
an iterator it is handed — and *direction* becomes the backend's
responsibility. One predicate helper shared, one block-reading mechanism
shared (§1), no policy shared, and the file backend never
materialises the whole log.

### 7. `AuditScanStats`

```rust
pub struct AuditScanStats {
    pub records_examined: usize,
    pub bytes_examined: Option<u64>,
}
```

`records_examined` is the contract-level counter both backends can report, so
it is what the conformance suite asserts. `bytes_examined` is `None` for the
in-memory backend. The oracle says "records/bytes examined or index work";
records is the portable half.

### 8. The documented bound (C1)

C1 wants a *documented* bound, and this commit adds one file. So the line is
specified here and pasted by the implementation commit into
`docs/control_plane.md` § Current Limits (currently ending at line 106),
verbatim:

> - A single audit read examines at most 8 MiB of the audit log by default,
>   regardless of how large the log has grown. A query that reaches that budget before
>   filling its page reports the page as incomplete and returns a cursor to
>   resume from; it never returns a short page as if it were the whole answer.

Phrased as a claim an operator can rely on, which is what "documented bound"
has to mean to be worth grading.

### 9. Rejected

- **An on-disk index.** Every production query is "newest N, optionally
  filtered". A reverse scan answers that in page-proportional time with no
  second artefact to keep consistent with the chain. An index buys nothing
  until someone needs "oldest-first" or "all events in a range from 2023",
  and nobody does.
- **Keeping `AuditFilter.offset`.** A numeric offset over a log that grows
  from the end is wrong under concurrent append (page 2 re-shows rows page 1
  already showed) and cannot be made bounded — resolving offset *N* means
  walking *N* records. The cursor replaces it; see Blast radius for what that
  costs.
- **Capping with a `bounded_read_to_string`.** Reading the first 8 MiB of a
  large log returns the *oldest* events — precisely the ones no caller wants —
  and still fails C3, because the rare-filter query would return an empty page
  having examined the wrong end of the file.

## What could go wrong

| Risk | Why it happens | Handling |
|---|---|---|
| Torn trailing line | A concurrent append is mid-write when the reader seeks to EOF | The captured file length says whether its final byte is a `\n`. If not, the bytes after the last newline are an unterminated fragment: discarded, never emitted, never used to mint a cursor. Determined from the one captured length, not by scanning for a preceding newline later |
| Corrupt but complete record | Disk damage or an external writer | **Fail closed — `StoreError::Corrupt`, as today** (`store.rs:757`, `:763`). Not skipped: a skipped record would let a page come back `Complete` with evidence missing (§4). The UI signals it through the existing `store_read_degraded` path |
| Concurrent append during pagination | Appends land at the end; the cursor points backwards from a fixed offset | Cursor-based paging is stable by construction — new entries appear only on page 1 of a fresh query, never duplicated into page 2 |
| Rotation between pages | External, uncoordinated (§3) | Anchor mismatch → `StaleCursor`, which ends that traversal. The caller starts a **new** walk from the newest end and must treat it as unrelated — it cannot resume, and history it had not read is unrecoverable |
| Foreign kinds in the log | The transparency log is shared; `AUDIT_KIND` lines are a subset | Non-audit lines are filtered out *inside* the scan and count toward `records_examined` and `bytes_examined` — otherwise a log dominated by other kinds would appear to scan cheaply while doing real work |
| Empty or missing file, **no cursor** | Fresh install | `Complete` with zero events and zero stats. An empty page must be distinguishable from a failed read; that is what `Complete` asserts |
| Empty or missing file, **with a cursor** | The log was rotated or truncated between pages | `StoreError::StaleCursor`, never `Complete`. Reporting success here would claim "you have now seen everything" to a caller that lost unread history (§3) |
| A single record larger than the budget | External writer, or a pathological entry | `StoreError::OversizedRecord { offset }` — no complete record means no anchor, so `BudgetExhausted` would hand back a cursor that cannot advance (§3) |
| Incomplete page reaching the UI | `BudgetExhausted` is an `Ok`, and the consumer degrades only on `Err` today | `merge_store_into_snapshot` degrades on `BudgetExhausted` (§4). Untouched, a truncated audit view renders as authoritative — the MIK-6701 defect class one level down, and less visible than the empty view it closed |
| Budget vs. a very rare filter | A filter matching one event a year ago will never fill a page inside 8 MiB | This is `BudgetExhausted`, not a bug — the caller walks cursors. C3 asks that the query stay *bounded*, not that it stay complete |

## Acceptance

Mapped to `docs/requirements/RELEASE-4.0.0-scope-tests.md:62` conjunct by conjunct.

**Oracle helper.** `full_scan_oracle(path, filter)` — parse every `AUDIT_KIND`
line from a small fixture, reverse, apply the filter predicates, return **all**
matches. It does **not** apply the limit: a test that wants a limited oracle
takes it at the call site. Baking `take(limit)` into the helper is how the
completeness walk (case 4) would quietly grade itself against a truncated
answer, which is the one comparison it exists to prevent. Deliberately the
naive implementation, so it cannot share a bug with the thing it grades.

1. **C2 — page-proportional cost.** Two fixtures sharing the *same newest 50
   events*, one 2 MiB and one 8 MiB, each read with an unfiltered page of 50
   and a 1 MiB injected budget. Assert (a) both pages are full with `end ==
   LimitReached(_)`, (b) `bytes_examined` is **equal** across the two logs,
   and (c) `bytes_examined <= block_size + bytes_of_the_50_returned_records`.
   Equality across log sizes is what actually falsifies C2: page cost must not
   move when the log grows. The previous form — one log, a 64 KiB budget,
   assert `bytes_examined <= 64 KiB` — could not fail, because the budget *is*
   the ceiling and one 64 KiB block is the floor of any page; a scan that
   drained the entire budget after the page had filled passed it. The injected
   budget here is deliberately an order of magnitude above the expected cost,
   so draining it is visible instead of definitional.
2. **C3 — rare filter stays bounded.** The 2 MiB fixture with a 64 KiB
   injected budget, and a filter matching exactly one event near the *oldest*
   end. Here the budget-shaped ceiling is the right assertion — C3 asks that
   the query stay bounded, not that it stay cheap. Assert `stats.bytes_examined.unwrap() <=
   64 * 1024` and `end` is `BudgetExhausted(_)` — the query stopped, and said
   so, rather than scanning 2 MiB to return one row.
3. **C3 — no-match filter stays bounded.** Same fixture and budget as case 2,
   a filter matching nothing. Same byte assertion; assert `events.is_empty()` **and** `end` is
   `BudgetExhausted(_)`, which is the pair that distinguishes "nothing here"
   from "nothing found yet".
4. **C4 — completeness invariant.** Walk cursors until `end == Complete`,
   concatenate the pages in walk order, and assert the resulting **sequence is
   exactly equal** — same events, same multiplicity, same order — to
   `full_scan_oracle` over the same filter with no limit. Set-equality is not
   enough and was the first draft's mistake: a set comparison passes a walk
   that duplicates a boundary record or returns pages out of order, and the
   release criterion asks for ordered equivalence. Three walks, same assertion:
   (a) pages ending on the limit, (b) pages forced to end on a budget boundary
   by a small injected budget, so every `BudgetExhausted` resume is exercised —
   and assert the byte bound on **every** page of that walk, not just the
   first, which is what proves cursor validation is charged against the budget
   (§3) rather than being free on resume; and (c) a walk with an append landing
   between two pages — the appended event is newer than the cursor, so it must
   appear in **neither** the walk nor the oracle snapshot taken at walk start,
   and the sequences must still match exactly.

   Case (c) needs one more assertion or it is vacuous: equality to the
   start-of-walk oracle is also true of a run where the append never landed.
   So after the walk, re-run the oracle and assert the appended event **is**
   present there and is its newest element. That makes the append's arrival
   observable, and the pair — present afterwards, absent from the walk — is
   the actual isolation claim.
5. **Ordering (§5).** Small log, both backends, same filter: assert the event
   sequences are identical and newest-first. Lives in the conformance suite so
   `InMemoryControlPlaneStore` is held to it too.
6. **`StaleCursor` in all four shapes.** Take a cursor, then (a) truncate the
   file behind it so `len < next_end`, (b) replace it with a different log
   (rotation), (c) empty it, and (d) truncate it so `len > next_end` but the
   cut lands *inside* the anchored record, which no length comparison and no
   hash compare on a complete record would catch. Each re-read asserts
   `StoreError::StaleCursor` — specifically *not*
   `Complete`-with-zero-events for (c), which is the case where an empty file
   would otherwise look like a finished walk, and specifically not
   `OversizedRecord` for (d), whose question is cursor validity (§3).
7. **`records_examined` portability.** Both backends report a non-zero
   `records_examined` for a filtered query that matches nothing — the
   in-memory backend must not report zero work for work it did.
8. **Forward progress.** With an injected per-record bound below the injected
   scan budget, a log containing one record larger than that bound asserts
   `StoreError::OversizedRecord`, not a
   `BudgetExhausted` page. And across any cursor walk, assert each successive
   cursor's boundary is strictly smaller than the last — the property that
   makes a walk terminate. Separately, assert `with_read_bounds` panics when
   `max_record * 2 > scan_budget` (§2) — an unpaginable store must fail at
   construction.
9. **The consumer degrades on an incomplete page.** At
   `merge_store_into_snapshot`, not at the store: a double returning
   `BudgetExhausted` must make the function return `true` and the response
   carry `store_read_degraded` (the existing test-module store double at
   `control_plane.rs:1558` already provides the shape). Positive control: a
   double returning `LimitReached` with a full page must **not** degrade, or
   the flag means "busy gateway" instead of "incomplete view" (§4). A
   store-level assertion cannot catch a consumer that drops the field, which
   is exactly the defect this case exists for.
10. **Malformed records fail closed, whatever the filter says.** Three
    fixtures: (a) an `AUDIT_KIND` line that is not valid JSON, (b) one that is
    valid JSON but does not reconstruct into a `ControlPlaneAuditEvent`, and
    (c) case (b) where the record would have been *excluded by the filter
    anyway*. All three assert `StoreError::Corrupt` — (c) is the one that
    matters, because an implementation that tests the filter before parsing
    would pass (a) and (b) while silently dropping evidence, which is the §4
    invariant restated as a test.

## Blast radius

`gitnexus_impact` on `ControlPlaneStore::read_audit`, upstream: **MEDIUM
risk, 7 impacted symbols, all at d=1, exact match.** Breakdown:

- **3 implementations** to update: the trait default/definition
  (`store.rs:213`), `InMemoryControlPlaneStore` (`:430` region), and
  `FileControlPlaneStore` (`:741`).
- **4 in-file tests**, plus the `FailingStore` test double, which needs the
  new return type.
- Process participation: `cross_process_audit_append_stays_verifiable`
  (proc_96, proc_212); module cluster `Control_plane`.

**The graph under-reports.** The sole production consumer,
`merge_store_into_snapshot` (`gateway/ui/control_plane.rs:626`), does **not**
appear in the impact result — it was found by `rg`. Recording that is the
honest version of the CLAUDE.md impact-analysis requirement: the tool was run,
and it missed the one caller that matters. Verify by grep before editing.

**So the implementation commit touches two files, not one.**
`gateway/ui/control_plane.rs` is not merely "a caller that must compile": its
degradation logic changes, because `BudgetExhausted` is an `Ok` that today's
`Ok` arm would render as an authoritative view (§4). A commit that lands the
store change and leaves the consumer compiling-but-unchanged ships the
regression rather than the fix.

**This change spends another criterion's evidence.** `AuditFilter.offset`
(`store.rs:115`) is `pub` and re-exported at `src/control_plane/mod.rs:22`.
`read_audit_honors_offset_limit_and_filters` (`store.rs:1003`) constructs it at
`:1016` and `:1027`, and those tests are tagged **MIK-6685.STORE.6**. Removing
`offset` rewrites them, so state the ruling up front rather than discovering it
at grading time.

**`offset` is deleted outright. There is no deprecated no-op fallback.** An
earlier draft offered one; it is withdrawn as the worst of the options. A
no-op `offset` keeps a `pub` field that existing callers still set and that
silently stops meaning anything — `filter.offset = 50` would hand back page 1
while the caller believes it holds page 2. Wrong pages returned quietly are
strictly worse than a compile error, and the field would not preserve the
original acceptance test's semantics either, so it buys neither compatibility
nor evidence.

So this is an explicit, documented API change: `AuditFilter.offset` is
removed, `read_audit` returns `AuditPage`, callers migrate from offsets to
cursor walks, and the trait doc plus the changelog say so in those words.

**And the superseded requirement is named, not quietly re-labelled.**
MIK-6685.STORE.6's offset-paging conjunct is **superseded by MIK-6710**: its
original evidence (`read_audit_honors_offset_limit_and_filters`,
`store.rs:1003`, constructing `offset` at `:1016` and `:1027`) no longer
exists after this change and must not be cited as if it still passed. Its
replacement — that paging honours limit and filters, cursor-walked rather than
offset-indexed — is carried by
`read_audit_honors_cursor_limit_and_filters`. The release ledger should record
the supersession explicitly; a criterion whose evidence was deleted and
re-pointed without a note is how a green row ends up meaning nothing.

**Brief claim, now checked.** The brief cited "filter tests exist at
`src/security/transparency_log.rs:1031`". Line 1031 is
`fn show_session_filters_correctly` — it logs three invocations across two
session ids, calls `show_session_entries(path, "alpha")`, and asserts two
entries come back. It is a real filter test, but of a **different filter
surface**: session-id filtering inside the transparency-log reader, not the
`AuditFilter` predicate set that `page_audit` (`store.rs:334`) applies for
`read_audit`. It therefore gives no coverage for C3, and the C3 acceptance
tests below do not build on it.
