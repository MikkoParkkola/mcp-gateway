# Transparency append recovery for MIK-7407

Status: draft design; no production logger repair implemented. This is a required
dependency of MIK-7407.RESPONSE.5 and CONTROL.3. The original response-firewall
change identity remains
`0c61dddc348533b5ca66db71f5535c9ac7c42aa644d84be750193c569eef0c07`.

## Problem and measured evidence

The real Spark gateway binary
`43a4b5ec439d0c96f9e48a02edaff13d3f4291131835c30b18646133fda18ce1`
successfully served a counted backend call while a child-only RLIMIT_FSIZE cap
allowed only 64 bytes of its transparency append. Its actual audit CLI verified
the one-entry baseline, then rejected the incomplete JSON. After removing the
cap, the next call succeeded but the log contained duplicate counter 2. A
separate restart after the partial write logged an open error, continued without
transparency logging, and still served the next call.

The exact source is `TransparencyLogger::append_core`: `BufWriter` retains the
unwritten suffix after `flush` fails, while the in-memory counter advances only
on success. The next append flushes the old suffix followed by another entry
with the same counter. `open` currently parses the last nonempty line without
recovering an unterminated fragment.

The actual probe, two case logs, result JSON and SHA manifest are preserved in
`scope-review/firewall-response-review/logger-partial-write-*`. The successful
probe's isolated remote directory is
`/home/mikko/codex/mcp-gateway-v4-logger-probe-_s3ovvz2`. Its first unsuccessful
fixture attempt is retained separately: Python reset SIGXFSZ before exec. The
corrected run explicitly verifies the child's ignored-signal mask before
applying the limit. No conclusion relies on the failed fixture.

## Definition of Ready

The value is preserving trustworthy audit history through a representable disk
failure, without converting an optional invocation log failure into a client
request failure. Root explicitly ratified this as a release blocker under the
existing ticket and granted the logger's design, tests and implementation hunks.
There is no new product feature, tool surface, external service or dependency.

G0–G3 follow the security-mandate path: the mandate is MIK-7407.RESPONSE.5 and
CONTROL.3 under the operator's full 4.0 delivery instruction; the event deadline
is before the 4.0 release gate can close. NPV/ROI ratios are N/A, not invented.
The planning allocation is 320,000 input and 60,000 output tokens: 30,000/12,000
for implementation and test drafting, 260,000/40,000 for independent staged
reviews and repairs, and 30,000/8,000 for context changes and receipt work.
At the canonical $15/$75 per million planning rates this is $9.30. This is a
reasoned allocation including review/context overhead, not measured billing or
an operator-approved spending cap. The measured corrupt-chain/restart-loss
evidence makes this a required current release dependency, rather than a
speculative optimization competing for backlog priority.

The parent [response-enforcement design](2026-09-06-firewall-response-enforcement.md)
records the independently verified B1–B5 tracker fields, stable RESPONSE.5
criterion and ranked release dependency, canonical named-gate applicability,
existing Rust/primitives/license choices and owner seams. Those unchanged gates
are inherited, not reset. The new risks and planned checks below amend that
record: recovery changes persistence behavior, so preservation, write ordering,
real locking and bounded reads must pass their own gates. Quarantining the exact
uncommitted suffix before removing it preserves an operator restoration source;
this does not migrate or rewrite completed history or add an irreversible
format change. No separate ADR or operator decision is inferred from this
reversible repair.

Target ownership: `src/security/transparency_log.rs`, focused recovery tests,
this design and its test plan. Shared finalizer and public adapter acceptance
remain separate staged dependencies. Reuse `crate::fs_lock::ExclusiveFileLock`
and existing hash/HMAC helpers; preserve other workers' edits and the existing
test-only generic append-failure hook.

The cheapest falsifier is the already executed real-file partial-write probe.
After implementation it must show no duplicate append in the poisoned process,
then a verified chain after a safe restart repair. A recovery test that only
returns an injected error before writing cannot close this criterion.

## FOR and OUT

FOR: failure state of an append-only transparency writer; bounded restart
recovery of an incomplete final frame; serialization of append/recovery across
cooperating Unix processes; preserving prior complete records and existing
hash/HMAC formats; exact error/no-success behavior for callers; actual OS fault
and restart evidence.

OUT: a new durable receipt claim, changing invocation/client error handling,
rewriting or re-signing completed historical records, external replication,
log rotation automation, new signing-key history storage, or claiming that a
bounded restart scan verifies an entire arbitrarily large audit trail. The
existing full `audit verify` remains the historical verification operation.
Unsupported-platform cross-process locking does not acquire a new guarantee.

## Proposed contract

1. A complete newline-framed entry is the unit of on-disk append. Existing
   entry fields, canonicalization, HMAC format and ordinary return types remain.
   `append_event_synced` retains its stronger `sync_all` behavior. A returned
   error does not assert that zero bytes reached the file.
2. Remove the redundant per-entry `BufWriter`: the current code flushes after
   every entry. Serialize one complete line and write it through the actual
   `File`. This avoids an uncommitted buffered suffix being replayed implicitly.
3. If the write or required durability operation fails, mark that logger
   instance poisoned before releasing its mutex. Return an error and reject
   subsequent appends without writing, advancing state, or issuing a success
   digest. Client callers retain their current fail-open behavior and warning;
   governance callers retain their current refusal on append error.
4. Serialize all append/recovery operations with the existing Unix exclusive
   file-lock helper on a canonical per-log sidecar. Lock order is outer caller
   governance lock, then logger mutex, then per-log lock. `open` takes only the
   per-log lock. The sidecar is `.<canonical filename>.transparency.lock` in
   the canonical parent directory. Creating the data file before resolving its
   canonical path must use create/append without truncation; no recovery or
   write occurs before acquiring the sidecar. No path acquires these locks in
   reverse order. Cache committed
   length; if another cooperating writer changed it, refresh bounded tail state
   before the next append. Compare the held file's identity with the canonical
   pathname under the lock; a replacement refuses append rather than writing
   a detached inode. This prevents recovery truncating an active append.
5. Preserve MIK-6710: read at most the final 4 MiB for recovery, including any
   incomplete suffix. Ignore only the leading partial frame created by the
   bounded window. Validate complete frames within that window: required fields,
   canonical entry hash, adjacent counter/hash links, and configured HMAC.
   If the window reaches the file's beginning, validate the genesis link too.
   Older history remains unchanged and is not certified by this bounded scan.
6. A malformed or altered complete frame is an error. Leave the log byte-for-byte
   unchanged and refuse to open for appends; never reinterpret it as an
   incomplete write or recompute its stored integrity fields.
7. Only an unterminated EOF suffix after a validated complete boundary is
   eligible for recovery. Preserve it in an exclusively created, owner-only
   quarantine sibling and make that copy durable before truncating the source
   to the prior boundary. Sync the repaired file before opening for appends.
   Use a unique create-new filename (never follow or overwrite an existing
   quarantine), mode 0600 on Unix, write all original suffix bytes, sync that
   file and its parent directory, then truncate and sync the data file. Keep
   the quarantine after successful recovery. Any zero-byte genesis boundary
   is eligible only when the bounded read reaches the actual file beginning.
   If any preservation/repair operation fails, refuse opening and retain the
   available evidence; never claim successful recovery. A valid JSON object
   without its newline is still an incomplete frame, not a committed entry.
8. Recovery never reads unbounded data. If the last complete boundary cannot be
   established within the tail window, refuse without truncating. Empty files
   and files containing only blank complete lines retain the genesis state.
9. On platforms where the existing helper supplies no actual cross-process lock,
   do not automatically truncate a torn tail. Return an explicit unsupported
   recovery error. Healthy single-process logging keeps its current platform
   behavior; Unix is the actual recovery deployment target.

These are explicit engineering choices for the measured failure. They do not
change the user's release intent. The paired design review must inspect the
locking and bounded-read contracts before test/production edits.

## Alternatives and risks

- Retrying the current BufWriter can replay uncommitted bytes and recreate the
  demonstrated duplicate counter; rejected by the real probe.
- Truncating immediately on every write error would need reliable buffer
  disposal and a second I/O operation during an active storage failure. Explicit
  poisoning is simpler and avoids pretending that the disk recovered.
- Refusing every restart after a torn suffix avoids mutation but leaves an
  ordinary recoverable interrupted append permanently disabling logging.
  Bounded, locked preservation and repair is the proposed restart path.
- Whole-history startup verification would violate the explicit MIK-6710
  bounded-recovery obligation. Full verification remains an operator operation.
- A writer trait hierarchy is unnecessary: the actual OS-fault probe exercises
  `File` behavior without replacing the production writer with a mock.

The quarantine file contains existing audit bytes and must receive restrictive
permissions; no client payload is added. Recovery must not race another writer.
The per-log lock must use a canonical path so symlink aliases do not create
different lock domains. Replacing or rotating the log while a writer is active
is not made safe by this increment and is detected before appending; hard-link
aliases in separate directories and noncooperating external writers are outside
the cooperating canonical-path lock contract. A missing EOF newline proves an
uncommitted frame under this format, not why it happened: recovery preserves the
suffix rather than asserting that corruption was accidental. If a complete
write reached disk but its required sync failed, the poisoned caller still gets
an error; restart may recover that complete valid frame without claiming that
the caller's dependent operation committed. HMAC verification uses the configured secret
and the entry's bound key ID; no historical secret is guessed or silently ignored.
An unverifiable signed tail refuses append until the correct configuration or
operator-managed log rotation is supplied.

## Acceptance and validation

Stable supporting IDs are MIK-7407.AUDIT.1–7, mapped to RESPONSE.5 and CONTROL.3:
poison/no replay; healthy and synced compatibility; bounded incomplete-tail
recovery with preserved prefix; complete-frame tamper refusal; real concurrent
append/recovery exclusion; repair-failure preservation; platform/read-bound
controls. The adjacent test plan defines their fixtures and falsifiers.

Required gates: paired design/test-plan review, compiled failing tests reviewed
as tests, implementation, focused/legacy regressions, isolated actual OS-fault
and restart run, code review and the release's independent functional pass.
The generic finalizer test gate continues independently. This dependency must
be green before audit-integrity release acceptance closes.

## Review record

Pending. No production repair or recovery success is claimed.
