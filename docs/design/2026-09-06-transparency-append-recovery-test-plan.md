# Transparency append recovery test plan

Status: draft, pending paired review before tests or production repair.
Design: [transparency append recovery](2026-09-06-transparency-append-recovery.md).
Ticket: MIK-7407. These supporting AUDIT IDs trace to MIK-7407.RESPONSE.5 and
CONTROL.3; they do not replace the existing response-finalization criteria.

| ID | Level/type | Stimulus and required observation | Falsifier and control |
|---|---|---|---|
| AUDIT.1 | Actual binary/OS-write failure | A verified one-entry baseline, counted second backend call and actual 64-byte partial append under child-only RLIMIT_FSIZE. Client result succeeds; the writer returns/logs failure. Restore the limit and call again: the poisoned instance writes no further audit bytes and cannot emit a successful append digest. | Existing code appends duplicate counter 2. Baseline actual CLI verification and child signal-mask proof reject a fixture that never reaches the target write or dies from SIGXFSZ. |
| AUDIT.2 | Library regression/compatibility | Normal invocation, append_event and append_event_synced produce the unchanged entry schema, correct counters/hash links and valid configured HMAC. Each successful append contributes exactly one frame. The synced path still executes real sync_all; its failure poisons rather than returning success. | Kill state advancement before write, omitted newline, altered entry/HMAC format and skipped sync path; existing 20 logger tests remain required. Any synthetic sync-error seam is labeled component evidence, not a real disk fsync failure. |
| AUDIT.3 | Actual binary/restart + library boundary cases | Stop the capped child after its partial append, restart without the cap, verify exact quarantine bytes and unchanged committed-prefix bytes, then invoke once and verify the actual full chain. Cover empty log, first incomplete frame, valid JSON missing only newline, and trailing whitespace. | Current startup silently continues without logging. Wrong truncation or discarded committed record fails prefix/hash/counter checks; omitted quarantine durability cannot be represented as a successful repair. |
| AUDIT.4 | Library/adversarial complete-frame cases | Complete newline-terminated malformed JSON, missing required fields, altered body/hash, bad counter/link and configured HMAC failure refuse open and preserve all bytes. A legitimate signed tail succeeds. | Prevents truncating a tampered completed frame, trusting stored hash alone, or silently degrading signed verification. No startup claim is made about history before the bounded window. |
| AUDIT.5 | Real Unix processes/concurrency | Hold the actual canonical per-log lock in one process, start a second process's append/recovery and observe explicit started-but-not-completed state. Release the first guard; the second proceeds against the completed file. Two logger instances alternating appends produce a verified chain; symlink alias paths use one lock domain. Replacing the pathname under a live instance refuses a detached-inode append. | An unlocked or differently named recovery lock must fail the overlap oracle. Use pipe/barrier readiness and bounded joins, not scheduling sleeps as proof; retain an all-healthy control. Hard-link aliases and noncooperating external writers are not claimed covered. |
| AUDIT.6 | Real filesystem errors/recovery safety | Deny quarantine creation and separately repair writes through owned isolated filesystem fixtures. `open` fails, no successful digest is returned, and source/available preserved bytes remain unchanged. A permitted retry succeeds. Assert exact suffix preservation, owner-only permissions and create-new collision handling; sync-stage component instrumentation verifies quarantine file and directory durability precede truncation. | Prevents truncation before preservation, success on incomplete repair, and unbounded retry. Explicitly record which OS operation actually failed; fixture/setup failures are not behavior reds. A synthetic sync error is stage-order evidence, not a claim to reproduce physical disk durability loss. |
| AUDIT.7 | Bounds/platform/negative controls | A valid audit history larger than 4 MiB recovers using an actual read observer that counts positive bytes but no more than the tail bound. A suffix with no complete boundary inside that bound refuses without modification. Non-Unix unavailable-lock recovery refuses mutation; healthy existing platform behavior is preserved. | Whole-file startup read, a fabricated counter-only tail, missing read observation and zero collected platform tests cannot prove the bound. Replace the existing fake oversized-tail fixture with legitimate history while retaining its original MIK-6710 obligation. |

Every test name and receipt carries MIK-7407.AUDIT.n. Actual process tests record
binary/source digests, exit status, collected names, target file lengths,
backend call counts and real audit-CLI output. The initial failed SIGXFSZ fixture
stays in the evidence history but never counts as a caught logger defect.

The first fail-fast commands remain focused logger tests and the isolated
existing-binary OS-fault probe. No whole release build is needed to establish the
baseline. After implementation, run the new focused cases, existing logger 20,
generic finalizer tests, control-plane audit/identity propagation regressions and
the actual HTTP fault/restart journeys. Root coordinates shared build/source
lanes; an isolated Spark lane is bounded to four jobs.

Mutation/falsifier obligations: retain BufWriter replay, omit poisoning, permit an
append after failure, truncate the wrong boundary, truncate a completed bad hash,
omit quarantine-before-truncate ordering, skip the real lock, use an alias lock,
skip external-length refresh, read the whole file, ignore configured HMAC, and
return successful append after sync failure. A mutation pass requires the named
behavior assertion to fail and a restored green run; compile/setup failures are
not killed mutants.

## Review record

Pending. The generic finalizer's one-shot append-error test is retained as caller
handling evidence and is not substituted for these OS/restart cases.
