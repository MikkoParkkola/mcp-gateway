# SUB.2b stdio mint — implementation notes (subordinate to ADR-014 §2)

Status: notes, not a design. **ADR-014 §2 as amended by `b9e1fb95` is the design
of record.** The mint, the `minted → (caller token, sender)` entry, the
translate-back and the drop-guard reclamation are all decided there; nothing
here re-decides them. What follows is the residue that the ADR deliberately
does not fix at this granularity, plus one defect in today's code measured
against what the ADR already demands.

Scope when implemented: `src/transport/stdio.rs`, plus one generic-parameter
change to `PendingRequestGuard` in `src/transport/mod.rs` (note 2).

## 1. Store the caller's original `Value`, not its string form

The map value must hold the caller's progress token as the `serde_json::Value`
it arrived as. Translate-back then restores `params.progressToken` byte-
identically, including the `Number`/`String` distinction that
the `Number`/`String` arm of `capture_notification`
(`src/transport/stdio.rs`) collapses. Storing the stringified form makes
a numeric `3` come back as `"3"` — a token the client never sent, which is the
invented owner that `register_progress_token` /
`release_progress_token` exist to prevent.

ADR-014:152-154 settles the *key* side of that collapse (minted keys are never
numeric, so they cannot alias). The *value* side is what this note covers, and
the ADR does not state it at this granularity.

## 2. Generalise `PendingRequestGuard` rather than writing a second guard

ADR-014:157-161 requires a guard that removes its own key on drop —
"completion, error, timeout, cancellation alike". The existing
`PendingRequestGuard` (`PendingRequestGuard`, `src/transport/mod.rs`) is typed to the `pending`
map's value. Make it generic over the value type instead of adding a
near-identical second struct: one `Drop`, two maps.

`websocket.rs`'s `request` is the other construction site. The parameter is
inferred there, so it compiles unchanged.

The motivation is not new and need not be argued: `websocket.rs:511-514`
already gives the guard's purpose as stopping "a request future dropped by an
OUTER timeout or task abort" from stranding its entry. That is the cancellation
case, stated by the codebase before this row existed. Only the second map is
new — which is also why one generic guard beats a second near-identical struct.

### Two comments outside `transport/` that this change falsifies

Both describe the guard from elsewhere and must be re-read, not assumed, at
implementation time:

- `src/gateway/proxy.rs:95-97` — "That guard is typed to the transports'
  `DashMap` of response senders, so it cannot be reused here." A generic
  parameter makes the stated reason false. Note the consequence beyond
  staleness: it also removes the blocker on folding `PendingSampleGuard`
  (`proxy.rs:98`) into the same guard. **Not this row's work** — record it as a
  follow-up rather than widening the diff.
- `src/gateway/input_bridge.rs:291-295` — cites `stdio.rs:517` and
  `stdio.rs:815` by line number. Editing `stdio.rs` shifts both. Re-anchor to
  the symbol names (`cancelled_request_does_not_strand_pending_entry`) rather
  than re-numbering.

## 3. Today's code does not meet ADR-014:157-161 (the gap to close)

Release is currently a statement after `outcome`. It runs on `Ok`, on transport
error and on timeout, because all three flow through that statement. It does
**not** run when the future is dropped mid-await — cancellation — and that path
leaks one entry, holding the caller's sink open so its receiver never observes
close. This is a gap in the code against the ADR, not a gap in the ADR.

A panicked reader task is a separate and already-bounded path: the
`oneshot::Receiver` never fires, the call blocks until `self.request_timeout`,
and that timeout flows through today's release statement. One timeout per
in-flight call, zero map growth, guard or no guard.

## 4. Acceptance

`s02_stdio_progress_reaches_its_own_call_before_the_result`
(`tests/mik_7272_sub2b_acs.rs`) asserts both halves and is the acceptance
proof for this work. Not edited from this lane.

## 5. Cite by symbol, not by line

Every reference above names a symbol. `stdio.rs` is about to be edited by this
row and is already dirty in another lane, so any line number written into a
document or a comment is stale before it is read — which is exactly the defect
recorded against `input_bridge.rs:291-295` in note 2. Line numbers that remain
here point only at files this row does not touch.
