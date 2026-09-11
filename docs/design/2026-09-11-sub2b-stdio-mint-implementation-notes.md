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
`src/transport/stdio.rs:469-471` collapses. Storing the stringified form makes
a numeric `3` come back as `"3"` — a token the client never sent, which is the
invented owner `:455-462` exists to prevent.

ADR-014:152-154 settles the *key* side of that collapse (minted keys are never
numeric, so they cannot alias). The *value* side is what this note covers, and
the ADR does not state it at this granularity.

## 2. Generalise `PendingRequestGuard` rather than writing a second guard

ADR-014:157-161 requires a guard that removes its own key on drop —
"completion, error, timeout, cancellation alike". The existing
`PendingRequestGuard` (`src/transport/mod.rs:180`) is typed to the `pending`
map's value. Make it generic over the value type instead of adding a
near-identical second struct: one `Drop`, two maps.

`src/transport/websocket.rs:515` is the other call site. The parameter is
inferred there, so it compiles unchanged.

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
(`tests/mik_7272_sub2b_acs.rs:481`) asserts both halves and is the acceptance
proof for this work. Not edited from this lane.
