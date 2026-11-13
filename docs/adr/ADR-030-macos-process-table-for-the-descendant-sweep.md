# ADR-030: One scoped `unsafe` module for the macOS process table

- **Status**: Accepted, 2026-11-12 (maintainer decision, option A: one macOS-only file of
  `unsafe` code). Vetoable until the implementing PR merges.
- **Relates to**: ADR-016 (scoped `unsafe`), `#![deny(unsafe_code)]` (`src/lib.rs`), the
  stop-budget work (a backend's stop is bounded; its descendants die with it).

## Context

A stdio backend that is itself a gateway runs its own backends in their own process
groups, so the outer's group kill never reaches them. The descendant sweep
(`src/transport/stdio_sweep.rs`) walks the process tree before the kill, freezes it,
verifies it and kills it. It reads the tree through a table: on Linux `/proc` and
pidfds (safe `std` and `rustix`), on macOS libproc. libproc has no safe route in the
standard library or in `rustix`.

Alternatives considered:

- Spawning `ps`. Forks inside a deadline-bound stop, and its start time is one second
  wide, which weakens the pid-reuse check the sweep relies on. Rejected.
- The `libproc` crate. A new dependency that wraps the same two calls in the same
  `unsafe`. Rejected.

## Decision

Allow `unsafe` in exactly one more module, `src/transport/stdio_sweep_macos.rs`
(macOS-only calls; the file parses everywhere, so the allowlist scan sees it on every
host). It calls `libc` (already in `Cargo.lock`; now a macOS target dependency) and
only these functions: `proc_listallpids` and `proc_pidinfo` with `PROC_PIDTBSDINFO`.
Signals go through `rustix::process::kill_process`, which is safe. Adding any other
libproc call is an amendment to this ADR. `src/unsafe_allowlist_tests.rs` pins the
module list and checks that every `unsafe` block in the file names its contract.

## Safety contract

Every `unsafe` block carries a `// SAFETY:` comment naming which of these it relies on.

1. **Ownership.** Every buffer is a Rust-owned `Vec<i32>` (pids) or a stack value
   (`proc_bsdinfo`) that outlives the call. Nothing the kernel allocates is kept.
2. **Sizing.** The pid count can change between the size call and the fill call. The
   buffer is sized from the first call plus headroom with checked arithmetic and a hard
   cap; a fill that is full (count not below the slot count) means "list again", and
   the count the kernel returns is clamped to the buffer before any read.
3. **Short reads.** `proc_pidinfo` is accepted only when it returns exactly
   `size_of::<proc_bsdinfo>()` and the record names the pid asked for; anything else is
   "no such process".
4. **Identity.** The start time is `pbi_start_tvsec` and `pbi_start_tvusec`
   combined at microsecond resolution with checked arithmetic. A pid is signalled only
   after an identity re-read, and only after the sweep has stopped it.
5. **Privacy.** `pbi_comm` and `pbi_name` are never read; no command line leaves the
   module.
6. **Errors.** A negative or zero return is a refusal, never a partial result.
7. **No global state.**

## Consequences

- The crate's `unsafe` surface grows by one reviewed macOS file with a written contract
  and the allowlist fence; Linux and Windows builds do not compile its calls.
- macOS has no pidfd: its signals go by pid after an identity re-read, with the
  stop-verify-kill order that keeps the reuse window closed.
