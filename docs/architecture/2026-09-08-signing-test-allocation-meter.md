# Test-only global allocator for the SIGNING.5 allocation checkpoint

Status: proposed, under P2 source review. Not approved, not merged, and the
allocation oracles it exists for have not produced a verdict yet.

`CLAUDE.md` requires a `docs/architecture/` justification before any `unsafe`
enters this crate. This is that justification, for a `cfg(test)` allocator meter
and nothing else. It is a bounded test exception, not a policy waiver: the
crate-wide `#![deny(unsafe_code)]` stays exactly as it is, and no production
path gains an `unsafe` block, a performance trick, or a new contract.

## Why an allocator at all

Approved test-plan row 40 (MIK-7377.SIGNING.5) asserts that a nonce refusal on
the owned stdio dispatcher allocates under 16 KiB while refusing a prepared
1 MiB or 3 MiB request. That claim is about REAL ALLOCATED BYTES. Every cheaper
proxy answers a different question and would let the row pass while false:

| proxy | what it actually measures |
|---|---|
| retained heap / RSS | what survived, not what was asked for — a copy made and dropped is invisible |
| bytes hashed | one component's work, chosen by the person who already suspects it |
| a counter around a suspected call site | the clone you knew about, never the one you did not |

Only `GlobalAlloc` sees what the dispatch asks the allocator for, including the
allocations nobody wrote down. The row was approved on that basis.

## What is added

One `unsafe impl GlobalAlloc` in `src/gateway/server/tests/alloc_meter.rs`,
reachable only through a `#[cfg(test)]` module declaration. Every method
forwards its exact arguments to `std::alloc::System` and returns its exact
result; the type holds no state and allocates nothing of its own. The safety
contract is therefore whatever `System` already guarantees, and each method
carries a SAFETY comment saying so.

`#[allow(unsafe_code)]` sits on that single impl block. It does not appear at
crate, module or file scope, and it is the only occurrence in the deliverable.

## Why it is safe to have it installed at all

A `#[global_allocator]` is process-wide, so during a test build every test in
the crate routes through it. Three properties keep that harmless:

1. **The inactive path is trivial.** One `const`-initialised thread-local `bool`
   read, then a forward to `System`. No lock, no buffer, no allocation, no lazy
   initialiser, no destructor registered — so it cannot recurse into itself and
   cannot fail during thread setup.
2. **Deallocation is never counted and never touches the thread-local cells.**
   The row asks for allocated bytes, never net heap, so `dealloc` only forwards.
   That also removes the thread-teardown hazard on that path entirely.
3. **Failure is silent, never a panic.** Counter access uses `try_with`; a
   record lost during teardown is dropped rather than raised. A panic inside an
   allocator is not usefully recoverable.

Measurement scopes are RAII, refuse to nest, and check that refusal BEFORE
mutating any counter, so an unwind through an awaited dispatch cannot leave a
scope open or a total half-erased.

## Why the readings can be trusted

Two controls run under the same meter, so a blind counter cannot pass quietly:

* **positive** — a forced deep clone of the prepared tree must report at least
  the payload's own serialised size;
* **negative** — a single known-size reservation must be reported within a
  known range of that size.

Isolation is structural, not procedural: each measuring test re-executes the
test binary as a child running exactly one test on a current-thread runtime,
asserts the child exited zero AND that it reported `1 passed`. Without that
second assertion a filter matching nothing would exit zero and turn the file
green — a suite that cannot fail.

## Scope

Test scaffolding only. No product surface, no runtime behaviour, no new
dependency, no visibility widening. If the P2 source gate rejects the mechanism,
the deletion is four files and one `cfg(test)` module declaration.
