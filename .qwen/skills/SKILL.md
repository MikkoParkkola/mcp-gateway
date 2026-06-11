---
name: symphony-implementer-workflow
description: End-to-end workflow for implementing Symphony+ tickets with acceptance criteria, including worktree verification, module creation, test implementation, and commit conventions
source: auto-skill
extracted_at: '2026-06-11T19:27:43.514Z'
---

# Symphony+ Implementer Workflow

Complete workflow for implementing Symphony+ tickets in the mcp-gateway project.

## Phase 1: Pre-flight Verification

### Worktree Base-Ref Check (BLOCKING)
Before any edits, verify the worktree is valid:

```bash
cd <worktree>
git rev-parse HEAD
git show -s --format=%s HEAD
git rev-parse HEAD^
```

The worktree is valid when:
1. HEAD equals the expected base commit, OR
2. HEAD message is `chore(<ticket>): skeleton pre-seed for dispatch` AND HEAD^ equals the base commit

If neither condition holds → return `blocked` status, do not proceed.

### Extract Acceptance Criteria
Read the ticket context and extract EVERY acceptance criterion. List them as a numbered checklist. You are graded on ALL of them, not a subset.

### Find Pre-seeded Test Stubs
Search for test files matching the ticket (e.g., `tests/mik_<ticket>_acs.rs`):

```bash
find tests -name "*<ticket>*.rs" -o -name "*mik_*_acs.rs"
```

Read the stub file. It contains test functions that `panic!("pre-seeded stub not implemented")`. These define the acceptance criteria contract.

## Phase 2: Implementation

### Module Structure
New features go in subdirectories under `src/`:

```
src/
  <feature>/
    mod.rs          # Module root with re-exports
    descriptor.rs   # Core data types
    compiler.rs     # Transformation logic
    ...
```

**Pattern:**
- `mod.rs` declares sub-modules and re-exports public types
- Each sub-module has a specific responsibility
- Use `serde::{Serialize, Deserialize}` for data types
- All public items need `///` doc comments (enforced by `#![warn(missing_docs)]`)

### Register in lib.rs
Add the module to `src/lib.rs`:

```rust
pub mod <feature>;
```

Place it alphabetically among existing modules.

### Documentation
If ACs require docs, create `docs/<area>/` with markdown files:
- `descriptor-spec.md` — schema specification
- `substrate-mapping.md` — field mapping tables
- `divergence-registry.md` — known divergences

Each doc should be >100 bytes with clear structure.

## Phase 3: Test Implementation

### Replace Stubs
For each stub in the test file:
1. Keep the function signature and doc comment
2. Replace `panic!` with real assertions
3. Use the test helper pattern: `fn test_descriptor() -> Type { ... }`

### Test Patterns

**Determinism check:** Compile twice, assert equal
```rust
let a = compile(&desc).unwrap();
let b = compile(&desc).unwrap();
assert_eq!(a, b, "compilation must be deterministic");
```

**Serde round-trip:**
```rust
let json = serde_json::to_string(&desc).unwrap();
let rt: Type = serde_json::from_str(&json).unwrap();
assert_eq!(desc, rt);
```

**Documentation existence:**
```rust
let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), "docs/runtime/file.md");
let content = std::fs::read_to_string(&path).unwrap();
assert!(content.len() > 100);
```

## Phase 4: Verification

### Run Tests
```bash
cargo test --test <ticket>_acs
```

All tests must pass.

### Run Clippy (Iterative)
```bash
cargo clippy --all-targets
```

Fix ALL warnings in both source AND tests. Common fixes:
- `len() > 0` → `!is_empty()`
- `_ => unreachable!()` → explicit variant match
- `format!("{:?}", x)` → `format!("{x:?}")`
- Add `#[must_use]` to builder methods returning `Self`
- Add `#[allow(clippy::too_many_arguments)]` when needed
- Use `#[derive(Default)]` instead of manual `impl Default`

Re-run clippy until zero warnings.

## Phase 5: Commit

### Commit Message Format
```
[symphony+/<ticket>] <type>: <summary>

<description of what was implemented>

AC mapping:
AC.1 (<id>): covered by <test_fn> — <what it verifies>
AC.2 (<id>): covered by <test_fn> — <what it verifies>
...
```

The AC mapping is REQUIRED. Without it, the commit scores RED on SPEC axis.

### Stage and Commit
```bash
git add -A
git commit -m "<message>"
```

Do NOT push — the orchestrator handles push.

## Phase 6: Audit Comment

Generate the Linear audit comment in stdout (do not call Linear tools):

```
[symphony+/implement/<ticket>] <summary>

Branch: <branch-name>
Commit: <sha>
Files changed: <count> (+<add>/-<del>)

### What was done
<bullet points of implementation>

### Verifier gates
- **cargo_build**: PASS
- **cargo_test**: <passed>/<total> passed
- **cargo_clippy**: PASS (zero warnings)

### AC coverage
Addresses <ticket>.AC.1: <how>
Addresses <ticket>.AC.2: <how>
...
```

## Common Pitfalls

1. **Partial AC coverage** — Implementing only the "easy" ACs is the #1 bounce cause
2. **Zero test coverage** — No committed tests = automatic rejection
3. **Clippy warnings** — Fix them in source AND tests
4. **Missing AC mapping** — Commit message must map each AC to a test
5. **Negated assertions** — Test assertions must match AC polarity (if AC says "X must be true", test must assert X is true, not false)
