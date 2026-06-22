---
name: rust-clippy-pedantic-fixes
description: Systematic approach to fixing Rust clippy pedantic/all lint warnings when the crate enforces -D warnings, including diagnostic flow, common fix patterns, and test-portability gotchas.
source: auto-skill
extracted_at: '2026-06-22T04:18:16.001Z'
---

# Fixing Rust Clippy Pedantic Warnings Under `-D warnings`

Use this skill when a crate has `[lints.clippy]` configured with `all` or `pedantic` at warn level and the verifier runs `cargo clippy -- -D warnings`. Every warning becomes a build error.

## Diagnostic flow

1. **Check the lint config first** — `Cargo.toml` `[lints.clippy]` section tells you which lints are allowed globally (e.g. `module_name_repetitions = "allow"`, `must_use_candidate = "allow"`). Don't fight lints the crate already opted out of.
2. **Run clippy once to get the full list**: `cargo clippy --lib 2>&1 | grep -E "^(warning|error):" | sort -u` — gives the unique warning categories.
3. **Get file locations**: `cargo clippy --lib 2>&1 | grep -E "(warning:|-->)" | head -60` — pairs each warning with its source location.
4. **Fix by category, not by file** — batch all `missing documentation` fixes together, then all `must_use`, etc. Reduces context switching and reveals patterns.
5. **Re-run after each batch** — confirms progress and surfaces warnings that were hidden behind earlier ones.

## Common fix patterns

| Warning | Fix |
|---|---|
| `missing documentation for a struct field` | Add `///` doc comment above each `pub` field |
| `missing documentation for a variant` | Add `///` doc comment above each enum variant |
| `missing documentation for a module` | Add `///` doc comment on the `pub mod foo;` line in the parent |
| `missing #[must_use] on method returning Self` | Add `#[must_use]` attribute on builder/conversion methods |
| `item in documentation is missing backticks` | Wrap code-like strings in doc comments with backticks: `"foo"` → `` `"foo"` `` |
| `unused import` | Remove from main scope; if test code uses it, add `use` inside `#[cfg(test)] mod tests` |
| `casting u64 to f64 may lose precision` | Add `#[allow(clippy::cast_precision_loss)]` when the values are small in practice |
| `more than 3 bools in a struct` | Add `#[allow(clippy::struct_excessive_bools)]` when the struct genuinely has that many flags |
| `this function has too many lines` | Add `#[allow(clippy::too_many_lines)]` when the function is a cohesive pipeline that would be harder to read split |

## Gotchas learned the hard way

### 1. Moving imports breaks `#[cfg(test)]` code
When you remove an "unused" import from the top of a module (e.g. `serde_json::json`), check whether the `#[cfg(test)] mod tests` block below uses it via `use super::*`. The fix is to add the import **inside** the test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;  // <-- add here if super no longer re-exports it
```

### 2. Tests assuming absence of binaries on PATH
A test like `assert_eq!(result.runtimes_checked.len(), 1)` implicitly assumes only one runtime binary is installed. This is **not portable** across dev environments. Use portable assertions:
```rust
// BAD: assumes codex and openclaw are NOT installed
assert_eq!(result.runtimes_checked.len(), 1);

// GOOD: asserts the invariant regardless of environment
let claude = result.runtimes_checked.iter().find(|r| r.runtime == "claude-code").unwrap();
assert!(claude.accessible);
```

### 3. Compilation OOM on large crates
Some crates (e.g. those pulling in axum + tokio + tls stacks) exhaust memory when `cargo build` runs at full parallelism. Pass `-j 2` to cap concurrent rustc processes. This is especially relevant in shared CI/cargo-target environments.

### 4. Unused variables in tests
After refactoring (e.g. removing an assertion that used `mem`), the variable may become unused. Clippy flags these as warnings. Either remove the binding or prefix with `_`.

## Verification command set
Run these three in order; all must be green before declaring done:
```bash
cargo clippy --lib -- -D warnings 2>&1 | tail -5
cargo test --lib -j 2 -- <module_prefix>
cargo test --test <acceptance_test_name> -j 2
```
