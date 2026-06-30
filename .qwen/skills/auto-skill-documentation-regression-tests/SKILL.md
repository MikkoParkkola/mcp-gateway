---
name: documentation-regression-tests
description: Pattern for writing Rust integration tests that verify markdown documentation content and prevent doc drift
source: auto-skill
extracted_at: '2026-06-30T12:55:44.520Z'
---

# Documentation Regression Tests

When implementing tickets that require creating or updating documentation (competitive analysis, RFCs, design docs), write Rust integration tests that assert the presence of critical content. This prevents documentation from losing key claims, terminology, or cross-references over time.

## When to use

- Ticket requires creating new documentation pages
- Acceptance criteria include CHECK commands that `rg` or `grep` for specific terms
- Documentation must retain competitive positioning, feature comparisons, or implementation pointers
- Preventing doc drift is as important as the doc itself

## Pattern structure

Create a test file at `tests/<ticket_id>_<doc_name>_docs.rs` (e.g., `tests/mik_5843_willow_competitive_docs.rs`):

```rust
use std::fs;

const DOC_PATH: &str = "docs/competitive/willow-enterprise-agent-governance.md";

fn read_doc() -> String {
    fs::read_to_string(DOC_PATH)
        .unwrap_or_else(|e| panic!("failed to read {DOC_PATH}: {e}"))
}

/// AC.1: Document names competitor and positions mcp-gateway on sovereign deployment.
#[test]
fn doc_names_competitor() {
    let doc = read_doc();
    assert!(doc.contains("Willow"), "doc must name Willow as competitor");
    assert!(doc.contains("sovereign"), "doc must position as sovereign");
}

/// AC.2: Feature-bar table includes required rows and verdicts.
#[test]
fn doc_has_feature_bar_table() {
    let doc = read_doc();
    assert!(doc.contains("Connectors"), "table must include Connectors");
    assert!(doc.contains("LEAD"), "table must have LEAD verdicts");
}
```

## Key guidelines

1. **One test per logical claim** — don't cram all assertions into one test. Separate tests for competitor name, positioning, table structure, cross-references.

2. **Assert exact terms from AC CHECK commands** — if the AC says `rg -n "Willow|Webrix|sovereign"`, your test must assert all three terms.

3. **Use descriptive assertion messages** — `"doc must name Willow as competitor"` not just `assert!(doc.contains("Willow"))`. The message becomes the failure explanation.

4. **Handle cross-references** — if AC.5 requires linking from an index, write a test that checks the index file contains the doc filename:
   ```rust
   #[test]
   fn doc_is_linked_from_index() {
       let index = fs::read_to_string("docs/competitive/README.md").unwrap_or_default();
       assert!(index.contains("willow-enterprise-agent-governance"),
           "doc must be linked from competitive README");
   }
   ```

5. **Verify implementation pointers** — if the doc must reference source files like `config_scanner.rs`, assert those filenames appear:
   ```rust
   assert!(doc.contains("config_scanner.rs"),
       "doc must reference config_scanner.rs implementation");
   ```

## Critical clippy fix: backticks in doc comments

**Gotcha**: Rust's `clippy::doc_markdown` lint flags identifiers in doc comments that aren't wrapped in backticks. This includes:
- File names: `config_scanner.rs` → `` `config_scanner.rs` ``
- Acronyms: `IdP` → `` `IdP` ``, `SIEM` → `` `SIEM` ``
- Product names: `Okta` → `` `Okta` ``, `Entra` → `` `Entra` ``, `JumpCloud` → `` `JumpCloud` ``

**Example fix**:
```rust
// ❌ Clippy error: item in documentation is missing backticks
/// Shadow-AI detection with config_scanner.rs and IdP integration.

// ✅ Clippy clean
/// Shadow-AI detection with `config_scanner.rs` and `IdP` integration.
```

When writing test doc comments, wrap all identifiers in backticks to avoid `clippy -- -D warnings` failures.

## Running the tests

```bash
# Run the specific documentation regression test
cargo test --test mik_5843_willow_competitive_docs

# Run all acceptance criterion tests
cargo test --test mik_5843_acs

# Verify clippy is clean
cargo clippy --tests -- -D warnings
```

## Verification

After implementing, run the exact CHECK commands from the ticket's acceptance criteria:

```bash
# AC.1 CHECK
rg -n "Willow|Webrix|sovereign|self-hosted" docs/competitive/willow-enterprise-agent-governance.md

# AC.5 CHECK
rg -l 'willow-enterprise-agent-governance' docs/
```

Both the Rust tests and the CHECK commands must pass.

## Example from MIK-5843

The Willow competitive landscape ticket required:
- AC.1: Naming Willow/Webrix, positioning on sovereign/self-hosted
- AC.2: Feature-bar table with LEAD/MATCH/LAG verdicts
- AC.3: Shadow-AI detection scope with implementation pointers
- AC.4: Regression test that fails if doc loses claims
- AC.5: Doc linked from index

Created `tests/mik_5843_willow_competitive_docs.rs` with 7 tests covering all claims. All tests pass, clippy clean.
