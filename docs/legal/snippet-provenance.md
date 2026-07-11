# Snippet Provenance Audit

**Work:** mcp-gateway
**Audit date:** 2026-07-12
**Auditor:** Mikko Parkkola (with AI-assisted tooling)
**Purpose:** Record the provenance of any third-party source code copied into
first-party files, so that clean chain of title can be asserted for the
PolyForm-Noncommercial-1.0.0 default and the commercial-license offer.

## Why this exists

Copyright in the integrated work does not launder materially-copied third-party
snippets. Even short verbatim extracts can carry another author's protected
expression (CJEU *Infopaq*, C-5/08), and Stack Overflow user content is licensed
**CC BY-SA** (attribution + share-alike), which is incompatible with a
proprietary/commercial redistribution unless the attribution and share-alike
terms are honored. Copied code is therefore tracked as a licensing matter
independent of the AI-authorship question.

## Method

Automated sweep of `src/` and `crates/` on 2026-07-12:

- `grep -rni "stackoverflow|stack overflow"` — copied Stack Overflow code.
- `grep -rniE "copied from|adapted from|borrowed from|taken from"` — attribution
  markers.
- `grep -rniE "//.*https?://(github|gitlab|gist|reddit|medium|dev\.to)"` —
  external source URLs in comments.

Any AI-tool output that reproduces distinctive upstream code near-verbatim is
treated as a **copied-snippet** issue, not an AI-authorship issue, and would be
logged in the register below.

## Findings

**No third-party source code was found copied into first-party files.**

| Signal | Result |
|---|---|
| Stack Overflow references | 0 |
| `copied from` / `adapted from` markers pointing at external code | 0 (all matches are internal — struct fields, source reports, import plans) |
| External source URLs in code comments | 2, both non-copies (see below) |

Non-copy references identified and cleared:

- `src/validator/README.md` — cites Phil Schmid's "MCP Best Practices" article as
  the **design basis** for validation rules. This is a factual citation of an
  idea/approach, not copied code. Ideas and methods are not protected
  expression (CJEU *SAS Institute*, C-406/10).
- `src/a2a/types.rs` — links the A2A protocol **specification** for reference.
  Types implement a spec; the comment is a pointer, not a code copy.
- `src/gateway/meta_mcp/invoke.rs` — links this project's own issue tracker.
- `src/security/firewall/memory_scanner.rs` — an `attacker.com` URL inside a
  **test fixture** (adversarial input), not a source reference.

## Register of copied snippets

None as of the audit date. If any third-party snippet is later introduced, add a
row here before merge:

| File | Source (URL/repo) | License | Extent | Decision (replace / attribute+comply / remove) | Date |
|---|---|---|---|---|---|
| _(none)_ | | | | | |

## Standing

Not legal advice. Records the author's provenance audit for counsel review. The
sweep is comment/marker-based and is a reasonable-diligence audit, not a
guarantee against undocumented copying; it is re-runnable as the codebase grows.
