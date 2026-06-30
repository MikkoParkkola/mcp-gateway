---
name: doc-section-ordering-for-machine-tests
description: Structure documentation files so machine-checkable tests that use first-occurrence section extraction and cross-reference validation both pass.
source: auto-skill
extracted_at: '2026-06-30T13:29:03.262Z'
---

# Document Section Ordering for Machine-Checkable Tests

## Problem

When documentation files (e.g., roadmaps, specs) must satisfy multiple machine-checkable acceptance tests, a subtle conflict can arise between:

1. **Section-extraction tests** — Tests that use `content.find(id)` to locate the **first occurrence** of each section identifier, then extract text from that position to the next section marker (`\n## `). They validate that specific fields exist within the extracted section.

2. **Cross-reference tests** — Tests that validate dependency relationships by checking that a section's `Dependencies` field contains references to other section IDs.

If a section's Dependencies field references an ID that appears *later* in the file (a forward reference), the first-occurrence test finds that ID in the wrong section's Dependencies line rather than in its own section header. The extracted "section" then contains only the referencing section's tail text, missing all the expected fields.

Similarly, any preamble (dependency graphs, summaries, indices) that lists all section IDs before their actual sections will cause every section extraction to fail.

## Solution

### Rule 1: Preamble/summary sections go LAST

Move dependency graphs, summary tables, cross-reference indices, and any content that enumerates multiple section IDs to the **end** of the file, after all canonical sections.

### Rule 2: Order sections in dependency direction

Arrange sections so that if Section A's Dependencies field references Section B, then Section B appears **earlier** in the file than Section A. This ensures every dependency cross-reference points backward, never forward.

Concrete procedure:
1. Map all dependency edges: `(section, dependency)` pairs
2. Topologically sort sections so dependencies come first
3. For sections with no tested dependency relationship, place them in any valid position that doesn't create forward references
4. Remove non-essential forward references from Dependencies fields (e.g., if a dependency isn't tested by cross-reference validation, describe it by name rather than by ID)

### Rule 3: Verify first-occurrence positions

After writing, verify that for each section ID, `content.find(id)` lands within that section's own header or body — not in an earlier section's Dependencies, a preamble, or a graph.

## When to apply

- Writing documentation that must pass machine-checkable acceptance tests
- Structuring roadmap/spec files with `## ID: Title` section headers
- Any scenario where tests use first-string-match to locate and extract sections
- Documentation with both field-validation tests AND cross-reference/dependency tests

## Anti-patterns to avoid

- Placing a dependency graph with all IDs at the top of the file
- Forward-referencing IDs in Dependencies fields (e.g., MIK-6554 referencing MIK-6555 when 6555 comes later)
- Including child IDs in introductory/preamble text before their sections
- Using the same ID format in both cross-reference text and section headers without ordering discipline
