<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Test plan — MIK-6865.SCHEMA.1c forwarded schema bounds

Design: `2026-09-07-schema-1c-forwarded-schema-bounds.md`. One row per
acceptance criterion. Every row names the case, its level, and — because a case
that cannot fail is not a case — what makes it fail.

## Acceptance criteria

- **AC1** — a forwarded schema carrying an unresolved local `$ref` is reported
  out of bounds on the descriptor the client receives.
- **AC2** — a forwarded schema whose local `$ref` resolves in its own document
  is reported within bounds.
- **AC3** — the descriptor's published `inputSchema` is unchanged by the
  inspection: nothing is dropped, rewritten or sanitised.
- **AC4** — the first-party populations already observed stay within bounds
  under the same inspector.

## Rows

| AC | case | file | level | type | how it fails |
|---|---|---|---|---|---|
| AC1 | `a_backend_forwarded_schema_is_inspected_before_it_reaches_the_client` (converts the existing gap witness, same fixture: `allOf` + `#/$defs/Absent`) | `tests/schema_2020_12_validity.rs` | integration | negative | fails today — no `schemaBounds` field exists on the emitted `trustCard`; fails later if the inspector stops naming the unresolved pointer |
| AC2 | `a_forwarded_schema_whose_local_ref_resolves_is_within_bounds` (a `$defs` block the `$ref` actually reaches) | `tests/schema_2020_12_validity.rs` | integration | positive | fails if the inspector flags every `$ref` rather than every UNRESOLVED one — the defect AC1 alone cannot catch |
| AC3 | asserted inside the AC1 case: `composition_sites` and `dangling_refs` over the PUBLISHED `inputSchema` still return the backend's own values | `tests/schema_2020_12_validity.rs` | integration | invariant | fails the moment the inspection mutates or filters the schema instead of only judging it |
| AC4 | the existing `gateway_*` and capability rows, re-run unchanged | `tests/schema_2020_12_validity.rs` | integration | regression | fails if the moved walker changes its verdict on the first-party surface |

## Falsifier

`falsifier_a_composed_subschema_is_reported_by_the_same_walker` already keeps the
composition walker from being one that reports nothing. The `$ref` walker gets
the same treatment for free: AC1 and AC2 use the SAME inspector on fixtures that
differ only in whether `$defs/Absent` exists, so a walker that always reports and
a walker that never reports each fail exactly one of them.

## Not covered, and why

- **2020-12 meta-validity of a forwarded schema.** Needs a validator in `src/`
  (`jsonschema` is dev-only). Named decision in the design; owner: release team
  lead. No row until it is answered.
- **A composition bound on forwarded schemas.** No bound exists to assert —
  U9 unanswered, and composition is legal 2020-12. Observed, not bounded.
