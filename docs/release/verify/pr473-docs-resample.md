# PR 473 — Absence-Claim Resample (docs/requirements, docs/design, docs/release)

Deeper resample after a prior shard found 3/5 sampled absence claims false. Priority: BLOCKS/blocking/yes/NOT MET rows first, then `docs/release/` (zero prior coverage), then remainder.

Method: verify at source via `rg` against `src/**` and `tests/**`, never from another doc. Classify MATCH / CONTRADICTION / CANNOT-VERIFY. Flag DRIFT (right claim, stale line ref) separately.

Work in progress — appended per claim as verified.

## Findings

| claim (quoted, short) | doc file:line | verdict | evidence file:line | blocking row? |
|---|---|---|---|---|
