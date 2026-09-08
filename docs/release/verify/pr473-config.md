# PR #473 unreviewed-slice review — shard: `src/config/`, `src/config_reload/`, `src/commands/`

Range `c3626cf8..60b138bb10a869703254eae2fe500f055d96f8d7`, pinned SHAs, not the worktree.

## Payload

    git diff c3626cf8 60b138bb -- src/config/ src/config_reload/ src/commands/

| field | value |
|---|---|
| sha256 | `3c12f814f46fa6172243c87c1b0e3ac53352fb838f019834d823ebe10daddb36` |
| bytes | 212,860 |
| files | 10 |
| insertions | 4,000 (deletions 262) |

213 KB exceeds the ~150 KB single-payload ceiling in the brief, so the payload was
split two ways along module lines and each part reviewed by both vendors.

The parts partition the whole exactly: 8 + 2 = 10 files, 2,627 + 1,373 = 4,000
insertions, 141 + 121 = 262 deletions, 136,484 + 76,376 = 212,860 bytes. The
concatenation `cat part1.diff part2.diff | sha256sum` reproduces the combined
payload hash `3c12f814…` byte for byte, so no code was dropped by the split.

| part | paths | sha256 | bytes | files |
|---|---|---|---|---|
| 1 | `src/commands/`, `src/config/` | `b4e00665340447128f3633b762f973b9ab2b16309398bea624bf282cda80d38a`* | 136,484 | 8 |
| 2 | `src/config_reload/` | `6ccfa71ce2f5237601f3340dd69078f8d81f649c1d858897ed17e3da018287d3`* | 76,376 | 2 |

\* these are the NUL-prefixed binding digests, see below; the raw file hashes are
part 1 `dcb2…` (not used for binding) and part 2 identical to the raw `pC` payload.

Per-file breakdown (insertions/deletions):

| file | ins | del | part |
|---|---|---|---|
| `src/commands/add_remove.rs` | 66 | 1 | 1 |
| `src/commands/setup.rs` | 17 | 2 | 1 |
| `src/commands/upgrade.rs` | 217 | 30 | 1 |
| `src/config/env_overlay.rs` | 507 | 0 | 1 |
| `src/config/features/error_budget.rs` | 167 | 0 | 1 |
| `src/config/features/mod.rs` | 2 | 0 | 1 |
| `src/config/mod.rs` | 780 | 78 | 1 |
| `src/config/tests.rs` | 871 | 30 | 1 |
| `src/config_reload/mod.rs` | 253 | 60 | 2 |
| `src/config_reload/tests.rs` | 1,120 | 61 | 2 |

## Ledger rows

A ledger row's `material_sha256` is NOT the payload hash. `gpt-review`'s
`digest_material` hashes `printf '%s\0' "$*"` followed by the stdin file, so for a
stdin review with no scope arguments the digest covers one NUL byte plus the
payload — `material_bytes` is always payload + 1. The binding digests are:

| part | binding material_sha256 | expected material_bytes |
|---|---|---|
| 1 | `b4e00665340447128f3633b762f973b9ab2b16309398bea624bf282cda80d38a` | 136,485 |
| 2 | `6ccfa71ce2f5237601f3340dd69078f8d81f649c1d858897ed17e3da018287d3` | 76,377 |

Rows, by vendor and part:

PENDING

## Findings

PENDING

## Coverage limits

PENDING
