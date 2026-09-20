# PR #473 review — plumbing shard

Shard scope: everything under `src/` **except** `src/gateway/`, `src/protocol/`,
`src/security/`, `src/config/` (those four belong to other shards).

Pinned revision: `BASE=c3626cf8`, `HEAD=60b138bb10a869703254eae2fe500f055d96f8d7`.
Payload built from the pinned SHAs, never the worktree:

    git diff c3626cf8 60b138bb -- src/ \
      ':(exclude)src/gateway/' ':(exclude)src/protocol/' \
      ':(exclude)src/security/' ':(exclude)src/config/'

## Combined payload

| field | value |
|---|---|
| sha256 | `bfb61e222c0b2e2481a75ba2b1a493c74d04cc1535d9528ad3371317a9f81a7d` |
| bytes | 356,178 |
| files | 55 |
| insertions | 5,989 |
| deletions | 442 |

356 KB exceeds the ~150 KB single-payload ceiling, so the shard was split into
five parts along module lines.

## Split — a byte-exact partition

`cat p1.diff p2.diff p3.diff p4.diff p5.diff | sha256sum` reproduces the combined
payload hash exactly, and the part byte counts sum to 356,178. No file appears in
two parts and none is dropped.

| part | modules | bytes | files | sha256 |
|---|---|---|---|---|
| p1 | `attestation/`, `backend/`, `cache.rs` | 40,857 | 11 | `cce2f6d94102c6ca97311a21632d36f70080d9b01d2cbf2f7d74cf0691ce7893` |
| p2 | `capability/`, `cli/`, `commands/`, `config_persistence.rs`, `config_reload/` | 142,875 | 14 | `134e1fe0039d0e39988fcd61f8cacd685a64c7ea26b7e0016e090be9fd626fb4` |
| p3 | `discovery/`, `error.rs`, `failsafe/`, `honest_task_tokens.rs`, `idempotency.rs`, `kill_switch/`, `lib.rs`, `main.rs`, `main_tests.rs`, `mtls/` | 54,475 | 14 | `4515aa7f90f7de14592f5feb6fd3c4351eed1546689362c2e2db10579e37a263` |
| p4 | `oauth/`, `protocol_revision_telemetry.rs`, `runtime/`, `secret_injection.rs`, `secrets.rs` | 57,303 | 10 | `dbf0489aee802361cf96de24a2405eeeb2d1407ceb7070b5343dca358c4d3b43` |
| p5 | `transport/`, `trust/` | 60,668 | 6 | `9c519e3c749da077d10f762780214ce5448e7114611ba7510aaf67431489507c` |
| | **total** | **356,178** | **55** | |

Per the brief's Correction, `material_sha256` covers one NUL byte followed by the
payload, so `material_bytes` is payload bytes + 1. Expected digests:

| part | `{ printf '\0'; cat pN.diff; } \| sha256sum` | expected `material_bytes` |
|---|---|---|
| p1 | `f9ba241e786ff2d29afb227e47795641cba2deac24fe5b36fe7372ce11313416` | 40,858 |
| p2 | `983f1246d294e1c5da629897b7c1af34184ebbc22ffb95b9bc5dfa3add53679f` | 142,876 |
| p3 | `4da9fdb879172f627fc902c643a8650caf0125d795485c5fd42f20bcc4009533` | 54,476 |
| p4 | `7762fffda6c4ce868c82e463832fd7e6f77da46a7e522178314fc1288806eaa2` | 57,304 |
| p5 | `7286724dab3e3369bb5a18eecb69b504a5bdb384cfa9864d3fa400ecf2a49cf1` | 60,669 |

## Ledger rows

Pending — filled in once all ten reviewer runs land.

## Findings

Pending.
