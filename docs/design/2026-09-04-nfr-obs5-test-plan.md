# NFR.OBS.5 — test plan (§P2)

Status: plan, pre-implementation. Reviewed by both legs before any test code is written.

## §P0 SCOPE

FOR: making `tests/nfr_obs5_flag.rs` prove every clause of NFR.OBS.5, and landing the one-line
default flip that clause (c) requires.

OUT:
- `SUPPORTED_VERSIONS` membership for `2026-07-28` (NFR.COMPAT.1's row, and a pinned test at
  `src/protocol/mod.rs:66-88` exists specifically to stop that edit).
- unknown-revision fallback behaviour in `negotiate_version` (see clause (d) boundary).
- the modern frame's *content* (`_meta`, mirrored headers) — other criteria own it.

## The criterion, split into clauses

| id | clause |
|---|---|
| a | the modern surface is behind a flag |
| b | revertible without a downgrade |
| c | serves the latest revision by default |
| d | negotiates down to the highest revision the client supports |

## Mechanism facts this plan rests on (verified at source)

- `ServerConfig::default().modern_protocol == false` — `src/config/mod.rs:1229`. (Every document
  in the tree that cites this default gives a stale line — `1174` or `1127`. It is `1229`.)
- **`#[serde(default)]` sits on the field at `src/config/mod.rs:1181`.** This is the fact that
  makes "by default" a two-part change rather than one line. A field-level `#[serde(default)]`
  resolves to `bool::default()` — `false` — *not* to `ServerConfig::default()`. So a config file
  carrying a `server:` section that simply omits the flag deserializes to `false` no matter what
  the struct default says. That is every real deployment. Flipping the struct default alone would
  leave the operator-facing default off while a `Config::default()`-based test went green:
  a test passing while the criterion is broken.
- No shipped config file sets the flag; `deploy/helm/mcp-gateway/values.yaml` only mentions it in
  a comment. So the operator-facing default is decided by those two places and nothing else.
- `discover_document(modern_enabled)` — `src/gateway/meta_mcp/mod.rs:1108-1140` — starts from
  `SUPPORTED_VERSIONS` and appends `MODERN_VERSIONS` (`["2026-07-28"]`) only when the flag is on.
- `negotiate_version()` — `src/protocol/mod.rs:52-62` — exact-matches over `SUPPORTED_VERSIONS`,
  else falls back to `PROTOCOL_VERSION`. Flag-independent.
- `unsupported_version_error` — `src/gateway/router/handlers.rs:172-188` — emits
  `error.data.supportedVersions == []` only when the flag is off. This is the fingerprint that
  stops an earlier gate's 400 impersonating this one.

Neither (c) nor (d) needs `2026-07-28` in `SUPPORTED_VERSIONS`: the modern frame is advertised
through `discover_document`, and negotiation exact-matches revisions that are already in the list.
The gap plan's claim that the absence is "the precondition for the ruling" is recorded as an
out-of-scope observation below, not acted on.

## Prior coverage — asked before assuming

(d) is *incidentally* covered today: `tests/nfr_obs5_flag.rs` case 3 asserts
`legacy_before["result"]["protocolVersion"] == LEGACY` — but as a **precondition** for a different
test, at **one** revision, against a **flag-off** gateway. Against a flag-off gateway it proves
nothing about the new default, which is exactly what the criterion is about. Promoted to a
first-class case below.

(a), (b) are covered. (c) is not covered and cannot pass today.

## Test plan — one row per clause

| # | clause | case | proves it | probe (fixture inversion → must fail) |
|---|---|---|---|---|
| 1 | c | default gateway (`Config::default()`, flag untouched) serves a modern `tools/list` frame | 200 + `result` present. The method is named deliberately: the modern revision REMOVED the handshake, so asserting anything "on initialize" would validate a retired path instead of a live one | set fixture flag to `false` → must fail |
| 2 | c | default gateway's `server/discover` lists `2026-07-28` | positive fingerprint: `discover_document` can only append it when the flag is on, and the call is reachable from a legacy caller, so the modern branch is not vouching for itself | invert flag → list must lose the entry |
| 3 | a | explicit `modern_protocol: false` refuses the modern revision with `error.data.supportedVersions == []` | the flag gates serving; the empty-array fingerprint distinguishes this refusal from an earlier gate's 400 | invert to `true` → must fail |
| 4 | b | after reverting the flag, modern is refused **and** the legacy version list survives intact | revert is a revert, not a downgrade | already probed in the existing case; re-probe after restructure |
| 5 | d | default (modern-on) gateway answers a client offering `2025-06-18` **at** `2025-06-18`; repeated for `2025-03-26` and `2024-11-05` | negotiation is not one value, and holds with modern on | request an unsupported revision → the echo assertion must break |
| 6 | b | `legacy_after == legacy_before` | guard against the revert perturbing legacy behaviour | **unprobeable by construction** — an equality between two observations of the same code path. Kept as a guard; the comment says so rather than implying a probe exists. |
| 7 | c | a `server:` mapping that OMITS `modern_protocol` deserializes to `true` | this is the clause's operator-facing half. Case 1 exercises `Config::default()`; only this case exercises what an operator with a config file actually gets, and the two answer differently today because of the field-level `#[serde(default)]` | revert the serde attribute → must fail |

Cases 1 and 3 replace today's cases 1 and 2, which collapse into each other once the default
flips: `state(&default_config, default_config.server.modern_protocol)` and
`state(&Config::default(), true)` become the same state. Two tests that cannot differ are one
test. Case 3 is the old case 1 turned inside out, which is what keeps clause (a) proven after
the collapse.

Case 4 survives with its assertions intact — "before" is now the default and "after" is the
escape hatch, which fits the criterion better than the old fixture did.

## Clause (d) boundary, stated so a reviewer does not have to find it

`negotiate_version` falls back to `PROTOCOL_VERSION` for a revision *not* in `SUPPORTED_VERSIONS`
— it does not refuse. The criterion's "negotiates down to the highest revision the client
supports" reads as covering a client offering an older **supported** revision, which is what case
5 tests. Unknown-revision fallback is out of scope and is not asserted either way.

## The changes outside the test file

TWO code changes, not one. Clause (c) cannot pass without both, and no amount of test authorship
substitutes:

1. `src/config/mod.rs:1229` — `modern_protocol: false` → `true` (the struct default).
2. `src/config/mod.rs:1181` — DELETE the FIELD-level `#[serde(default)]`. The struct already
   carries a container-level `#[serde(default)]` at `:1166`, which resolves a missing field to
   `ServerConfig::default()`; the field-level attribute shadows it with `bool::default()` —
   `false`. Deleting it is the whole change; no `default = "..."` function is needed. Without
   this, (1) is invisible to every deployment that has a `server:` section, which is all of them.

**Both are gated on something outside this criterion.** `docs/requirements/RELEASE-4.0.0-blocking-rollup.md:30`
and `criteria-status.md:320` record that the flip "cannot land before cluster A wires the
continuation path, since default-on turns every gap there into a first-run defect", and that the
operator accepted that consequence on 2026-09-02. So the flip is sequenced behind cluster A, not
merely unauthorized. Until cluster A lands, clause (c) is legitimately unmet and cases 1, 2 and 7
fail for the right reason — which is the §P2 free-and-real failure, held deliberately rather than
papered over.

Risk I am naming rather than assuming: 12 files touch `modern_protocol`, several through
`Config::default()` (`tests/nfr_obs_records.rs`, `src/gateway/router/tests.rs`). No test asserts
the default *value*; that is not the same as nothing depending on the behaviour. Measurement is a
full `cargo test` before and after, not an argument. Baseline recorded below.

## Baseline (`cargo test --quiet --no-fail-fast`, before any change)

Exactly one red suite: `nfr_obs_3_era_observability`, 15 failures — an untracked file belonging to
another agent, red before this work began and unrelated to it. Everything else green;
`nfr_obs5_flag` 3/3. Reported, not chased (RED-SIGNAL TRIAGE).

## §P4a — documents this change makes untrue

Six operator-facing documents state modern is off by default. Every one is falsified the moment
the flip lands, and §P4a puts them inside the change rather than after it:

`README.md:355` · `docs/DEPLOYMENT.md:135` · `docs/requirements/RELEASE-4.0.0-pr-body.md:6` ·
`docs/requirements/RELEASE-4.0.0-execution-plan.md:39` · `docs/requirements/RELEASE-4.0.0-dod-check.md:950` ·
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:285`

These are peer-owned release documents. Named here so the obligation is visible and assignable;
not edited without the lead's ruling on who owns them.

## Out-of-scope observation (§P0 disposal: record, do not act)

`docs/requirements/RELEASE-4.0.0-gap-plan.md` (~920-945) states that `2026-07-28`'s absence from
`SUPPORTED_VERSIONS` is "the precondition for the ruling". The pinned test at
`src/protocol/mod.rs:66-88` says adding it is a *recurring misreading* and that the gate is the
default "and only that". Both cannot be right, and someone acting on the gap-plan sentence will
break a test written specifically to stop that edit. NFR.COMPAT.1's row, not this one; repairing
it is hop two. Recorded here, reported to the lead.
