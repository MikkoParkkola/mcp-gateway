# NFR.UPGRADE.1 rehearsal — results

**VERDICT: 17/17 PASS.**

Criterion (`docs/requirements/RELEASE-4.0.0-scope-update.md`): "Upgrade from 3.5.1 and
exercise modern-off/rollback with config, credentials, permissions, mounts and active
callers preserved according to the documented lifecycle." Test plan
(`docs/requirements/RELEASE-4.0.0-scope-tests.md`): "Copy realistic 3.5.1 config/token
data into an isolated deployment; upgrade, verify permissions/mounts/callers, turn
modern off, roll back; compare original and migrated data according to the documented
migration contract."

This document is evidence for that criterion. It does not itself flip
`docs/requirements/RELEASE-4.0.0-scope-status.json` from `pending` — that ledger is
graded by a separate process (`scripts/release/check_scope_acceptance.py` and whatever
reviews this evidence).

## How to reproduce

```
BIN_351=/path/to/mcp-gateway-3.5.1 \
BIN_400=/path/to/this/tree/target/debug/mcp-gateway \
RUN_DIR=$(mktemp -d) \
bash scripts/release/nfr_upgrade_1_rehearsal.sh
cat "$RUN_DIR/results.json"
```

Everything the script touches (config, OAuth tokens, version stamp, gateway ports) lives
under `$RUN_DIR/home`, isolated from the operator's real `~/.mcp-gateway`. The mounted
backend is `scripts/release/fixtures/nfr_upgrade_1_mount_stub.py`, a pure-stdlib stdio
MCP server with no network dependency, so the "active caller can still invoke a mounted
tool" checks have nothing external to flake on.

## Revision under test

- `mcp-gateway 4.0.0`, built from `8ab4bc5d66a4c5b6cc2af03dd8870de90804c58e` (tree clean
  apart from this rehearsal's own new files), `cargo build` debug profile, default
  features.
- `mcp-gateway 3.5.1` reference binary, built separately from the 3.5.1 tag, used as
  both the upgrade's starting point (phase 1) and the rollback target (phase 4).
- Run driven 2026-09-14. `results.json` reproduced across three consecutive runs with
  identical PASS/FAIL shape once the request-shape fix below landed.

## What each phase proves

1. **Phase 1 — 3.5.1 baseline.** Fresh install: `initialize` succeeds, an API key
   invokes the mounted tool through `gateway_invoke`, `version.stamp` is written as
   `3.5.1`.
2. **Phase 2 — upgrade to 4.0.0, same data dir.** `mcp-gateway upgrade` exits 0 and
   advances the stamp; `gateway.yaml` and the OAuth token file are byte-identical
   before/after (SHA-256 compared); the API key's backend scoping and the `echo_mount`
   mount both survive; the same API key still invokes the same tool post-upgrade.
3. **Phase 2b — modern protocol on by default.** A correctly-shaped 2026-07-28
   `initialize` (body `_meta` declarations, matching `Mcp-Protocol-Version` and
   `Mcp-Method` headers) succeeds; `server/discover` advertises `2026-07-28` in
   `supportedVersions`.
4. **Phase 3 — `server.modern_protocol: false`.** The same well-formed 2026-07-28
   `initialize` is refused (`-32602`/`-32022` era-refusal path); `server/discover`'s
   response — success or refusal — never lists `2026-07-28` in `supportedVersions`.
5. **Phase 4 — rollback to 3.5.1 against the 4.0.0-stamped data dir.** The stamp is
   left at `4.0.0` (older-binary-than-stamp is the `Greater` branch in
   `src/commands/upgrade.rs`'s stamp comparison, which intentionally does not rewrite
   the stamp backwards); 3.5.1's stderr logs `Downgrade detected: running an older
   binary against a newer data directory installed=4.0.0 binary=3.5.1`; the rolled-back
   gateway still answers `initialize` and the same API key still invokes the same
   mounted tool; config and token SHA-256 are unchanged by the whole rollback sequence.

## Full results

| id | status | detail |
|---|---|---|
| PHASE1.BASELINE_INITIALIZE | PASS | 3.5.1 initialize succeeded |
| PHASE1.ACTIVE_CALLER_BASELINE | PASS | API key invoked mounted backend tool through gateway_invoke on 3.5.1 |
| PHASE1.STAMP_WRITTEN | PASS | version.stamp == 3.5.1 after fresh-install run |
| PHASE2.STAMP_ADVANCED | PASS | upgrade exited 0, stamp 3.5.1 -> 4.0.0 |
| PHASE2.CONFIG_PRESERVED | PASS | gateway.yaml sha256 unchanged across upgrade |
| PHASE2.CREDENTIALS_PRESERVED | PASS | OAuth token file byte-identical across upgrade |
| PHASE2.PERMISSIONS_AND_MOUNTS_PRESERVED | PASS | api_keys[0] scoping and backend mount both intact post-upgrade |
| PHASE2.MODERN_INITIALIZE_ON | PASS | 2026-07-28 initialize accepted with modern_protocol default (true) |
| PHASE2.MODERN_DISCOVER_ADVERTISES | PASS | server/discover advertises 2026-07-28 with modern on |
| PHASE2.ACTIVE_CALLER_POST_UPGRADE | PASS | same API key invoked same mounted tool successfully on 4.0.0 |
| PHASE3.MODERN_OFF_INITIALIZE_REFUSED | PASS | 2026-07-28 initialize refused once server.modern_protocol: false |
| PHASE3.MODERN_OFF_DISCOVER_HIDES | PASS | server/discover no longer advertises 2026-07-28 |
| PHASE4.STAMP_UNCHANGED | PASS | stamp still 4.0.0 after starting the 3.5.1 binary (installed.cmp(current)==Greater leaves the stamp alone) |
| PHASE4.DOWNGRADE_WARNING_LOGGED | PASS | 'Downgrade detected' warning present in 3.5.1 stderr |
| PHASE4.GATEWAY_STARTS_NORMALLY | PASS | rolled-back 3.5.1 gateway answers initialize |
| PHASE4.ACTIVE_CALLER_POST_ROLLBACK | PASS | same API key invoked same mounted tool successfully after rollback |
| PHASE4.CONFIG_AND_CREDENTIALS_STILL_INTACT | PASS | config and token sha256 unchanged by running the rollback |

## What went wrong on the way here (test-script bugs, not product bugs)

The first full run scored 19 PASS / 2 FAIL. Both failures
(`PHASE2.MODERN_INITIALIZE_ON`, `PHASE2.MODERN_DISCOVER_ADVERTISES`) were the rehearsal
script sending the wrong wire shape, not a gateway defect:

- MCP 2026-07-28 declares protocol version and client capabilities inside
  `params._meta` (`io.modelcontextprotocol/protocolVersion`,
  `io.modelcontextprotocol/clientCapabilities`), not as flat `protocolVersion`/
  `capabilities` fields — that shape belongs to the 2025-era `initialize` handshake.
  `src/protocol/meta.rs::classify_request` requires both `_meta` keys or classifies the
  request `RequestShape::Malformed`; the `Mcp-Protocol-Version` header alone does not
  make a request modern. Fixed by adding an `rpc_modern()` helper that sends the correct
  body.
- Once the body was fixed, `src/protocol/headers.rs::HeaderCheck::validate` then
  rejected the request for a header/body mismatch it was designed to catch:
  MCP 2026-07-28 requires `Mcp-Method` to mirror the JSON-RPC `method`, and the
  rehearsal wasn't sending it. Fixed by adding `Mcp-Method` to `rpc_modern()`.
- The `PHASE3.MODERN_OFF_DISCOVER_HIDES` check originally string-matched the whole
  response body for `"2026-07-28"`. That's wrong on its own terms once the request is
  well-formed: the refusal response legitimately echoes the *rejected* version back in
  its error message (`"unsupported protocol version '2026-07-28'"`), which is not the
  same as *advertising* it. Fixed to parse `result.supportedVersions` /
  `error.data.supportedVersions` specifically and assert `2026-07-28` is absent from
  that list, rather than absent from the whole payload.

All three were caught because the first full run surfaced concrete wire-level responses,
and each was corrected against the request-shape code the gateway actually runs
(`src/protocol/meta.rs`, `src/protocol/headers.rs`), not by loosening the assertion.

## A finding outside this criterion's scope (pre-existing, not a 4.0.0 regression)

`src/oauth/storage.rs::TokenStorage::storage_key` derives a backend's OAuth token
filename from `sha256(backend_name + ":" + resource_url)[..8]` only — it does not
include the calling API key's identity. In a multi-key deployment
(`auth.single_user: false`) where more than one API key is scoped to the same OAuth
backend, all of those keys share one token file for that backend: whichever caller
authenticates first hands its grant to every other caller mounted on that backend. This
predates 4.0.0 (`upgrade.rs` never touches OAuth storage, and the key-derivation formula
is unchanged from 3.5.1), and it is out of scope for NFR.UPGRADE.1 (which asserts state
*survives* an upgrade, not that it was ever per-caller isolated). Flagging it here
because it surfaced while building the credential-preservation fixture and belongs in
front of whoever owns multi-tenant OAuth isolation, not buried in a script comment.

## Scope and limitations of this rehearsal

- One mounted backend (`echo_mount`, a synthetic stdio stub), one API key,
  `auth.single_user: true`. Multi-backend, multi-key, and `single_user: false` upgrade
  paths are not exercised here.
- OAuth "credentials preserved" is a byte-identical file check on a synthetic static
  token; no token refresh, expiry, or re-authentication flow is exercised.
- No config-reload-during-upgrade, no concurrent-instance, no crash-mid-upgrade
  scenario. Those are different NFRs' territory if they're in scope at all.
- 3.5.1 reference binary is used as-is (not rebuilt from this tree), matching what an
  operator actually runs pre-upgrade.
