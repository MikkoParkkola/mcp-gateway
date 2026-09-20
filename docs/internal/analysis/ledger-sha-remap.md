# Ledger SHA remap: 35 unreachable citations in RELEASE-4.0.0-criteria-status.md

Scope: the 35 SHAs cited in the ledger that are not ancestors of
`lane-a/surface-compaction` (release line), per team-lead's list. Method below;
table follows.

## Method (V = verified by the command shown, I = inferred, A = assumption)

1. **V** `git merge-base --is-ancestor <sha> HEAD` — ran for all 35; every one
   returned non-ancestor. Confirms the report's premise.
2. **A** Working hypothesis: these are pre-squash SHAs, surviving only on
   feature branches while the code landed under a squash-merge SHA (one case,
   `935d31d8` → `fafc943a` PR #561, was pre-confirmed).
3. **V** `git patch-id --stable` on all 35 originals vs. every commit reachable
   from HEAD: **zero exact matches**. This rules out single-commit-PR squashes
   (byte-identical diff) and means every one of these PRs squashed ≥2 commits.
4. **V** GitHub's squash-merge format concatenates every squashed commit's
   full message (subject + body) into the merge commit's body, each prefixed
   `* `. Extracted the body of every squash-merge candidate found by
   `git log HEAD --oneline --grep="<distinctive phrase from each subject>"`,
   then `rg -F` each of the 35 exact subject lines against those bodies.
   33/35 subjects matched verbatim inside one of four squash bodies:
   `c8803f06` (#568), `992b87c3` (#528), `0f04a179` (#473), `fafc943a` (#561).
5. **V** The 2 that didn't verbatim-match were resolved individually:
   - `469a3eab`: its subject text is quoted directly by the ledger itself
     (`RELEASE-4.0.0-criteria-status.md:143`), which says it "re-applies
     `0f04a179`'s `invoke.rs` hunks." Confirmed the `BridgeDispatcher`
     struct/impl it introduces is live in
     `src/gateway/meta_mcp/invoke.rs:846-908`, and traced it with
     `git log -1 -S"struct BridgeDispatcher" -- src/gateway/meta_mcp/invoke.rs`
     → `c40ed24a`, `fix(mrtr): put the MRTR.7 input bridge back on the
     production invoke path (#571)`.
   - `9cf1557b`: no squash body contains its subject, and its diff (2 new test
     fns in `tests/mik_7272_sub2b_acs.rs`) is absent from that file on the
     release line. See MISSING section below.
6. **V** `git log <mergecommit> --format='%s'` for every replacement carries
   its PR number inline (GitHub squash format `... (#NNN)`), so no `gh pr
   view` round trips were needed.

## Table

| Cited SHA | Subject | State | Replacement / proof | PR |
|---|---|---|---|---|
| `039e7c2a` | ci(docker): start the image before publishing it | REMAPPED | `c8803f06` (V: subject verbatim in squash body) | #568 |
| `0c81988f` | test(sub4): score the permission half of session-expiry recovery | REMAPPED | `992b87c3` (V) | #528 |
| `1f695846` | fix(transport): derive the GET stream's protocol version from the negotiated era | REMAPPED | `0f04a179` (V) | #473 |
| `237b30f2` | fix(stdio): refuse a bridged prompt that close overtook on a full queue | REMAPPED | `fafc943a` (V) | #561 |
| `2415fdc9` | fix(stdio): stop admitting requests once stdout is gone | REMAPPED | `fafc943a` (V) | #561 |
| `322de814` | fix(mrtr): keep a firewall refusal typed when it is replayed from the cache | REMAPPED | `fafc943a` (V) | #561 |
| `34897a8a` | feat(idempotency): deny resend without an explicit tool annotation | REMAPPED | `992b87c3` (V) | #528 |
| `35cfbda8` | feat(idempotency): settle a dispatched call that errored as a terminal failure | REMAPPED | `992b87c3` (V) | #528 |
| `364f4373` | test(acs): release the parked stdio call through the fixture's own gate | REMAPPED | `992b87c3` (V) | #528 |
| `3df3ffca` | docs(design): match the stdio writer section to the bounded queue | REMAPPED | `fafc943a` (V) | #561 |
| `424a2df0` | feat(continuation): per-process continuation key rotation (NFR.SEC.3) | REMAPPED | `0f04a179` (V) | #473 |
| `469a3eab` | feat(mrtr): wire the legacy-client input bridge into the invoke path | REMAPPED | `c40ed24a` (V: `BridgeDispatcher` live at `invoke.rs:846`, `git log -S` traced) | #571 |
| `482746c1` | chore(release): track server.json version with the 4.0.0 crate version | REMAPPED | `0f04a179` (V) | #473 |
| `527bb065` | test(idempotency): observe resend deliveries at the backend | REMAPPED | `992b87c3` (V) | #528 |
| `66d1fc23` | fix(firewall): commit the response-block definitions its caller already uses | REMAPPED | `992b87c3` (V) | #528 |
| `6984f905` | feat(transport): route resend permission and redirect evidence through one dispatch | REMAPPED | `992b87c3` (V) | #528 |
| `6fc9471b` | docs(release): narrow two SUB.2b claims to what was measured | REMAPPED | `992b87c3` (V) | #528 |
| `71bacf01` | style(tests): satisfy the lint and format gates in the sub2b rows | REMAPPED | `992b87c3` (V) | #528 |
| `7781719f` | test(confirm-1a): witness the two unwitnessed Unsupported producers | REMAPPED | `0f04a179` (V) | #473 |
| `7912f3fc` | ci: gate both image publishers on a container that starts | REMAPPED | `c8803f06` (V) | #568 |
| `8c1c6574` | feat(mrtr): gate bridged challenges through the response firewall | REMAPPED | `fafc943a` (V) | #561 |
| `976c56b7` | fix(mrtr): refuse a resume step outside the chain instead of indexing it | REMAPPED | `fafc943a` (V) | #561 |
| `9b0caa1e` | docs(design): withdraw the stdio start-order guarantee | REMAPPED | `fafc943a` (V) | #561 |
| `9cf1557b` | test(sub2b): cover the command-backend leg of S-02 | **MISSING** | see below | — |
| `a27d5f36` | test(release): align two fixtures with the surface that shipped | REMAPPED | `0f04a179` (V) | #473 |
| `a3409375` | fix(mrtr): settle the idempotency key when a refused round already dispatched | REMAPPED | `fafc943a` (V) | #561 |
| `b7a4a768` | feat(mrtr): wire the input bridge into the invoke path | REMAPPED | `0f04a179` (V) | #473 |
| `cef7972f` | feat(security): prove a connect failure is pre-dispatch | REMAPPED | `992b87c3` (V) | #528 |
| `d0c68e15` | fix(stdio): stop admission from parking the only stdin reader | REMAPPED | `fafc943a` (V) | #561 |
| `ead3e40b` | fix(docker): give the runtime user a home directory | REMAPPED | `c8803f06` (V) | #568 |
| `edccc0b6` | fix(router): mint a progress token on the direct backend route too | REMAPPED | `992b87c3` (V) | #528 |
| `f39cea7d` | fix(stdio): close the stdout-death windows the review found | REMAPPED | `fafc943a` (V) | #561 |
| `f612b7e8` | test(stdio): pin the admission and inflight caps over the real binary | REMAPPED | `fafc943a` (V) | #561 |
| `f85ce838` | feat(backend): mint a gateway progress token on outbound calls | REMAPPED | `992b87c3` (V) | #528 |
| `fffc5fde` | fix(stdio): log a refusal that cannot be queued | REMAPPED | `fafc943a` (V) | #561 |

Counts: **REMAPPED 34** · **PRESENT-BY-CONTENT 0** · **MISSING 1**.

## MISSING (the important one)

### `9cf1557b` — test(sub2b): cover the command-backend leg of S-02

- **Ledger row**: `docs/requirements/RELEASE-4.0.0-criteria-status.md:233`,
  criterion **`MIK-7272.SUB.2b`** (verdict on that row: `MET (caveat)`).
- **What the row claims (V, quoted)**: "Two more landed in `9cf1557b` (tests
  only, 160 insertions, nothing under `src/`):
  `s02_progress_from_a_command_backend_reaches_the_client_before_the_result`
  (`:1667`) is the first row in the file to configure a `command:` backend..."
- **What's actually on the release line (V)**:
  `rg -n "async fn s02_" tests/mik_7272_sub2b_acs.rs` returns 6 functions, none
  named `s02_progress_from_a_command_backend...`. The file has 1587 lines of
  pre-existing content (matches the pre-`9cf1557b` diff context) and none of
  the two functions the commit added —
  `s02_progress_from_a_command_backend_reaches_the_client_before_the_result`
  and `a_command_backend_notification_with_no_client_token_is_not_forwarded`
  (`git show 9cf1557b -- tests/mik_7272_sub2b_acs.rs`, both `+fn`/`+async fn`
  lines) — exist anywhere in the repo (checked full path, not just that file).
  No squash body among the 5 replacement merges quotes this subject either.
- **Consequence**: `MIK-7272.SUB.2b` is graded `MET (caveat)` partly on the
  strength of a `command:`-backend regression test that never reached the
  release line. The row's other citations (`364f4373`, now confirmed
  REMAPPED into `992b87c3` #528) are fine; only the `9cf1557b` evidence is
  unverifiable — that criterion's status should be re-examined against
  whichever subset of its citations actually ship.

## Not investigated further

Per the instructions, only `9cf1557b` needed doubt raised — the other 34 all
resolved cleanly to a specific replacement commit with an inline PR number,
so no criterion row backed only by a REMAPPED SHA is in question.
