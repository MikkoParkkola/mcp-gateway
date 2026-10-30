# ADR-029: Enforced policy lives in gateway.yaml, and the Policies screen edits it there

- **Status**: Accepted, 2026-10-27 (three review rounds; the last round's precision findings are folded in and carried by POLICY.2's test plan). Amendment of 2026-10-30 (live apply, below): Accepted, 2026-10-30, ratified by the lead after three design rounds and a narrow fourth, each reviewed by two independent reviewers; every finding is folded in
- **Criteria**: POLICY.1; shapes POLICY.2 (schema), POLICY.4 (save path) and POLICY.6 (control-plane route)
- **Base**: `docs/ranking-1-release-line` at `267074e92`

## Context

The Policies screen edits rules, their actions, data sensitivity and exceptions. Two places could hold what it saves:
the gateway config, and the control-plane policy store. Only one of them changes what the gateway does.

| # | Fact | Where |
|---|---|---|
| F1 | `security.firewall.rules` decide **findings only**: each finding takes the first rule whose `match` covers the tool and whose `scan` holds its type, else its severity default. A call with no findings resolves to Allow whatever the rules say, so a rule cannot block a tool by name. | `security/firewall/mod.rs:614`; request side `chokepoint.rs:279`, `backend_handlers.rs:174`, `dispatch_tools_call.rs:301`, `watch_poll.rs:70`; answer side `firewall/response.rs:43` |
| F1b | Some firewall blocks bypass the rules entirely: a blind or forced anomaly block, a blind tenant guard, a budget refusal. No rule or exception softens them. | `security/firewall/mod.rs:404` |
| F1c | A rule has no direction field: a rule applies on whichever side made the finding, and an empty `scan` list decides every type on both sides. The stateless rescan resolves by tool name alone. | `firewall/config.rs:147`; `firewall/mod.rs:332` |
| F2 | `security.tool_policy` blocks tools by name before dispatch. Its compiled effect is more than the YAML lists: built-in default denies (`use_default_deny`), a `default_action`, allow-over-deny, and a `server:tool` qualified grammar. | `security/policy.rs:18,160-205`; `gateway/authz.rs:487`, `router/authorization.rs:347` |
| F2b | Other enforced tool limits live elsewhere: per-key `allowed_tools`/`denied_tools` under `auth.api_keys`, and identity grants in the file named by `security.identity_grants.path`. | `config/features/api_key.rs:93-100`; `mutations.rs:302` |
| F3 | The collusion gate's `sources` are declared sensitive sources; it also reads inferred context-integrity classifications. `non_egress` and `allowed_flows` are relay exceptions. All of it is inert while `collusion.action` is `off`, its default. It judges cross-principal relays, and under `block` it also refuses unkeyed egress (`collusion_gate.rs:374`). | `firewall/collusion_gate.rs:72`; `collusion_gate_receipts.rs:168` |
| F4 | Credential redaction in answers is the global switch `security.firewall.credential_redaction` (on by default). It runs before any rule is read, and only while the firewall and `scan_responses` are on. | `firewall/response.rs:27,81` |
| F5 | `security.sanitize_input` and `security.ssrf_protection` are switches read at start. | `gateway/server/run.rs:420-421` |
| F6 | The control-plane store holds `{policy_id, name, enforced}` rows in `policies.json` and nothing in dispatch reads it. A write answers 503 when the store is unavailable, else RBAC, else 409 `policies_managed_in_gateway_config`, before any store or audit write. | `control_plane/mod.rs:316`; `ui/control_plane/mutations.rs:308-331` |
| F7 | The UI's policy rows today are the two switches only (`local:input_sanitization`, `local:ssrf_protection`), built from running config. | `ui/control_plane/snapshot.rs:209` |
| F8 | Today `security` is one restart-pending reload section. The UI writer (ADR-024) and per-field live apply (ADR-023) are planned work, not yet on the line. | `config_reload/diff.rs:214`; ADR-023, ADR-024 |

So the policies this screen covers are all in gateway.yaml, and the store is a list nobody reads.

## Options

1. **gateway.yaml under `security` is the one source of truth for this screen.** The screen reads the running config and saves through the ADR-024 writer. The store is never offered as editable.
2. **Replace the YAML policy with the control-plane store.** Dispatch would read `policies.json` instead of `security`. Its strongest form is a single store with a schema built for the UI. Rejected: the store's `{id, name, enforced}` rows cannot express a rule, a scan list or an exception; hand-edited and Git-reviewed config would lose its authority; every existing deployment would need a migration.
3. **Both, synchronised.** Two copies that must agree, plus a sync that can fail between them. Rejected for the reasons of option 2, with an extra failure mode.

## Decision

Option 1, scoped to the fields below. Out of scope, and edited where they are today: identity grants (their own file) and per-key tool lists (`auth.api_keys`, the Keys screen) (F2b).

| On the screen | In gateway.yaml | Notes |
|---|---|---|
| "Block tools by name", its own section | `security.tool_policy` (`enabled`, `allow`, `deny`, `default_action`, `use_default_deny`) | Firewall rules cannot do this (F1). The section shows the effective compiled policy: the built-in default denies, `default_action`, and that an allow beats a deny (F2). While `enabled` is false every entry is inert: the section says so and offers turning it on in the same save. Entries the screen creates are written qualified, `server:tool`, because a bare name matches that tool on every backend (`security/policy.rs:206`). Existing bare and prefix entries, and `log_denied`, are kept verbatim and shown read-only unless explicitly edited. Each entry shows its effective verdict, and the diff names any allow entry that overrides a deny being saved (`policy.rs:168`). A blocked tool also disappears from discovery, not just from dispatch (`router/authorization.rs:330`) |
| "Decide what happens to findings", its own section: what is checked, on which tools, and the action | `security.firewall.rules[]`: `match`, `scan` (always non-empty when written from the screen), `action` (`block`, `warn`) | Offered scan types: `credentials`, `prompt_injection`, `shell_injection`, `path_traversal`, `sql_injection`, `memory_poisoning`. Each is shown with the side that produces it, the switch it needs (`credential_redaction`, `prompt_injection_detection`, `scan_requests`, the memory scanner and its configured tools) and whether that is on; the diff names any precondition that is off, since a rule for a type nothing produces decides nothing (`firewall/mod.rs:310`, `response.rs:81`, `memory_scanner.rs:171`). Not offered: `collusion_relay` (decided by the collusion gate alone, `collusion_gate.rs:406`), the guard types `sequence_anomaly`, `cross_tenant_reach`, `budget_exceeded` (their own config), and `pii` (no scanner produces it). No call/answer choice: the screen shows the side or sides each chosen type runs on (F1c). Rules are shown in their order, with an earlier rule that shadows an edited one named. A rule the screen cannot represent (`action: allow`, a `reason`, an empty `scan`, or a scan type outside the offered list) is shown read-only and kept verbatim by the writer |
| Guard blocks, when enabled | anomaly (`anomaly_block_threshold`), tenant guard, budget guard | Read-only, each with its running state; all three are off by default and stop when the firewall is off. Only their blind and forced cases are rule-proof (`firewall/mod.rs:404`): a blind or forced anomaly block, an unattributable tenant read, a budget refusal. Their ordinary findings (a tenant-limit refusal, a Low anomaly) pass through the finding rules like any other (`mod.rs:479`, `anomaly_gate.rs:108`), and the screen shows them as rule-decidable (F1b) |
| Credentials: remove them, pass the rest | the global `security.firewall.credential_redaction` switch **and** one rule `{match: "*", scan: [credentials], action: warn}` | Both are needed: redaction removes the credential, but the redacted credential is still a High finding, and High defaults to block (`firewall/redactor.rs:487`, `verdict.rs:131`, `meta_mcp/invoke/egress.rs:221`). The rule is identified by that exact shape, so saving again is idempotent. It goes before any rule that also covers credentials, and the diff names a rule it shadows or that shadows it (first match wins, `verdict.rs:116`). The screen saves switch and rule in one diff, and shows the action as unavailable while the firewall or `scan_responses` is off (F4). Scope: final answers the gateway may rewrite. A credential in a protected member of an interim question or a challenge still refuses the whole artifact (`response.rs:48`, `response_policy.rs:56-64`), and the screen says so |
| Applies to: servers, keys | new optional `servers:` and `keys:` on a rule (POLICY.2) | Requires server and authenticated key to reach every resolution: `check_request`, the stateless `rescan` and the answer side (F1c). POLICY.2 decides whether the existing `server:tool` grammar covers `servers:` |
| Exceptions | new optional `except:` on a rule (POLICY.2) | Never applies to the always-on guards |
| Relay sensitivity, labelled "declared" | `security.firewall.collusion.sources`, `non_egress`, `allowed_flows`, and `collusion.action` | The row states what the saved action does: `off` checks nothing, `observe` records relays and lets them through, `block` refuses them and also refuses unkeyed egress (`collusion_gate.rs:374`), which the diff names when switching to `block`. All of it needs `security.firewall.enabled`. The inferred sensitive classes are shown read-only beside the declared sources (F3) |
| Input sanitization, SSRF protection | `security.sanitize_input`, `security.ssrf_protection` | |

- **Saved through the ADR-024 writer only** (POLICY.4): diff first, in place, all or nothing, admin only, in the admin audit. No second writer.
- **Applied per field through ADR-023's reload path** (POLICY.3), once it lands. Until then every field on this screen is marked "needs a restart" before Save (F8). The live claim is made per field, only for fields with a masking test that leaves them out of the restart comparison.
- **The control-plane policies route** (POLICY.6) never answers 2xx for a write to the store, and refuses whether or not the store is available. Until the save path exists it keeps the refusal, with a message that names the real keys. After that it writes through the ADR-024 writer or is retired.
- **The store stays readable** and is offered as editable nowhere. Retiring `policies.json` is a separate change with its own upgrade note.

## Tool limits: what exists, and no new kind

Every check below must permit a call, and none can widen another. Firewall finding rules are not among them: they decide findings in calls these checks let through (F1). The table is the configured tool limits; it is not every refusal the gateway can make (routing profiles and identity grants also refuse, inside `meta_mcp/visibility.rs:63`).

| Limit | Setting | Meaning | Edited on |
|---|---|---|---|
| Global | `security.tool_policy` | tools blocked by name for every caller and backend | this screen, "Block tools by name" |
| Key | `auth.api_keys[].allowed_tools` / `denied_tools`, and the key's backend scope | what one key may call | the Keys screen |
| Certificate | `mtls` policy | what a client certificate may call (`router/authorization.rs:361`) | gateway.yaml |
| Agent | OAuth agent scopes | what an OAuth agent may call (`router/authorization.rs:387-394`) | gateway.yaml |

On HTTP the four run as one chain (`router/authorization.rs:341-394`, `decide_tool_target`): the key's backend scope, then `tool_policy`, then the key's tool scope, then certificate policy, then agent scopes. On stdio only `tool_policy` applies (`gateway/authz.rs:456-490`). This screen edits only the global limit.

**Planned, not yet in the code:** a per-backend selection, `backends.<name>.allowed_tools`, under its own ticket, out of scope here. Whatever its final form, it must be a fifth limit of the same kind: it only narrows, and every route checks it. A new way to limit tools extends one of these limits; it does not add a new kind.

**POLICY.2 fixtures:** worked YAML diffs for the coupled credential save, a shadowing firewall rule, and a tool deny overridden by an allow.

## Known limit

"Remove credentials, pass the rest" works on a tool's final answer. If a credential appears inside a question the tool asks you mid-call, or inside a sign-in challenge, the gateway cannot remove just the credential there without breaking the question. So it blocks that whole message instead, and the Policies screen says so next to the setting.

## Consequences

- No second store, so no precedence rule between stores. The audit names the finding and the action taken. It does not name a matching rule, because a severity default or an always-on guard can decide without one (F1, F1b).
- Policy edits get the same diff, stale-file check and comment-preserving save as every other UI edit.
- A config file edited by hand stays authoritative. The screen shows what is running, read from the live config. Today that means two switch rows (F7); the other rows are new work.
- Rules scoped by server and key need the server and the authenticated key threaded into every rule resolution, including the stateless rescan (POLICY.2).
- Tool blocking by name and finding rules stay two separate models (F1, F2). Revisit folding them into one when effective-policy display shows operators keeping both lists for the same tools.
- `policies.json` remains an unread file until it is retired.

## Amended 2026-10-30: policy fields apply live on reload (POLICY.3, POLICY.8, POLICY.11)

The Decision's "applied per field through ADR-023's reload path" is settled here. Every field on the Policies screen goes live in 4.0.0, each with the reason it is safe. Line numbers are at `docs/ranking-1-release-line` `1b540514a8`.

| # | Fact | Where |
|---|---|---|
| L1 | A request is judged under one generation, pinned on arrival; a reload publishes a new one without touching requests already admitted. | `config_reload/generation.rs:14`; `router/handlers/dispatch_intake.rs:51`; `router/mod.rs:800` (`pinned_generation`) |
| L2 | `security.tool_policy` compiles once into an `Arc<ToolPolicy>` held beside the router, not in the generation. | `router/mod.rs:399` |
| L3 | `Firewall` holds the compiled rules beside per-principal and per-process state: the anomaly detector, the tenant guard and its read history, the call budget and the relay gate. Rebuilding it resets that state. | `security/firewall/mod.rs:92-123` |
| L4 | The relay tracker classifies each delivery when it records it: whether its source was sensitive (kept in a separate `sensitive` store), and which `allowed_flows` entries the copy may leave through, one bit per entry by position (a plan seam keeps one mask per contributing source). A witness reads those held bits; it does not re-judge them against the lists. | `security/firewall/collusion.rs:99-104`, `:119-138`, `:401-415`; `collusion_gate.rs:182-190` |
| L5 | Retention depends on the record-time class: over a caller's cap or the pool, plain records are dropped and sensitive ones are kept as overflow. | `collusion.rs:247-249` |
| L6 | The mode (`off`, `observe`, `block`) is read from the detector's own parameters at witness, and the compiled `sources`, `non_egress` and `flows` live in the relay gate, both fixed at startup. | `collusion.rs:589-591`; `collusion_gate.rs:182-190` |
| L7 | All relay evidence is in memory: a restart starts with none. | `collusion.rs:240-255` (no persistence in `collusion*.rs`) |
| L8 | Today every `security` field except `sanitize_input` and `ssrf_protection` is compared for restart and reported as needing one. | `config_reload/diff.rs:263` |

### Decision

1. **`security.tool_policy` and `security.firewall.rules` go live** (match, scan, action, `servers`, `keys`, `except`), by U19's PR4 mechanism.
   - **One rule set per request.** Both compile when the generation is prepared, so a reload carrying an invalid rule is refused and the running generation stays. Every check a request reaches reads its pinned generation's rules: route scan, dispatch rescan, answer side, bridge, task dispatch (per dispatch). Without the pin, one request could pass a request-side check under the old rules and an answer-side check under the new ones. Each complete configuration would deny that call, but the mix would let it through. The pin removes that mix, and it is also the key-by-policy barrier (POLICY.11).
   - **State outside the generation.** The firewall keeps only its state (L3) across a reload and takes rules from the request's generation. No budget, anomaly history, tenant read or relay evidence is reset.
2. **`security.firewall.collusion`'s `sources`, `non_egress`, `allowed_flows` and `action` go live**, by recording facts at delivery and judging them at witness against the witnessing request's pinned generation.
   - **Facts recorded per delivery**, on every holder of evidence: the exact copy, the plain copy kept under the cap, the overflow slot, the plan seam, and the replay receipt.
     - The raw source identity (`server:tool`). A seam keeps, per contributing source, that source's identity and its own pre-redaction inferred fact; it stores no combined bit (today the OR at `relay_seams_record.rs:93`). Seam overflow is grouped by the exact set of contributor identities and inferred facts, within the receipt byte limits, never merged across sets by a record-time decision (`relay_seams_record.rs:129`), so a source edit re-judges only the seams it contributed to.
     - The inferred-sensitivity fact: `context_integrity_sensitive(result)` itself (not `DeliveryDigest.sensitive`, which mixes in the list match; `collusion_gate_receipts.rs:168`), taken before any redaction, a property of the data, not of the lists. A redacted rebuild (`relay_delivered.rs:143`, `:229`) carries only this pre-redaction fact across, never a bit that mixes in the list match.

     These replace L4's declared-sensitivity bit and position mask. An inferred copy keeps its timestamps in the existing sensitive `Copies` slot (`collusion.rs:99`), which a later plain delivery never extends, so the fact expires with its own copies.
   - **Judged at witness.** The egress check reads `sources`, `non_egress`, `allowed_flows` and `action` from the witness's pinned generation.
     - **Sensitive:** a held copy, plain or sensitive slot alike, is sensitive when its inferred fact is set or its source matches the current `sources`. Today's filter reads only the sensitive slot (`collusion.rs:646`); after this change a plain copy still held under the cap is caught once its source is added.
     - **Seam:** sensitive when any contributor's inferred fact is set, or any contributor matches the current `sources`.
     - **Allowed flow:** a current `allowed_flows` entry covers the (source, egress) pair. For a seam, every contributing source must have such an entry for that egress, as `Flows::Each` requires today. The composite seam name is never matched.

     Nothing is held by position, so a reload that adds a sensitive source, or removes or reorders a flow, applies to every held copy at the next witness.
   - **Mode follows the generation, not the startup.**
     - **The detector and the replay store are always built.** Today `detector_for` builds none when `action` is `off` (`collusion_gate.rs:271`). Every gate on the startup action is removed:
       - the detector's own early returns (`collusion.rs:425`, `:590`);
       - the record paths (`collusion_record.rs:65`, `record_holder_at`);
       - the seam excuses (`collusion_seam_excuse.rs:494`);
       - the observe-or-block decision in `check_relay` (`collusion_gate.rs:367`), which reads the witness generation.
     - **Recording** follows the action of the generation current at delivery: a call admitted while it was `off` that delivers after a switch to `block` is recorded. The replay snapshot store follows the same gate: `store_replay` and `capture_commit` (`collusion_gate_replay.rs:60`) store nothing for a delivery whose effective action is `off`, so no copy delivered while off is held anywhere. A steady `off` gateway records nothing. It still stages a receipt's pre-delivery facts (source identity, inferred fact), so a receipt delivered after activation keeps them.
     - **Observe versus block** follows the witness's pinned generation. An effective `off` at witness checks nothing: `check_relay` (`collusion_gate.rs:367`) allows at once without consulting the detector, never falling through to observe or audit.
     - **Limit:** copies delivered before a switch from `off` are not held, so a relay of them is not seen. A restart into `block` gives the same.
   - **Activation needs the running detector to match.** `window_secs`, `min_matches` and `common_principals` are fixed when the detector is built.
     - The generation carries an effective collusion view, computed when it is prepared and compared with the running detector, not with the previous generation, so an edit left pending by an earlier reload still counts.
     - **Effective view = the new four live fields** when the new config's `window_secs`, `min_matches` and `common_principals` equal the running detector's and the running firewall is enabled.
     - **Otherwise, effective view = the previous generation's effective view** of the four fields (not `LiveConfig.running`, which stays at the startup config), unchanged, and `security` reports as needing a restart. So a later detector-parameter edit can never drop an already-live `block` back to the startup action. The published config still carries the edit, ready for the restart.
     - **Every reader takes the effective view:** witness, recording and the screen's "running" display. So `block` never runs on a window or thresholds the operator did not set, and an action-only second reload cannot bypass the check.
   - **Overflow keeps sources, within a budget.** Today an overflow slot is one merged entry per caller with no source (`collusion_holders.rs:144`).
     - It now holds a bounded set of (source, inferred fact) pairs under a fixed byte budget per caller and in total.
     - When a caller's set is full, the slot is marked unattributed: judged sensitive and covered by no flow, so it fails closed until it ages out.
     - A saturation test fills one caller with many sources.
   - **The other collusion fields stay restart-only:** `window_secs`, `min_matches` and `common_principals`. They stay in the restart comparison and report as needing a restart.
     - **Not on the Policies screen.** ADR-029's table offers only `sources`, `non_egress`, `allowed_flows` and `action`. They are detector tuning, restart-only like every other `security` field the screen does not edit (ADR-023), not a safety fallback.
     - **Per field, for the record.** Two are applied when evidence is recorded, so a live change cannot be made safe within this ticket:
       - `window_secs`: recording expires holders by it, coalesces held copies' timestamps under it, and stamps lost-evidence markers at `now + window`; the sweep also uses it (`collusion.rs:193`). A shorter live window drops held evidence irreversibly, and a longer one cannot restore what was dropped.
       - `common_principals`: recording turns a fingerprint held by that many principals into `Common` and discards its holder records, and the egress check never reads the threshold again (`collusion.rs:544`). A raised value cannot reclassify text already made common.

       `window_secs` is also read at witness, to decide which copies are held (`collusion.rs:594`), so it is not judgement-only either. Only `min_matches` is read solely when a relay is judged and could go live by the pin; it stays restart-only because no screen edits it.
3. **Retention (L5): what this does not guarantee.**
   - **Retention priority** is still decided when a copy is recorded, by the recording generation's lists plus the inferred fact. A replayed receipt recomputes it when re-recorded, never copying a stored decision.
   - **A source made sensitive after the fact:** its copies still held, plain ones included, are judged sensitive at the next witness. Plain copies the cap dropped before the reload are gone. The cap bounds the evidence held, not the number of deliveries lost, so a relay of a dropped copy is missed. This is a stated detection limit, not a fail-closed guarantee.
   - **A source made non-sensitive:** its held copies and overflow pairs are judged plain at the next witness and stop refusing. Only an unattributed overflow slot keeps refusing until it ages out.
   - **What is and is not re-classified:** every retained copy is judged against the current lists, so retained evidence is effectively re-classified at each witness. Dropped evidence cannot be recovered by any design short of keeping every plain copy with no cap, which is the memory bound L5 exists for.
4. **`security.firewall.credential_redaction` goes live with the rule it pairs with.** The screen's "remove credentials" row saves both the switch and a rule. `check_response_artifact` reads the switch and the rules from one generation (today two separate startup fields, `response.rs:111`), so a response is never judged by the new rule with the old redaction. Everything else under `security` (other scanner switches, anomaly, tenant and budget settings, the identity grants path) stays restart-only and reported, as ADR-023 says.
5. **Every judging site reads one generation.** This is the boundary matrix the tests cover; each site reads tool policy, rules, collusion and redaction from it.
   - **The request's pinned generation:** route scan, discovery filter, dispatch rescan, answer side (protected responses included), bridge delivery, collusion witness.
   - **The generation taken for each stdio line**: stdio authorization and every firewall check on that line. Today the loop takes the generation at `stdio_loop.rs:316` but copies only `sanitize_input` (`:319`), and the dispatch closes over the startup `ToolPolicy` (`:419`). The `Arc<Generation>` taken at the line read is held and threaded through the dispatch in its place, through both the single-request and the batch closures (`stdio_loop.rs:509`), and into `relay_refusal` and `judge_and_commit`.
   - **The generation current when the dispatch runs:** queued task dispatch.
   - **The generation current at delivery:** collusion recording (item 2).
   - **The generation current at scan time** (on `Services.live`, as a task dispatch reads it): event payload scans (`events/services.rs:357`). An event delivery has no request to pin.
   - **The restart comparison** masks `tool_policy`, `firewall.rules`, `firewall.credential_redaction` and the four live collusion fields, with a test that each alone reports no restart. Each of `window_secs`, `min_matches` and `common_principals` alone still reports one, so a mask of the whole collusion object fails.

### Consequences for the policy criteria

- **POLICY.3**:
  - For each of `default_action`, allow, deny, `use_default_deny` and a firewall rule's action, a reload changes a dispatched call's outcome with no restart, on HTTP and on stdio.
  - On stdio, a reload published between a line's capture and its dispatch leaves that line judged under the captured generation.
  - A reload carrying an invalid rule glob is refused, and the running rules still apply.
  - Anomaly, tenant, budget and relay state is unchanged across a rule reload.
- **POLICY.8**: one row per path, each with a mutant that restores the record-time or startup decision it replaces (the held bit, the position mask, the startup action, the sensitive-slot-only filter, the combined bit across redaction), which must turn its row red:
  - a removed flow;
  - an added sensitive source, caught on a sensitive copy and on a plain copy kept under the cap;
  - reordered flows (no verdict changes);
  - a removed `non_egress` entry;
  - `off` to `block`: a copy delivered after the switch is caught, including one from a call admitted while `off`;
  - an activation combined with a detector-parameter edit, which applies nothing live and reports a restart. Then an action-only second reload while that edit is still pending, which also applies nothing;
  - a multi-contributor plan seam, allowed only when every contributor's flow is allowed;
  - overflow pairs after a source is made non-sensitive and after a source is added, a saturated caller's unattributed slot, the total budget exhausted across callers, and an unattributed marker expiring on its own clock;
  - a replayed receipt, including one staged and redacted while `off` and delivered after activation;
  - a seam whose contributor is added to, or removed from, `sources`, including after seam overflow holds more than 16 contributor groups;
  - an effective `off` at witness with receipts held, which checks nothing and audits nothing;
  - a delivery committed while `off`, then a switch to `block`: its replay snapshot was never stored, so a relay of it is not refused;
  - a live `block`, then a detector-parameter edit: `block` stays effective and a restart is reported;
  - an inferred-sensitive delivery from an undeclared source, including through a redacted rebuild, and its expiry with no extension from later plain deliveries;
  - `credential_redaction` turned on together with its rule.
- **POLICY.11**: the barrier rows in both directions, one mutant per site, each matched to that site's contract.
  - Pinned sites (auth, intake, tool policy, firewall request side, firewall answer side, collusion witness, dispatch, stdio line): the mutant reads the current generation instead of the pinned one.
  - Current-at-run sites (queued task dispatch, event scan, collusion recording): the mutant reads the startup firewall, or a second generation read, instead of the one the contract names.
- **ADR-023**: its 2026-10-26 amendment (collusion restart-only) is superseded by item 2; `tool_policy`, `firewall.rules`, `firewall.credential_redaction` and the four live collusion fields join its live set.

### Size

- **Items 1, 4 and 5** (U19 PR4, with the stdio, event-scan and redaction sites): about 6 to 8 points.
- **Items 2 and 3** (relay tracker): about 10 to 13 points. They cover:
  - source identity and the pre-redaction inferred fact on every holder;
  - the bounded source-aware overflow;
  - seams and replay receipts;
  - the always-built detector with no startup early returns;
  - the activation check;
  - witness-time lists, action and plain-slot judging;
  - the rows and mutants above.
- **Together**: about 16 to 21 points, in two PRs: items 1, 4 and 5 first, then items 2 and 3.
