# ADR-029: Enforced policy lives in gateway.yaml, and the Policies screen edits it there

- **Status**: Accepted, 2026-10-27 (three review rounds; the last round's precision findings are folded in and carried by POLICY.2's test plan). Amendment of 2026-10-30 (live apply, below): proposed, under review
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
2. **All of `security.firewall.collusion` goes live** (`sources`, `non_egress`, `allowed_flows`, `action`), by judging at witness time instead of at record time.
   - **Record facts, not verdicts.** Each delivery's copy records its raw source identity (server and tool; for a plan seam, the set of contributing sources) in place of L4's sensitivity bit and position mask.
   - **Judge at witness.** The egress check reads the compiled lists and the mode from the witnessing request's pinned generation, then decides: is the held copy's source sensitive now, is the egress non-egress now, and does an allowed flow cover this (source, egress) pair now.
   - **Why this is safe.** No held verdict can disagree with the rules: a reload that adds a sensitive source or removes a flow applies to every held copy at the next witness. Reordering entries changes nothing, because nothing is held by position.
   - **The compiled lists** move into the generation; the relay detector keeps only its evidence store, shared across generations as L3's state is.
3. **Evidence that outlives a swap: retention (L5).** Record-time sensitivity also decides which copies survive the cap. After this change, retention follows the record-time generation's lists (a copy whose source was sensitive when recorded keeps overflow priority), and judging follows the witness-time lists.
   - **A source made sensitive after the fact** may have lost older plain copies to the cap before the reload. That loss is bounded by the cap and the window, and it is never worse than a restart, which holds no evidence at all (L7).
   - **A source made non-sensitive** keeps its overflow copies until they age out, but they are judged plain, so nothing is refused for them.
   - **Rejected alternative:** re-classifying the held store on every reload. It needs every plain copy kept with no cap, which is the memory bound L5 exists for.
4. **Everything else under `security`** (scanner switches, redaction, anomaly, tenant and budget settings, identity grants path) stays restart-only and reported, as ADR-023 says. The restart comparison masks `tool_policy`, `firewall.rules` and `firewall.collusion`, with a test that each one alone reports no restart.

### Consequences for the policy criteria

- **POLICY.3**:
  - For each of `default_action`, allow, deny, `use_default_deny` and a firewall rule's action, a reload changes a dispatched call's outcome with no restart.
  - A reload carrying an invalid rule glob is refused, and the running rules still apply.
  - Anomaly, tenant, budget and relay state is unchanged across a rule reload.
- **POLICY.8**:
  - A reload that removes an allowed flow makes the next witness of a copy recorded before the reload, leaving through that flow, a relay.
  - A reload that adds a sensitive source makes the next witness of an earlier copy from that source a relay.
  - A reload that reorders `allowed_flows` changes no verdict.
  - Each row has a mutant that reverts to record-time judging (the held bit, the position mask), and that mutant must turn its row red.
- **POLICY.11**: the pin's barrier rows in both directions, one mutant per boundary: auth, intake, tool policy, firewall request side, firewall answer side, collusion witness, dispatch. Each mutant makes its boundary read the current generation instead of the pinned one.
- **ADR-023**: its 2026-10-26 amendment (collusion restart-only) is superseded by item 2; `tool_policy`, `firewall.rules` and `firewall.collusion` join its live set.

### Size

- **Item 1** (U19 PR4): about 5 points. It moves two compiled views into the generation, threads the pinned generation to the firewall's checks (route, rescan, answer side, bridge, tasks), masks the restart comparison, and adds the rows above.
- **Item 2 and item 3**: about 5 to 8 points, in the relay tracker's record and witness paths. Copies carry source identity in place of bits; the egress check takes the lists from the generation; plan seams keep contributor sets. It adds the POLICY.8 rows and mutants.
- **Together**: about 10 to 13 points, in two PRs: item 1 first, then items 2 and 3.
