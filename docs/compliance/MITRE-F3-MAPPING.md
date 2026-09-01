# MITRE Fight Fraud Framework (F3) mapping

**Date**: 2026-08-31
**Standard**: MITRE Fight Fraud Framework (F3) v1.1 (JSON `lastModified` 2026-06-23)
**Sources**: [CTID F3 site](https://ctid.mitre.org/fraud/), [F3 repository](https://github.com/center-for-threat-informed-defense/fight-fraud-framework), `public/f3-v1.1.json` (Apache-2.0)
**Scope**: mcp-gateway repo-local controls at the **gateway boundary** (client identity, tool dispatch, capability integrity, session and cost limits). This is a mapping, not a claim that mcp-gateway is a fraud platform.

F3 is a behavior-based model of financial-fraud actor tactics and techniques. It reuses MITRE ATT&CK identifiers where the behavior already exists, and adds two fraud-specific tactics:

| ID | Name | F3 role |
|---|---|---|
| FA0001 | Positioning | After initial access: collect or manipulate data, or otherwise prepare for execution. |
| FA0002 | Monetization | Convert stolen assets into usable funds or value. |

The other six tactics reuse ATT&CK identifiers with fraud-oriented definitions: TA0043 Reconnaissance, TA0042 Resource Development, TA0001 Initial Access, TA0005 Stealth, TA0112 Defense Impairment, TA0002 Execution. Technique IDs are `F####` (F3-native) or `T####` (ATT&CK). This document was written against F3 v1.1 (8 tactics, 123 technique objects in `f3-v1.1.json`).

## Boundary (read this first)

mcp-gateway sits between an AI client and MCP/REST tools. It can constrain **what an agent is allowed to invoke**, **who the caller is**, and **whether a tool definition was swapped after approval**. It does not see card rails, ATMs, mule accounts, payroll systems, or cash-out channels unless an operator connects a backend that talks to those systems.

That is why most F3 techniques are **GAP**. A GAP here means "this gateway does not implement a control for this technique," not "the technique is irrelevant." If a connected backend can initiate a wire, F3 still applies to that backend; the gateway can only deny the tool, cap spend, or require identity. Denying a tool is not detecting fraud.

The ticket named six existing features. Each is mapped below. **BPD-bounded execution is not a runtime control.** `docs/design/BPD_DSL_DESIGN.md` describes a Boundary Protocol Description DSL and a `mcp-gateway bpd` CLI that is not implemented in `src/`. Runtime bounds are session sandbox, cost accounting, and the kill switch.

Coverage labels:

| Label | Meaning |
|---|---|
| PARTIAL | A gateway control can disrupt or constrain the technique **when the action is a tool call through this process**. |
| GAP | No gateway control addresses the technique. Physical, card-scheme, and cash-out behaviors sit here. |
| N/A | The technique cannot occur at this boundary (stated only when that is actually true). |

There is no COVERED row. F3 techniques describe fraud-actor goals in financial environments. Claiming COVERED would overstate what a tool gateway does.

## Tactic coverage

| Tactic | ID | Gateway-boundary verdict | Why |
|---|---|---|---|
| Reconnaissance | TA0043 | GAP | Mail theft, IVR mapping, PIN peeking, card-dump capture, and phone-number spoofing are outside the process. Open-web search (T1593) is a backend choice, not a gateway detector. |
| Resource Development | TA0042 | GAP, with one PARTIAL | Counterfeit cards, fake documents, fraudulent merchant accounts, and PAN/CVV generation are outside the process. PARTIAL: T1608 Stage Capabilities when the staged artifact is a **local** pinned YAML. T1195 is Initial Access in F3 v1.1, not this tactic. Remote provenance does not cover T1608 tool-schema staging. |
| Initial Access | TA0001 | PARTIAL at the **gateway client**, GAP for **victim financial accounts** | mTLS, identity grants, attestation, and fail-closed OAuth isolation authenticate the AI client. They do not stop bank account takeover, SIM swap, or phishing of a cardholder. F1002 (public API abuse) is PARTIAL against the gateway HTTP surface (auth, origin/host checks, rate limits, SSRF). T1195 PARTIAL for local YAML pin only. |
| Stealth | TA0005 | GAP | 3DS bypass, geolocation spoofing, virtual cards, PaReq manipulation, and structuring are payment-scheme and mule behaviors. The gateway does not inspect those channels. |
| Defense Impairment | TA0112 | PARTIAL (policy), GAP (fraud-control sabotage) | Per-client denylists and the session sandbox can refuse tools that would change account settings **if those tools are connected**. There is no detector for "beneficiary added" or "e-delivery disabled" on a bank account. Email bombing (T1667) is GAP. |
| Positioning | FA0001 | PARTIAL for API/tool positioning, GAP for the rest | See the FA0001 table. Card testing, payroll change, mail theft, ATM/mobile deposit, and browser malware are GAP. |
| Execution | TA0002 | PARTIAL for tool-shaped execution, GAP for the rest | Session, cost, and idempotency bounds apply to `gateway_invoke`. ATM, NFC, check fraud, and scheduled bank transfers are GAP. |
| Monetization | FA0002 | GAP | The gateway has no payment rail, cash-out, crypto off-ramp, gambling, or P2P transfer control. Daily tool-cost budgets (`src/cost_accounting/enforcer.rs`) cap **API spend**, not stolen funds. |

## Named-feature mapping (MIK-3031.F3.2)

| Feature | Production wiring | Code | F3 IDs it can touch | Honest limit |
|---|---|---|---|---|
| Tool-poisoning detection | Not a default `tools/list` reject. Live callers: CLI validator (`src/validator/cli_handler.rs:136`), ContextIntegrityKernel on invoke (`src/context_integrity/kernel.rs:166`), CatalogTrustLab (`src/trust/lab.rs:154`). OpenAPI import also scrubs descriptions (`src/capability/openapi/sanitize.rs:87`) | `src/validator/rules/tool_poisoning.rs` (`ToolPoisoningRule` at line 152, `impl Rule` at line 155) | TA0001 / T1195 (poisoned tool definition as an access path) **when one of those live callers runs**; TA0042 / T1608 (staged malicious descriptions) same caveat; FA0001 F1002 when a poisoned description that actually reaches the client steers the agent into API abuse | Scans **tool description text**. Does not inspect payment payloads, 3DS, or account-holder social engineering. Do not read the README "before it reaches the agent" sentence as a tools/list gate. |
| Capability schema pinning | Only files that carry a `sha256:` pin; remote provenance is a separate opt-in | `src/capability/hash.rs` (`compute_capability_hash` at line 62); rug-pull unload in `src/capability/backend.rs` (`detect_rug_pulls`); remote backends in `src/security/remote_provenance.rs` | Local pin: TA0001 / T1195 (tampered capability YAML at load). Remote provenance: **not** T1195 tool-schema coverage. TA0042 / T1608 only for the local YAML bytes | Local pin hashes YAML bytes. Remote provenance (`RemoteServerProvenancePayload`) signs backend name, transport, URL, subject, issuer, and issued-at only (`src/security/remote_provenance.rs` lines 62–75). It authenticates declared publisher and endpoint metadata. It does not pin tool schemas and does not detect a live server changing behavior behind the same URL. |
| HMAC inter-agent message signing | **Unwired in production.** Config exists (`SecurityConfig::message_signing`). `MetaMcp` starts with `message_signer: None` (`src/gateway/meta_mcp/mod.rs:397`). `enable_message_signing` is called from tests only (`src/gateway/meta_mcp/authz_tests.rs:705`) | `src/security/message_signing.rs` (`MessageSigner::sign_response` at line 116). `previous_secret` is reserved for a future `verify_response()` API (line 74) | No live F3 PARTIAL until the server builder installs a signer. T1557 stays GAP at this layer in a default process | Code can HMAC a **response body**. Requests are not MACed. No in-repo response-replay verifier. This mapping does not treat the module as a deployed control. |
| BPD-bounded execution | **Not shipped.** Design only: `docs/design/BPD_DSL_DESIGN.md`. Runtime stand-ins (session/cost/kill) are separate | Runtime stand-ins: `src/session_sandbox.rs` (`SandboxEnforcer::check` at line 303), `src/cost_accounting/enforcer.rs` (`BudgetEnforcer::check` at line 180), `src/kill_switch/mod.rs` | TA0002 Execution (bound how much an agent can run); weak PARTIAL on FA0001 F1002 volume. Not F1012 / F1046 (those are payment-threshold tests, GAP) | Session call-count, duration, payload size, backend allow, tool deny. Cost enforcer is daily USD of **tool invocations**, not fraud loss. Kill switch disables a backend. None of these is a BPD document or `bpd validate` CLI. |
| mTLS | Off until `mtls` rules are configured; then fail-closed | `src/mtls/cert_manager.rs`, `src/mtls/identity.rs`, `src/mtls/access_control/mod.rs` (fail-closed `PolicyDecision::Deny` when rules exist but no verified identity, lines 87–110) | TA0001 Initial Access **to the gateway** | Authenticates the MCP/HTTP client certificate. Does not authenticate a cardholder, mule, or compromised end-user of a downstream bank. |
| Idempotency | **Unwired in production.** `enable_idempotency` (`src/gateway/meta_mcp/mod.rs:545`) has no production caller; `IdempotencyCache::new` is used in `src/idempotency.rs` tests only | `src/idempotency.rs` (`IdempotencyCache::check` at line 149) | **No F3 technique ID.** F1015 is card churning and F1043 is transaction reversal; both remain GAP under TA0002 | Code can suppress duplicate `gateway_invoke` side effects. That is not a live control and not a fraud mapping. |

Related controls that the ticket did not name, but that sit on the same boundary:

| Control | Code | F3 relevance |
|---|---|---|
| Identity grants | `src/identity_grants.rs` | TA0001: who may use a personal capability. |
| Boundary-call attestation | `src/attestation/validator.rs` | TA0001: signed task token, expiry, rotation. |
| SSRF guard | `src/security/ssrf/mod.rs` (`validate_url_not_ssrf` at line 131) | TA0001 / FA0001 F1002: stop the gateway fetching private/link-local destinations on behalf of a tool. |
| Input firewall | `src/security/firewall/input_scanner.rs` | TA0002: shell/traversal payloads in arguments. |
| Destructive elicitation | `src/gateway/destructive_confirmation.rs` | Courtesy prompt, **not** a security control (file header, lines 4–18). Do not map it as Defense Impairment coverage. |
| Anomaly scoring | `src/security/firewall/anomaly.rs` | Weak PARTIAL on unusual **tool sequences**. Not a fraud typology engine. |

## FA0001 Positioning — technique table

F3-native tactic. 35 techniques in v1.1.

| ID | Name | Verdict | Note |
|---|---|---|---|
| F1002 | Abuse of Public-Facing API | PARTIAL | Gateway HTTP surface: auth, origin/host checks, per-client rate limits, session sandbox, SSRF. Does not fingerprint mobile emulators or headless browsers. |
| F1002.001 / .002 | Mobile / Web API Abuse | PARTIAL | Same as F1002. No mobile-device or bot-score signal. |
| F1005 | Account Manipulation (and .001–.008) | PARTIAL (policy) / GAP (detection) | A denylist can refuse a connected "update beneficiary" tool. The gateway does not parse bank account mutations. |
| F1007 | Adversary-in-the-Browser (and .001–.003) | GAP | Browser malware, extensions, DLL injection. Outside this process. |
| F1009 | Bank Deposit (and .001–.004) | GAP | ATM / mobile / night / test deposit. |
| F1011 | Card Dump Capture | GAP | |
| F1012 | Card Testing | GAP | No card-authorization stream. Volume caps on tools are not BIN-testing detection. |
| F1013 | Change Payroll Details | GAP | |
| F1035 | Mail Theft | GAP | Physical. |
| F1036 | New Vendor Setup | GAP | |
| F1042 | Reactivate Account | GAP | |
| F1046 | Test Payment Thresholds | GAP | |
| T1113 | Screen Capture | GAP | |
| T1185 | Browser Session Hijacking | GAP | |
| T1219 | Remote Access Tools | GAP | |
| T1453 | Abuse Accessibility Features | GAP | |
| T1531 | Account Access Removal | GAP | |
| T1539 | Steal Web Session Cookie | GAP | |
| T1557 | Adversary-in-the-Middle | GAP at default process | HMAC signer is unwired in production. Even if enabled, it would cover response-body authentication only. |

## FA0002 Monetization — technique table

F3-native tactic. 13 techniques in v1.1. **All GAP.**

| ID | Name | Verdict |
|---|---|---|
| F1010 | Buy Money Order | GAP |
| F1017 / .001–.003 | Conversion to Physical Monetary Instruments (cash, cashier's check, money order) | GAP |
| F1018 | Convert to Cryptocurrency | GAP |
| F1025 / .001–.003 | Electronic Funds Transfer (P2P, regional rail, wire) | GAP |
| F1026 | Exploitation of Gambling Platforms | GAP |
| F1028 | Fradulent Purchasing | GAP |
| F1047 | Transfer of funds | GAP |

If an operator connects a payments or banking MCP backend, these techniques become the **backend's** problem. The gateway can deny the tool, require mTLS, or stop the session on a cost budget. That is still not monetization coverage.

## Other tactics — compact GAP / PARTIAL list

**TA0043 Reconnaissance** — GAP: F1011, F1029, F1034, F1035, F1040, F1041, T1555, T1598. T1593 (search open websites) is a backend search tool, not a gateway control.

**TA0042 Resource Development** — GAP: F1019, F1020, F1021, F1027, F1038, T1583, T1585, T1586, T1650. PARTIAL: T1608 via **local** capability pin of staged YAML. T1195 is Initial Access only in F3 v1.1 (not listed here).

**TA0001 Initial Access** — PARTIAL: F1002 (gateway HTTP); T1195 for **local YAML pin** (tamper at load), not remote tool-schema drift; gateway-client identity (mTLS, grants, attestation, OAuth fail-closed). GAP: F1004, F1006, F1007, F1016, F1031, F1032, F1033, F1040, F1041, F1042, T1110, T1111, T1185, T1189, T1451, T1539, T1550, T1557 (HMAC signer unwired; network MITM also GAP), T1621, T1660.

**TA0005 Stealth** — GAP: F1001, F1022, F1023, F1030, F1031, F1032, F1036, F1039, F1040, F1045, F1048, T1070, T1672.

**TA0112 Defense Impairment** — PARTIAL policy-only for F1005 if the mutating tool is connected and denied. GAP: T1667 Email Bombing; no sabotage detector for fraud-prevention systems.

**TA0002 Execution** — PARTIAL: F1002 via sandbox/rate/cost. GAP: F1003, F1007, F1008, F1009, F1014, F1015 (card churning), F1024, F1028, F1037, F1043 (transaction reversal), F1044, T1557 (network). Idempotency is a `gateway_invoke` retry guard, not an F1015 or F1043 control.

## Gaps that matter (MIK-3031.F3.3)

These are the gaps that would still be true after every named feature is enabled:

1. **Monetization (FA0002) is uncovered.** No cash-out, rail, crypto, or purchasing control lives in this repo.
2. **Card-scheme techniques are uncovered.** 3DS (F1001), PaReq (F1039), PAN/CVV generation (F1038), card testing (F1012), virtual cards (F1048), NFC (F1037).
3. **Physical and channel techniques are uncovered.** Mail theft, ATM, night deposit, PIN peek, SIM swap, IVR, phone spoofing.
4. **Account-holder fraud controls are not modeled.** Changing beneficiaries, notification settings, payroll, or vendor records is GAP unless a backend tool exists **and** policy denies it. Denial is not detection.
5. **BPD is design, not enforcement.** Mapping "BPD-bounded execution" to F3 without this sentence would be false.
6. **Destructive elicitation is a courtesy.** `src/gateway/destructive_confirmation.rs` says so in its header. It is not a Defense Impairment control.
7. **HMAC message signing is unwired.** `enable_message_signing` is test-only. T1557 is GAP in a default process, not PARTIAL.
8. **Idempotency is unwired.** `enable_idempotency` has no production caller.
9. **ToolPoisoningRule is not a tools/list gate.** CLI + invoke-time context-integrity + import sanitizer. A poisoned description can still reach the agent via `tools/list` unless another path runs the rule.
10. **Downstream tools remain the fraud surface.** A payments capability imported from OpenAPI inherits none of F3. The gateway will route it if policy allows.

Kill-gate from the ticket ("F3 is fraud-specific and mcp-gateway is too broad to claim meaningful coverage"): **not taken.** The mapping exists so a reader can see PARTIAL vs GAP. Claiming 8/8 tactic coverage would have been the overclaim the kill-gate warned about.

## Evidence map

| Claim | Evidence |
|---|---|
| F3 v1.1 tactic set | `public/f3-v1.1.json` in [fight-fraud-framework](https://github.com/center-for-threat-informed-defense/fight-fraud-framework); FA0001 / FA0002 are the F3-native tactic IDs |
| Tool poisoning | `src/validator/rules/tool_poisoning.rs:152` |
| Capability pin | `src/capability/hash.rs:62` |
| HMAC response body | `src/security/message_signing.rs:116` (`sign_response`); nonce optional; no `verify_response` yet |
| Session bounds | `src/session_sandbox.rs:303` |
| Cost bounds | `src/cost_accounting/enforcer.rs:180` |
| Idempotency | `src/idempotency.rs:149` |
| mTLS fail-closed | `src/mtls/access_control/mod.rs:87` |
| BPD not runtime | `docs/design/BPD_DSL_DESIGN.md` (CLI section is a proposal); no `bpd` subcommand under `src/` |
| Destructive confirmation is not a control | `src/gateway/destructive_confirmation.rs:4-18` |

Companion: [OWASP Agentic AI compliance](../OWASP_AGENTIC_AI_COMPLIANCE.md) (ASI01–ASI10 at the same gateway boundary). The two documents answer different questions. OWASP ASI is agent-tool risk. F3 is financial-fraud actor behavior. Overlap is real on supply chain, MITM, and API abuse, and thin everywhere else.

## What this document does not do

- It does not add F3 technique IDs to runtime telemetry.
- It does not score a coverage percentage.
- It does not treat a connected Stripe or bank OpenAPI import as F3 coverage.
- It does not claim EU AI Act mapping (not in this change).
