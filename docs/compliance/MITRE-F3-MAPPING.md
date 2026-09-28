# MITRE Fight Fraud Framework (F3) mapping

**Date**: 2026-09-28 (rescoped; source claims re-verified against `84e870dd3`)
**Standard**: MITRE Fight Fraud Framework (F3) v1.1 (JSON `lastModified` 2026-06-23)
**Sources**: [CTID F3 site](https://ctid.mitre.org/fraud/), [F3 repository](https://github.com/center-for-threat-informed-defense/fight-fraud-framework), `public/f3-v1.1.json` (Apache-2.0)
**Scope**: mcp-gateway repo-local controls at the **tool-call boundary** (client identity, tool dispatch, capability integrity, session and cost limits). This is a mapping, not a claim that mcp-gateway is a fraud platform.

F3 is a behavior-based model of financial-fraud actor tactics and techniques. It reuses MITRE ATT&CK identifiers where the behavior already exists, and adds two fraud-specific tactics:

| ID | Name | F3 role |
|---|---|---|
| FA0001 | Positioning | After initial access: collect or manipulate data, or otherwise prepare for execution. |
| FA0002 | Monetization | Convert stolen assets into usable funds or value. |

The other six tactics reuse ATT&CK identifiers with fraud-oriented definitions: TA0043 Reconnaissance, TA0042 Resource Development, TA0001 Initial Access, TA0005 Stealth, TA0112 Defense Impairment, TA0002 Execution. Technique IDs are `F####` (F3-native) or `T####` (ATT&CK). This document was written against F3 v1.1 (8 tactics, 123 technique objects in `f3-v1.1.json`). A subtechnique takes its parent's verdict unless it is listed separately.

## Boundary (read this first)

mcp-gateway sits between an AI client and MCP/REST tools. It can constrain **what an agent is allowed to invoke**, **who the caller is**, and **whether a tool definition was swapped after approval**. It does not see card rails, ATMs, mule accounts, payroll systems, or cash-out channels.

Most F3 techniques therefore fall outside this assessment. They happen somewhere the gateway never sits (a card network, a payment rail, a branch, a phone line, the victim's device or bank account), or inside a downstream system the gateway reaches only as an opaque tool call. They are marked **N/A** for this boundary. That does not make the risk go away. If an operator connects a backend that can move money, change a beneficiary, or edit payroll, F3 applies in full to that backend and its operator.

**Generic controls, stated once.** A tool call, including one that reaches a payments or banking backend, meets the generic controls the operator has configured: authentication, per-client tool allow and deny lists (per API key), and identity grants. None is on by default: with auth disabled, every caller is anonymous (`src/gateway/auth.rs`, `auth_middleware`). Calls through `gateway_invoke` also meet the daily tool-cost budget (`src/cost_accounting/enforcer.rs`, only when cost governance is configured) and the kill switch (`src/kill_switch/mod.rs`); the direct `POST /mcp/{name}` backend route (`src/gateway/router/backend_handlers.rs`) checks neither. These controls can refuse or cap a tool. They do not recognise fraud, so they are not counted as coverage of any individual technique. N/A rows marked "downstream" refer back to this paragraph.

**BPD-bounded execution is not a runtime control.** `docs/design/BPD_DSL_DESIGN.md` describes a Boundary Protocol Description DSL and a `mcp-gateway bpd` CLI that is not implemented in `src/`.

Coverage labels:

| Label | Meaning |
|---|---|
| PARTIAL | The technique targets the gateway's own surface (its HTTP/stdio endpoints, credentials, audit trail, or capability supply chain) and a shipped control constrains it. The note names what is still missing. |
| GAP | The technique targets the gateway's own surface, a gateway control could exist, and none ships. The note names the control that would close it. |
| N/A | Outside this boundary: the technique never passes through a tool call, or it is a downstream action the gateway sees only as an opaque tool call. Downstream fraud risk stays with the connected backend. |

There is no COVERED row. PARTIAL means "constrained", not "detected".

## Counts

| Verdict | Technique objects (of 123) |
|---|---|
| N/A | 108 |
| PARTIAL | 11: F1002, F1002.001, F1002.002, F1004, F1033, T1070, T1195, T1550, T1550.001, T1557, T1608 |
| GAP | 4: T1110, T1110.001, T1110.003, T1110.004 |

The previous revision of this document (2026-08-31) listed 109 GAP, 14 PARTIAL and 0 N/A. It filed physical, card-scheme, payment-rail and cash-out techniques under GAP although its own N/A label fitted them, and counted per-client tool policy as PARTIAL coverage of F1005 Account Manipulation. Both are corrected here.

## Tactic coverage

| Tactic | ID | PARTIAL | GAP | N/A | Why |
|---|---|---|---|---|---|
| Reconnaissance | TA0043 | 0 | 0 | 15 | Mail theft, IVR mapping, PIN peeking, card-dump capture, phone spoofing and phishing happen outside the gateway. Open-web search (T1593) through a connected search tool is ordinary tool use. |
| Resource Development | TA0042 | 1 | 0 | 19 | Counterfeit cards, fake documents, merchant accounts and PAN/CVV generation are off-boundary. PARTIAL: T1608 when the staged artifact is a **local** pinned capability file. |
| Initial Access | TA0001 | 9 | 4 | 24 | The gateway's own authentication surface is in scope: F1002, F1004, F1033, T1195, T1550, T1557 PARTIAL; T1110 GAP. Takeover of a victim's bank account, SIM swap, MFA interception and phishing are N/A. |
| Stealth | TA0005 | 1 | 0 | 14 | 3DS bypass, geolocation or device spoofing, PaReq manipulation, virtual cards and structuring are payment-scheme behaviors. PARTIAL: T1070, for the gateway's own invocation log. |
| Defense Impairment | TA0112 | 0 | 0 | 10 | F1005 Account Manipulation changes settings inside the victim's institution (downstream). T1667 floods the victim's mailbox. |
| Positioning | FA0001 | 4 | 0 | 31 | F1002 and T1557 PARTIAL on the gateway's own surface. Card testing, payroll change, deposits, browser malware and screen capture are N/A. |
| Execution | TA0002 | 4 | 0 | 20 | F1002 and T1557 PARTIAL. ATM, NFC, check fraud, chargebacks, reversals and scheduled transfers are N/A. |
| Monetization | FA0002 | 0 | 0 | 13 | Cash-out, payment rails, crypto off-ramps, gambling and purchasing are downstream or off-boundary. The daily tool-cost budget caps **API spend**, not stolen funds. |

Multi-tactic techniques (F1002, T1557, F1040 and others) are counted once per tactic in this table and once in the totals above.

## Techniques on the gateway's own surface

| ID | Name | Verdict | Control (evidence) | Missing |
|---|---|---|---|---|
| F1002, .001, .002 | Abuse of Public-Facing API | PARTIAL | Authentication; per-client rate limit and circuit breaker for authenticated callers (`src/gateway/auth.rs`, `client_preflight` near line 920); Origin and Host validation (`src/gateway/router/origin_guard.rs`); opt-in principal-keyed call budget (`src/security/firewall/budget_guard.rs`); SSRF guard on outbound fetches (`src/security/ssrf/mod.rs`, `validate_url_not_ssrf` at line 145) | Unauthenticated attempts are not throttled (see T1110). No mobile-emulator or bot signal. |
| F1004 | Access with Stolen Session Cookie | PARTIAL | The dashboard session is an opaque 32-byte handle held in memory and valid only for this process (`src/gateway/auth.rs`, `DashboardBootstrap` lines 505-543). The cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` when the listener speaks TLS (`src/gateway/auth_bootstrap.rs` lines 118-131). | The cookie's `Max-Age=86400` limits the browser, not the server: a stolen handle is accepted until the process restarts. No idle expiry, no binding to a client. |
| F1033 | Insider Access Abuse | PARTIAL | Identity grants (`src/identity_grants.rs`); the tamper-evident transparency log records every completed invocation and is required whenever auth is on (`src/config/features/security.rs` lines 112-121). | Records misuse; does not detect it. |
| T1070 | Indicator Removal | PARTIAL | The transparency log is a hash chain; `mcp-gateway audit verify` reports edited or deleted entries and segments (`src/security/transparency_log_verify.rs`). | Only while the log is enabled (required with auth, opt-in without). Downstream systems' logs are out of scope. |
| T1110, .001, .003, .004 | Brute Force; guessing, spraying, credential stuffing | GAP | None. Rate limit and circuit breaker run only after a token authenticates; an invalid token gets 401 with no throttle or lockout (`src/gateway/auth.rs` lines 905-918). | Would close: a failed-authentication throttle or lockout. |
| T1195 | Supply Chain Compromise | PARTIAL | Local capability files with a `sha256:` pin fail closed at load (`src/capability/hash.rs`, `compute_capability_hash` at line 82); tampered pinned files are unloaded (`src/capability/backend.rs`, `detect_rug_pulls` at line 615). | Unpinned files; remote tool-schema drift (see capability pinning below). |
| T1550, T1550.001 | Use Alternate Authentication Material; Application Access Token | PARTIAL | API keys can carry an expiry (`src/gateway/auth.rs` line 273); attestation tokens carry expiry and rotation (`src/attestation/validator.rs`); dashboard session as in F1004. | No binding of a key or token to a client instance; no reuse or leak detection. A leaked key is accepted from anywhere until it expires or is removed. |
| T1557 | Adversary-in-the-Middle | PARTIAL, only when configured | mTLS when `mtls.enabled` is set, with fail-closed tool authorization (`src/mtls/access_control/mod.rs`, `evaluate` lines 80-110). Response signing when `security.message_signing.enabled` is set (off by default, `src/config/features/security.rs` line 204): `gateway_invoke` results carry an HMAC over the final JSON-RPC envelope (`src/gateway/meta_mcp/signing.rs`, `finalize_gateway_invoke_response` at line 217; `src/security/message_signing_v2.rs` line 55), with an optional request nonce and replay window. | Signing protects only a client that verifies it; no client verifier ships in this repository. Requests are not MACed. |
| T1608 | Stage Capabilities | PARTIAL | Same local pin and rug-pull unload as T1195. | T1608.006 SEO poisoning is N/A (public web). |

## N/A techniques, by reason

| Reason | Techniques (subtechniques included) |
|---|---|
| Physical channel or instrument | F1008 ATM Manipulation, F1009 Bank Deposit, F1010 Buy Money Order, F1014 Check Fraud, F1017 Conversion to Physical Monetary Instruments, F1019 Create Counterfeit Card, F1035 Mail Theft, F1041 PIN-code Peeking |
| Card scheme or card-present | F1001 3DS Bypass, F1011 Card Dump Capture, F1012 Card Testing, F1015 Churning, F1024 Dispute Legitimate Transaction, F1037 NFC Payment, F1038 PAN/CVV Generation, F1039 PaReq Manipulation, F1043 Reversal of Transaction, F1048 Use Virtual Cards |
| Payment rail or cash-out (downstream) | F1016 Compromise Payment Gateway (a payment processor, not this gateway), F1018 Convert to Cryptocurrency, F1025 Electronic Funds Transfer, F1026 Exploitation of Gambling Platforms, F1028 Fradulent [sic] Purchasing, F1045 Structuring, F1046 Test Payment Thresholds, F1047 Transfer of funds |
| Victim account at an institution (downstream) | F1003 Abuse SMS verification, F1005 Account Manipulation, F1006 Account Takeover (incl. F1006.001 keys for financial services), F1013 Change Payroll Details, F1021 Create Fraudulent Merchant Account, F1022 Delete Relevant Emails, F1036 New Vendor Setup, F1042 Reactivate Account, F1044 Scheduled Transfer, T1531 Account Access Removal |
| Telephony, identity presented to an institution | F1023 Device Fingerprint Spoofing, F1030 Geolocation Spoofing, F1031 Impersonate Account Holder, F1032 Impersonate Official, F1034 IVR Mapping, F1040 Phone Number Spoofing, T1451 SIM Card Swap |
| Victim device, browser or mailbox | F1007 Adversary-in-the-Browser, T1111 MFA Interception, T1113 Screen Capture, T1185 Browser Session Hijacking, T1189 Drive-by Compromise, T1219 Remote Access Tools, T1453 Abuse Accessibility Features, T1539 Steal Web Session Cookie, T1110.002 Password Cracking (offline), T1555 Credentials from Password Stores, T1621 MFA Request Generation, T1667 Email Bombing |
| Social engineering, adversary resources, public web | F1020 Create Fake Materials, F1027 Falsify Business Documents, F1029 Gather Customer Information, T1583 Acquire Infrastructure, T1585 Establish Accounts, T1586 Compromise Accounts, T1593 Search Open Websites/Domains, T1598 Phishing for Information, T1608.006 SEO Poisoning, T1650 Acquire Access, T1660 Phishing, T1672 Email Spoofing |

"Downstream" rows: a connected backend could perform the action as a tool call. The generic controls in the Boundary section apply; they are not fraud controls, and the risk stays with that backend.

## Named-feature mapping (MIK-3031.F3.2)

| Feature | Production wiring | Code | F3 IDs | Limit |
|---|---|---|---|---|
| Tool-poisoning detection | Not a `tools/list` gate. Runs in the capability validator CLI (`src/validator/rules/mod.rs`, default rule set), the context-integrity kernel on invoke (`src/context_integrity/kernel.rs` line 166), and the catalog trust lab (`src/trust/lab.rs` line 154). OpenAPI import also scrubs descriptions (`src/capability/openapi/sanitize.rs`, `sanitize_description` at line 87). | `src/validator/rules/tool_poisoning.rs` (`ToolPoisoningRule` at line 152) | T1195 and T1608 when one of those paths runs | Scans tool description text. A poisoned description can still reach the agent through `tools/list`. |
| Capability schema pinning | Files that carry a `sha256:` pin | `src/capability/hash.rs` line 82; `src/capability/backend.rs` line 615; remote backends in `src/security/remote_provenance.rs` | T1195, T1608 (local files) | Remote provenance signs backend name, transport, URL, subject, issuer and issued-at only (`RemoteServerProvenancePayload`, lines 63-70). It does not pin tool schemas or notice a server changing behind the same URL. |
| HMAC message signing | Opt-in: built from `security.message_signing` at startup (`src/gateway/server/mod.rs` lines 958-970) | `src/gateway/meta_mcp/signing.rs`; `src/security/message_signing_v2.rs` | T1557 (PARTIAL, when configured) | Signs `gateway_invoke` responses; requests are not MACed; no in-repo client verifier. `previous_secret` is kept for a future verify API (`src/security/message_signing.rs` line 79). |
| BPD-bounded execution | Not shipped; design only | `docs/design/BPD_DSL_DESIGN.md` | None | Runtime stand-ins are the cost budget and kill switch, which are generic controls. |
| mTLS | Off until `mtls.enabled` is set; then clients without a valid certificate are refused at the handshake (`require_client_cert` defaults to true, `src/mtls/config.rs`), and tool authorization is fail-closed: a call no policy rule allows is denied | `src/mtls/access_control/mod.rs` | T1557, TA0001 access to the gateway | Authenticates the MCP/HTTP client certificate, not a cardholder or a downstream end user. |
| Idempotency | Enabled on every boot (`src/gateway/server/mod.rs` lines 1149-1153) | `src/idempotency.rs` (`IdempotencyCache::check` at line 348) | None: F1015 churning and F1043 reversal happen at an issuer | Suppresses duplicate side effects for calls that carry a client-supplied idempotency key. A failed call is cached as final, except a failure the gateway proves happened before dispatch, which releases the key (`src/gateway/router/backend_handlers.rs`, `settle_direct_failure` at line 1159). |

Also on this boundary: SSRF guard (`src/security/ssrf/mod.rs`), input firewall (`src/security/firewall/input_scanner.rs`), anomaly scoring on tool sequences (`src/security/firewall/anomaly.rs`, not a fraud typology engine). Destructive-tool elicitation (`src/gateway/destructive_confirmation.rs`, header lines 3-18) is a courtesy prompt, not a security control, and is not mapped.

## Open gaps (MIK-3031.F3.3)

1. **Failed authentication is unthrottled** (T1110.001, .003, .004). Close with a failed-auth throttle or lockout ahead of token validation.
2. **Credentials are not bound to a client** (F1004, T1550 residuals). A stolen dashboard handle, API key or bearer works from anywhere until expiry, removal or restart.
3. **Response signing needs a verifier** (T1557 residual). No client-side verifier ships.
4. **Tool poisoning is not a `tools/list` gate.**
5. **Downstream tools remain the fraud surface.** A payments capability imported from OpenAPI inherits none of F3's controls; the gateway routes it if policy allows.

Kill-gate from the ticket ("F3 is fraud-specific and mcp-gateway is too broad to claim meaningful coverage"): **not taken.** The mapping shows where the gateway's own surface meets F3 and marks the rest out of scope instead of counting it as covered.

Companion: [OWASP Agentic AI compliance](../OWASP_AGENTIC_AI_COMPLIANCE.md) (ASI01-ASI10 at the same boundary). OWASP ASI is agent-tool risk; F3 is financial-fraud actor behavior. Overlap is real on supply chain, MITM and API abuse, and thin elsewhere.

## What this document does not do

- It does not add F3 technique IDs to runtime telemetry.
- It does not score a coverage percentage.
- It does not treat a connected payments or bank OpenAPI import as F3 coverage.
- It does not claim EU AI Act mapping.
