# ADR-025: Receipts prove calls without storing their contents

- **Status**: Decided in design, recorded here, 2026-10-25 (design D2, MIK-8841). Not reopened by this ADR.
- **Ticket**: MIK-8839 (lead's addition); binding on U2 (MIK-8855, API2.2, API2.5, API2.8) and the receipt frames (25, 25r, 32a)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

The new UI's receipt (frames 25, 25r) answers "what happened to this call, and can I prove it?" without anyone reading the call.

| # | Fact | Where |
|---|---|---|
| F1 | The firewall audit log keeps identity fields, a SHA-256 hash of the request arguments, the action, and each finding as its type, severity and location only. Raw argument values are never logged, and a finding's matched excerpt cannot be stored: the field's type cannot hold it. | `src/security/firewall/audit.rs:8-24` (MIK-8236) |
| F2 | The transparency log is a separate hash chain of request and response hashes; each entry is signed with HMAC-SHA256 when a shared secret is configured, and unsigned otherwise. A CLI verifies a log or an export. | `src/security/transparency_log.rs:15-34`; `mcp-gateway audit verify` |
| F3 | Firewall rows written before schema 3 may still carry matched excerpts. | `src/security/firewall/audit.rs:21-22` |

## Decision

- **No role reads call contents**, admin and auditor included. The receipt shows the request hash, each finding (kind, severity, where: request, answer, or sequence of calls) and the proof, as separate facts.
- **Proof.** The receipt's proof is the transparency log entry (F2). When the log is signed, the receipt says "Signature valid" only for facts that entry covers; when it is unsigned, the receipt says so and shows the chain check alone.
- **Old rows.** Receipts and exports are built from an allowlist of fields, so a schema-2 row's excerpt (F3) is dropped, never shown or exported.
- **Auditor** is a role: it reads Activity, receipts and exports and changes nothing; admin sees everything auditor sees.
- **Exports** carry the same fields, signed; CSV is the same rows, unsigned.
- **Why** (D14 ruling): a receipt and a refusal also show the decision evidence, the key and what it may reach, the rule that matched, whether that rule requires audit, and whether a rollback applies (U2 API2.8). No content is needed for that.

## Consequences

- The gateway retains no raw call contents, so a leaked export or a compromised admin session cannot reveal them directly. A request hash is deterministic, though: anyone who can guess a small set of candidate arguments can test each one against it. The export screen says so.
- An operator debugging a bad answer cannot read it from the gateway; they see what kind of finding fired and where, and reproduce the call themselves. The design states this on frame 25.
- Any future content retention is a new decision with its own retention bound and redaction, as U2 API2.5 already requires.
