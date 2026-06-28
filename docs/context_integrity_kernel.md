# ContextIntegrityKernel

ContextIntegrityKernel is the policy envelope for tool-result boundary
protection. It classifies content before it is promoted into privileged agent
context and records provenance, trust boundary, classifier evidence, policy
decision, and audit metadata.

This first slice is a core contract plus tests. It does not change the live
gateway dispatch path yet.

## What It Covers

- Provenance: server, tool, invocation id, subject, trust boundary, and optional
  TrustCard digest.
- Baseline classifiers: prompt-injection patterns, protected access material,
  personal data, financial identifiers, destructive instructions, tool-access
  escalation, tool descriptor poisoning, and data-exfiltration-shaped content.
- Policy decisions: allow, strip, summarize, quarantine, confirm, and deny.
- Rollout mode: monitor-only by default, with an enforcing baseline available
  for opt-in tests and deployments.
- Evidence: versioned evaluation JSON, input content hash, findings, effective
  decision, would-enforce decision, and audit event.

## Default Posture

Default mode is monitor-only. Findings are recorded and the `would_decision`
shows what enforcement would do, but the effective decision remains `allow`.
This makes it safe to observe real tool traffic before turning on enforcement.

Read-only benign content stays allowed by default. Untrusted instruction-like
content, destructive instructions, tool-access escalation, and poisoned
descriptors produce stronger decisions under the enforcing baseline.

## Policy UX

The kernel exposes named presets that compile to explicit policies:

- `local_developer`: monitor-only with gentle would-strip defaults.
- `team_shared`: enforcing baseline for shared environments.
- `enterprise_strict`: enforcing policy with stronger guarded-material
  handling.
- `audit_only`: evidence collection without delivery changes.

Every evaluation can produce a plain-language explanation with the decision
reason, audit-safe source evidence, action taken, safe next step, and a
confirmation rationale when confirmation is required. Confirmation remains
reserved for exceptions, ambiguous high-risk content, destructive follow-up, or
private data exposure.

False-positive feedback is dispositioned by scope. Local-only feedback can tune
local policy with audit evidence. Enterprise policy feedback requires explicit
enterprise review and never silently weakens global policy.

## Free/Core Versus Enterprise

Free/core:

- Local content classification.
- Tool-risk annotations and provenance metadata.
- Built-in policy decisions and monitor-only rollout.
- Local developer, team shared, and audit-only policy presets.
- Plain-language decision explanations.
- Local false-positive feedback disposition.
- Existing response scanner and AX-010 tool-poisoning integration.
- Local JSON evidence for tests and operator inspection.

Enterprise:

- Organization-specific data-class policy packs.
- Enterprise strict preset and enterprise review disposition.
- Red-team fixture packs and continuous scheduled evaluation.
- SIEM/DLP/evidence export adapters.
- Central policy distribution, approval workflows, and fleet dashboards.
- Per-tenant policy exceptions and compliance reporting.

## Integration Point

The eventual live integration should sit after tool response transforms and
schema validation, and before projected content is returned to the client or
agent. That placement keeps existing redaction and schema behavior intact while
ensuring untrusted tool output cannot silently become privileged prompt context.

## Validation

Run:

```bash
cargo test context_integrity::tests -- --nocapture
```

The focused tests cover provenance metadata, baseline classifier coverage, all
six policy decisions, monitor-only evidence, privilege-boundary protection, and
AX-010 descriptor poisoning reuse.
