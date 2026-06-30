# ContextIntegrityKernel

ContextIntegrityKernel is the policy envelope for tool-result boundary
protection. It classifies content before it is promoted into privileged agent
context and records provenance, trust boundary, classifier evidence, policy
decision, and audit metadata.

The kernel is wired into live `gateway_invoke` dispatch after response contract
checks and response inspection, and before cache storage, idempotency completion,
transparency logging, signing, and delivery. Clean benign results are returned
unchanged; risky results receive a `_context_integrity` envelope with provenance,
classification, policy, and audit evidence.

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
- Large-output handling: classifiers run over a bounded head/tail text sample
  while the audit hash remains computed from the full canonical JSON payload.

## Default Posture

Default mode is monitor-only. Findings are recorded and the `would_decision`
shows what enforcement would do, but the effective decision remains `allow`.
This makes it safe to observe real tool traffic before turning on enforcement.

Read-only benign content stays allowed by default. Untrusted instruction-like
content, destructive instructions, tool-access escalation, and poisoned
descriptors produce stronger decisions under the enforcing baseline.

## Policy UX

The kernel exposes named presets that compile to explicit policies:

- `monitor_only`: default; evaluate risky output and attach evidence without
  changing delivery.
- `local_developer`: monitor-only with gentle would-strip defaults.
- `team_shared`: enforcing baseline for shared environments.
- `enterprise_strict`: enforcing policy with stronger guarded-material
  handling.
- `audit_only`: evidence collection without delivery changes.

Configure the preset in `gateway.yaml`:

```yaml
security:
  context_integrity:
    preset: team_shared
```

The default is `monitor_only`, which preserves the historical safe rollout
behavior. `team_shared` is the free/core opt-in enforcement preset for shared
developer or team gateways. `enterprise_strict` is reserved for enterprise
license scope because it belongs with organization-specific data policies,
approval workflows, and fleet evidence review.

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
- Live configurable wrapping for risky gateway-routed tool output.
- Bounded classifier sampling for large local tool outputs.

Enterprise:

- Organization-specific data-class policy packs.
- Enterprise strict preset and enterprise review disposition.
- Red-team fixture packs and continuous scheduled evaluation.
- SIEM/DLP/evidence export adapters.
- Central policy distribution, approval workflows, and fleet dashboards.
- Per-tenant policy exceptions and compliance reporting.

## Integration Point

The live integration sits after capability response transforms, output-schema
validation, canonical projection, response contract checks, and response
inspection. It runs before response caching, idempotency completion,
transparency logging, signing, and return to the client or agent. That placement
keeps existing redaction and schema behavior intact while ensuring untrusted
tool output cannot silently become privileged prompt context.

## Validation

Run:

```bash
cargo test context_integrity::kernel::tests -- --nocapture
cargo test --lib gateway_invocation_attaches_context_integrity_metadata_to_risky_tool_output -- --nocapture
cargo test --lib context_integrity_team_shared
```

The focused tests cover provenance metadata, baseline classifier coverage, all
six policy decisions, monitor-only evidence, privilege-boundary protection,
bounded large-output classification, and AX-010 descriptor poisoning reuse. The
live gateway regression proves risky tool output receives `_context_integrity`
metadata before return. The `context_integrity_team_shared` regression proves
that `security.context_integrity.preset: team_shared` is parsed from config and
enforces denial on risky gateway-routed tool output through the shared
`Gateway::build_meta_mcp` startup path.
