# ADR-011: Flip to PolyForm-Noncommercial default with a minimal MIT core

- **Status**: Accepted (pending legal review + operator tag approval), 2026-07-10
- **Supersedes**: the MIT-default + EE-allowlist model (ADR-001 / LICENSE-EE.md)

## Context

The whole 3.x line added enterprise features (multi-user identity, per-user
isolation, security governance, control plane, cost accounting, key server,
attestation). These features are Noncommercial (PolyForm-Noncommercial-1.0.0).
An "EE allowlist" approach — marking each enterprise file and enumerating it —
is structurally unworkable here because enterprise logic is **woven into the
runtime** (`gateway`, `backend`, `transport`, `config`, `commands`): the
boundary cannot be drawn cleanly per file (features such as `identity_grants`
and the per-user transport pool span both). An allowlist therefore cannot be
made complete or kept complete.

## Decision

Flip the default. The repository is **PolyForm-Noncommercial-1.0.0 by default**;
only files explicitly carrying `// SPDX-License-Identifier: MIT` are MIT. The MIT
core is small and enumerated in `.mit-core-allowlist`; every other first-party
source file carries an affirmative `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0`
header (not mere absence — an extracted file must carry its own governing license).
Enforced bidirectionally in CI
(`scripts/ci/check-license-headers.sh`): allowlist files must be MIT, and no file
outside the allowlist may be MIT.

Three operator decisions set the boundary:

1. **Companies pay to run it.** Free = personal/noncommercial only. No
   free-commercial tier, so no runtime refactor now. The runnable gateway is
   Noncommercial.
2. **Simple/config is MIT; anything an enterprise needs is NC.** The capability
   *definition format* was initially intended MIT, but it embeds the multi-user
   grant model and its parser/converter pull in NC engine + network-security
   code, so the definition, parser, OpenAPI conversion, and structural validator
   are Noncommercial. Only the generic, self-contained sub-utilities
   (`schema_validator`, `hash`) stay MIT.
3. **Old mis-licensed versions (3.0.0–3.2.1) are withdrawn** from active channels.

## MIT core (the entire open surface)

Simple, generic, self-contained, enterprise-free building blocks only:
`protocol`, `semantic_search`, `transform`, `projection`, `validator`, `skills`
(whole modules); `capability/schema_validator` and `capability/hash` (generic
JSON-schema validation + file hashing); `error.rs`; and the `crates/gateway-core`
crate (pure discovery/routing primitives). That is **~46 of ~370 source files**.
Everything else — the runnable gateway, `ranking` (authorization), `registry`
(marketplace), the capability definition/engine, all identity/security/
governance, all deploy/ops — is Noncommercial.

**Correction (post gpt-5.6-sol review):** an earlier draft of this ADR put
`ranking`, `registry`, and the capability *definition format* in the MIT core.
The adversarial review found they carry enterprise logic — `ranking` embeds
authorization/policy suppression, `registry` includes a plugin marketplace, and
`capability/definition` embeds the multi-user grant model (`CapabilityExposure`,
`GrantSubject`). Under the operator rule "simple/config is MIT, anything an
enterprise needs is NC," they are Noncommercial. The MIT core was shrunk to the
dependency-closed, enterprise-free set above (verified: zero enterprise imports,
zero enterprise logic).

## How this was decided

Tri-model analysis (Claude Opus 4.8 + grok 4.5 + gpt-5.5). All three independently
confirmed: the NC-default flip is correct (an EE allowlist can't be complete);
the runtime is NC so commercial running requires a license; do not refactor now;
MIT cannot be revoked on already-distributed 3.x copies. They diverged on core
width (grok widest, Claude tightest) and on yanking crates.io (2/3 for). The
operator resolved the divergences: tight core, engine closed (format open),
withdraw old versions.

## Consequences

- **Positive**: no leak class remains (default is closed); a small, auditable,
  CI-enforced MIT surface; clear commercial boundary.
- **Negative / accepted**: no free-commercial runnable tier; mixed per-file +
  non-OSI license will be misread by package license badges (mitigated by
  `license-file`, SPDX headers, `NOTICE.md`, SBOM); 3.0.0–3.2.1 copies stay MIT
  forever for their recipients (unpreventable — mitigated by withdrawal + a
  canonical corrected release).

## Cargo / packaging

`Cargo.toml` uses `license-file = "LICENSES.md"` (the `license` field cannot
express per-file mixed licensing). npm uses `"SEE LICENSE IN LICENSES.md"`.

## Deprecation runbook

See `scripts/release/deprecate-leaked-3x.sh`.
