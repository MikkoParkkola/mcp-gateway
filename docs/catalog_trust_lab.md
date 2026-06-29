# CatalogTrustLab

CatalogTrustLab is the advisory evaluation layer for candidate MCP servers. It turns TrustCard and CBOM metadata into a versioned evidence record with score, scanner results, policy verdict, certification status, and runtime evidence.

## What It Covers

- TrustCard and CBOM completeness.
- Tool schema drift against a stored baseline.
- Existing AX-010 tool-poisoning scanner results.
- Missing MCP behavior annotations.
- Broad host-impacting permissions and high-risk classifications.
- Safe active-eval planning and execution evidence: only fixture calls explicitly marked safe may be invoked, and only when the runtime is reported as isolated.
- Remediation plans that map findings to enable, fix, block, or quarantine outcomes.

The default CLI implementation remains static/advisory unless active fixtures are supplied. The core TrustLab evaluator supports active fixture execution evidence through an injected runner: declared-safe fixtures are executed only when runtime isolation is present, non-isolated runs are skipped and blocked by evidence, and failed safe fixtures block enablement. The CLI attaches dry-run fixture evidence with `--active-fixtures` by default, or executes declared-safe matching fixtures through the local capability executor with `--execute-active-fixtures`. Execution mode is fail-closed and records only argument/result digests and errors, but it does not provision a sandbox by itself; run it inside a disposable container, CI job, or RuntimeProvider-managed environment and set `isolated: true` only for that environment. Fully automated RuntimeProvider provisioning and enterprise scheduling remain follow-up work.

## License Split

Free/core:

- Local one-shot evaluation.
- TrustLab schema and JSON evidence.
- TrustCard/CBOM validation.
- Baseline drift checks with local baseline files.
- Managed local baseline registry with a manifest and safe baseline ids.
- Safe fixture-call planning.
- CLI dry-run fixture evidence from JSON/YAML files.
- Explicit CLI execution of declared-safe fixtures through the local capability executor.
- Isolated active-fixture evidence model for local or test runners.
- Local CLI reports through `mcp-gateway trust lab evaluate`.

Enterprise:

- Continuous scheduled evaluations.
- Fleet policy thresholds and centralized baseline governance.
- Vendor scorecards.
- Approval workflows.
- Compliance evidence export.
- Expiring certification records and evidence-retention policy.

## Build Vs Integrate

Build:

- MCP-specific scoring rubric.
- TrustCard/CBOM-to-policy evaluation.
- MCP fixture-call safety planning.
- Certification records and policy verdicts.
- Finding-to-remediation planning for MCP-specific approval workflows.

Integrate:

- Existing mcp-gateway AX-010 tool-poisoning scanner.
- Future scanner adapters for dependency audit, SBOM, signature verification, and external MCP safety scanners.
- RuntimeProvider for isolated active evaluation once live execution is wired.

## Policy Verdicts

- `allow`: score and findings satisfy policy.
- `warn`: non-blocking warnings exist.
- `block`: score is below threshold or failing findings exist.
- `advisory`: the candidate would block, but the policy is configured for advisory-only evaluation.

## Remediation Plans

Every JSON evaluation includes `remediation_plan` with:

- `outcome`: `enable`, `fix`, `block`, or `quarantine`.
- `actions`: normalized remediation actions derived from finding codes.
- `reviewable_diff_available`: true when metadata, CBOM, runtime, or baseline changes can be proposed for review.
- `human_approval_required`: true when approval, quarantine removal, risky runtime enablement, or baseline update approval is required.

This keeps the default local workflow automation-first: the report tells operators what can be fixed mechanically and what still needs a human decision.

## Active Fixture Evidence

Active fixture evaluation is fail-closed:

- Fixtures without `declared_safe: true` are skipped and recorded as `TRUSTLAB_UNSAFE_FIXTURE_SKIPPED`.
- Declared-safe fixtures are not invoked unless the runtime evidence says isolation is enabled.
- Non-isolated active evaluation attempts produce `TRUSTLAB_ACTIVE_RUNTIME_NOT_ISOLATED` and block enablement.
- CLI dry-run fixture files produce `TRUSTLAB_ACTIVE_FIXTURE_DRY_RUN` warnings and provisional certification until a live isolated runner executes them.
- Failed declared-safe fixture calls produce `TRUSTLAB_ACTIVE_FIXTURE_FAILED` and block enablement.
- Passing fixture calls record a digest of the captured output rather than raw output-dependent policy.

This gives future RuntimeProvider integration one stable contract: execute the candidate server in isolation, call only reviewed safe fixtures, then attach the resulting `TrustLabRuntimeEvidence` to the evaluation.

## Current Limits

- No CLI-wired live candidate server execution yet.
- No centralized or multi-user baseline registry yet; the current registry is
  local file-backed evidence.
- No automatic config patch application yet; remediation plans are report evidence and review guidance.
- No enterprise scheduler, approval workflow, or export sink yet.

These limits keep v0 honest while giving later implementation slices a stable schema and testable policy core.

## CLI

Generate a local advisory report:

```bash
mcp-gateway trust lab evaluate --capabilities capabilities --format json
```

Write the current generated schema digests as a local baseline:

```bash
mcp-gateway trust lab evaluate weather_current \
  --capabilities capabilities \
  --write-baseline trustlab-baseline.json \
  --baseline-id weather-current-v1
```

Evaluate one generated TrustCard and make blocked policy verdicts fail the command:

```bash
mcp-gateway trust lab evaluate weather_current \
  --capabilities capabilities \
  --baseline trustlab-baseline.json \
  --enforce
```

Create or update a managed local baseline registry entry:

```bash
mcp-gateway trust lab evaluate weather_current \
  --capabilities capabilities \
  --baseline-registry .mcp-gateway/trustlab-baselines \
  --update-baseline-registry \
  --baseline-id weather-current-v1
```

Evaluate against that managed baseline later:

```bash
mcp-gateway trust lab evaluate weather_current \
  --capabilities capabilities \
  --baseline-registry .mcp-gateway/trustlab-baselines \
  --baseline-id weather-current-v1 \
  --enforce
```

The registry stores each baseline under `baselines/<baseline-id>.json` and
keeps `manifest.json` with the baseline digest, tool schema count, server names,
and update timestamp. Baseline ids are restricted to ASCII letters, numbers,
`.`, `-`, and `_` so registry writes cannot escape the registry directory.

Attach dry-run active fixture evidence:

```bash
mcp-gateway trust lab evaluate weather_current \
  --capabilities capabilities \
  --active-fixtures trustlab-fixtures.yaml \
  --format json
```

Example fixture file:

```yaml
provider: cli_fixture_plan
isolated: true
fixtures:
  - tool_name: weather_current
    arguments:
      location: Helsinki
    declared_safe: true
  - tool_name: delete_weather_cache
    arguments:
      id: demo
    declared_safe: false
```

The CLI filters fixture entries to the evaluated capability's tools. Matching
declared-safe fixtures are reported as `dry_run`, not `passed`, and are not
invoked by the CLI. Unsafe entries stay skipped and cannot become runtime
evidence without an explicit safe review plus a real isolated runner.

Execute declared-safe active fixtures from an already isolated environment:

```bash
mcp-gateway trust lab evaluate weather_current \
  --capabilities capabilities \
  --active-fixtures trustlab-fixtures.yaml \
  --execute-active-fixtures \
  --enforce \
  --format json
```

Execution mode requires `--active-fixtures`, filters fixtures to the evaluated
capability, skips anything not explicitly marked safe, and refuses to invoke
fixtures when the fixture file says `isolated: false`. Failed safe fixture calls
produce `TRUSTLAB_ACTIVE_FIXTURE_FAILED`; with `--enforce`, that blocks the
policy verdict until the fixture passes in isolation.

Focused validation:

```bash
cargo test trust::lab::tests -- --nocapture
cargo test lab_execute_active_fixtures --bin mcp-gateway -- --nocapture
cargo test commands::trust::tests --bin mcp-gateway -- --nocapture
```
