# RuntimeProvider Planner

MIK-6555 starts with a compile-only RuntimeProvider contract. It recommends a
runtime provider, compiles least-privilege policy, lists preflight checks,
records human confirmations, emits audit evidence, and describes rollback. It
does not start processes or containers yet.

## Free/Core Baseline

- `local_process` preserves existing direct execution compatibility.
- `docker` and `podman` are modeled as containerized providers behind the same
  policy interface.
- Policies cover mounts, environment variable names, guarded names, network
  egress, resource limits, restart behavior, and privileged execution.
- Plans are dry-run by default and include no apply command in this slice.
- Plans include recommendation explanations, security tradeoffs, start command
  hints, health checks, log hints, stop hints, and rollback instructions for the
  selected provider.

## Human Gates

The planner pauses for human approval before host mounts, unrestricted egress,
privileged execution, or guarded environment names. Host root and other hard
blocked mounts fail closed. Recommendation text explains whether the provider
was selected by operator preference, isolation needs, or compatibility fallback.

## Enterprise Boundary

Kubernetes, fleet policy, advanced hardened runtime packs, tenant placement,
evidence export, and managed remediation remain enterprise work. This module
only establishes the shared policy contract those providers must use.

## Validation

The focused test target is:

```bash
cargo test runtime::provider::tests -- --nocapture
```

The tests cover Docker recommendation, local compatibility fallback, lifecycle
hints, guarded name handling, broad egress confirmation, forbidden mount denial,
container image denial, and the shared LocalProcess/Docker provider contract.
