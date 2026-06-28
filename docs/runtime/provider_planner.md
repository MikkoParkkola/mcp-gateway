# RuntimeProvider Planner and Apply Path

MIK-6555 provides a RuntimeProvider contract that plans and can apply a
least-privilege runtime start path. It recommends a runtime provider, compiles
policy, lists preflight checks, records human confirmations, emits audit
evidence, describes rollback, and exposes a structured apply command for
providers that are ready to launch.

## Free/Core Baseline

- `local_process` preserves existing direct execution compatibility.
- `docker` and `podman` are containerized providers behind the same policy
  interface.
- Policies cover mounts, environment variable names, guarded names, network
  egress, resource limits, restart behavior, and privileged execution.
- Plans include recommendation explanations, security tradeoffs, structured
  launch commands, display-only apply commands, health checks, log hints, stop
  hints, and rollback instructions for the selected provider.
- Docker and Podman launch commands use detached starts with restricted defaults:
  no shell execution, `--network=none` unless policy says otherwise,
  read-only root filesystem, `--cap-drop=ALL`, `no-new-privileges`, memory and
  CPU limits, and a small process limit.

## Human Gates

The planner pauses for human approval before host mounts, unrestricted egress,
privileged execution, or guarded environment names. Apply fails closed before a
runner is invoked when the plan is denied or required confirmations are missing.
Host root and other hard-blocked mounts fail closed. Recommendation text explains
whether the provider was selected by operator preference, isolation needs, or
compatibility fallback.

## Apply Contract

`RuntimePlan::apply_with` accepts an injectable command runner. The default
runner uses `std::process::Command`; tests use a recording runner so Docker and
Podman command construction can be validated without requiring a local daemon.
Audit records include provider, policy id, command program, argument digest,
approved confirmation ids, and environment variable names only. Environment
values are not serialized into plans, apply results, or audit evidence.

## Enterprise Boundary

Kubernetes, fleet policy, advanced hardened runtime packs, tenant placement,
evidence export, and managed remediation remain enterprise work. This module
only establishes the shared policy contract those providers must use.

## Validation

The focused test target is:

```bash
cargo test runtime::provider::tests -- --nocapture
```

The tests cover Docker recommendation, local compatibility fallback, executable
Docker lifecycle commands, guarded name handling, broad egress confirmation,
forbidden mount denial, apply fail-closed behavior, container image denial, and
the shared LocalProcess/Docker provider contract.
