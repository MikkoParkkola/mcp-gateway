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
  hints, restart hints, and rollback instructions for the selected provider.
- Docker and Podman launch commands use detached starts with restricted defaults:
  no shell execution, `--network=none` unless policy says otherwise,
  read-only root filesystem, `--cap-drop=ALL`, `no-new-privileges`, memory and
  CPU limits, a small process limit, and `--restart=on-failure:N` when the
  profile allows restart attempts.
- Docker and Podman use `--rm` only when `restart.max_restarts` is `0`, because
  container restart policies and automatic removal conflict in real runtimes.

## Gateway Config

Operators can declare reusable runtime profiles in `gateway.yaml`. Omitted
runtime config preserves the existing direct-launch behavior through
`local_process`.

```yaml
runtime:
  default_provider: local_process
  availability:
    docker: true
  profiles:
    gmail:
      provider: docker
      image: ghcr.io/example/gmail-mcp:1
      executable: mcp-gmail
      data_class: sensitive
      env_keys:
        - GMAIL_HANDLE
      guarded_env_keys:
        - GMAIL_HANDLE
      network_egress: none
      resources:
        cpu_cores: 2
        memory_mb: 768
        timeout_secs: 45
      restart:
        max_restarts: 3
        backoff_secs: 10
```

Config validation rejects container profiles without an image, invalid resource
limits, malformed environment names, empty allowlist entries, and malformed mount
targets. Availability is declarative and does not probe Docker or Podman during
config load; runtime plans still emit preflight checks such as `docker info`.

Backends can opt into a declared runtime profile with `runtime_profile`. The
gateway compiles that profile during startup and config reload, then gates live
stdio backend starts before spawning the child process.

```yaml
runtime:
  profiles:
    local_safe:
      provider: local_process
      network_egress: none

backends:
  docs:
    enabled: true
    transport:
      type: stdio
      command: node server.js
    runtime_profile: local_safe
```

Reusable backend profiles inherit the executable from the stdio command when
the profile does not set `executable`, so operators do not need to duplicate the
launch binary. Runtime profile changes are treated as config reload changes for
backends that reference a runtime profile, causing those backends to be replaced
with a freshly compiled plan.

Admin backend status includes the compiled runtime profile lifecycle under the
optional `runtime` object. It reports the selected provider, policy id, license
tier, ready/confirmation/denied state, denial and confirmation ids, restart
policy, provider health check, restart hint, and rollback instruction. Public
`/health` callers still receive the redacted backend summary only.

Current live lifecycle support is intentionally narrow: stdio backends accept
`local_process` runtime plans that are not denied and do not require pending
human confirmations, and Docker/Podman plans can replace the direct stdio
command with an interactive `docker run --rm` or `podman run --rm` bridge for
images whose default command speaks MCP over stdio. HTTP container endpoint and
port mapping remain future work. The planner and audit contract remain usable
for doctor, TrustLab, and future containerized lifecycle flows.

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

`RuntimePlan::restart_with` uses the same gate and audit path as start, health,
logs, and stop. Container plans expose `docker restart NAME` or
`podman restart NAME` as structured commands, while stop/rollback use
`rm --force NAME` so a deterministic runtime name can be reused on the next
apply.

## Scaling and Concurrency

Choose the provider by **how many isolated instances run concurrently**, not by
convenience:

- **`local_process`, `docker`, `podman` are single-node / development scale.**
  They launch each runtime through the host's local process table or local
  container daemon. This is correct for the current model — the gateway starts
  one runtime per configured backend at process start, a small static count.
- **`kubernetes` is the scale path for many concurrent isolated instances.** It
  schedules workloads across a node pool through the cluster API server and
  manages their lifecycles centrally.

**Do not scale per-caller, per-session, or per-tenant isolation through a local
container daemon.** Launching many containers concurrently through a single
local Docker/Podman daemon overloads the daemon's API server and makes it a
single point of failure. This is a documented failure mode in large-scale agent
systems: the R2E-Gym project reported that spawning 512 Docker containers per
iteration through the local daemon crashed the Docker daemon, and the fix was to
move scheduling to Kubernetes across a pool of nodes (Cameron R. Wolfe,
["Agentic RL: Frameworks and Best Practices"](https://cameronrwolfe.substack.com/p/agentic-rl),
2026). If a future feature gives each authenticated subject its own isolated
runtime for a personal MCP tool, that many-instance workload belongs on the
`kubernetes` provider, never on local Docker.

**Lifecycle teardown is a first-class requirement, not an afterthought.** At
scale, slow or missing teardown leaks containers/workloads and is itself a
bottleneck and a cost. Every launched runtime must have an explicit stop/TTL
path (the plan already emits `stop_command_hint`); a scale design must prove
that instances are reliably reclaimed, not just started.

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
Docker lifecycle commands, restart-policy-aware launch flags, restart command
audit, guarded name handling, broad egress confirmation, forbidden mount denial,
apply fail-closed behavior, container image denial, and the shared
LocalProcess/Docker provider contract.

For a live Docker daemon smoke on a Docker-enabled host, run:

```bash
scripts/dev/runtime-provider-docker-smoke.sh
```

The smoke is ignored in normal test runs. It sets the explicit
`MCP_GATEWAY_RUNTIME_DOCKER_SMOKE=1` gate, starts a restricted
`docker.io/library/hello-world:latest` container through
`StdRuntimeCommandRunner`, then exercises `inspect`, `logs`, `restart`, and
`rm --force` through the same structured `RuntimePlan` lifecycle commands used
by the provider contract. It also builds a tiny local BusyBox fixture image,
starts it with the same least-privilege Docker defaults, lets the fixture exit
non-zero, and verifies Docker's `on-failure` restart policy brings it back.
Override the
one-shot image with `MCP_GATEWAY_RUNTIME_DOCKER_IMAGE` and the restart fixture
image with `MCP_GATEWAY_RUNTIME_DOCKER_RESTART_IMAGE` when a local registry
mirror is required.
