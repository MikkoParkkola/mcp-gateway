# Runtime Providers — Backend MCP Server Execution

mcp-gateway supports three runtime providers for executing backend MCP
servers.  The provider is selected via the `runtime.provider` field in
`BackendConfig`.

## Architecture

The runtime system has two distinct layers (do not confuse them):

| Layer | Feature flag | What it does |
|---|---|---|
| **runtime-substrate** | `runtime-substrate` | Compiles a `SandboxDescriptor` into an OCI bundle or Apple VM-spec. Design tool for advanced operators. Answers "what should the sandbox look like?" — NEVER launches processes. |
| **Backend runtime providers** | Always on | The `RuntimeProvider` trait. Implementations (`local_compat`, `docker`, `podman`) actually spawn, monitor, and stop MCP server processes/containers. Answers "run this MCP server now." |

They share the `src/runtime/` directory for discoverability but operate at
completely different lifecycle phases — the descriptor compiler is a
pre-launch design tool; the backend runtime provider layer is the production
execution path for every `Backend::start()` call.

## Available Providers

### `local_compat` (default)

Preserves the existing direct-launch stdio behavior.  The backend process
runs on the host with ambient privileges.

```yaml
backends:
  my-server:
    command: "node my-mcp-server.js"
    # runtime defaults to local_compat — no config needed
```

Explicit form:

```yaml
backends:
  my-server:
    command: "node my-mcp-server.js"
    runtime:
      provider: local_compat
```

### `provider: docker`

Runs the MCP server in a Docker container with restricted defaults.

```yaml
backends:
  my-server:
    command: "node my-mcp-server.js"
    runtime:
      provider: docker
      resources:
        cpu: 1.0
        memory: "512MiB"
      mounts:
        allow_writable: false
        mounts:
          - host: /tmp/data
            container: /data
      egress:
        deny_default: true
        allowlist:
          - "10.0.0.0/8"
      env_policy:
        inherit_env: false
        allowlist:
          - PATH
          - HOME
      identity:
        user: "1000"
      timeouts:
        start_secs: 60
      log_policy:
        capture: true
        max_lines: 500
```

#### Docker restricted defaults

| Setting | Default | Notes |
|---|---|---|
| Network | `--network none` (when `egress.deny_default: true`) | No host network access |
| Root filesystem | `--read-only` | Read-only unless writable mounts declared |
| Environment | Explicit `--env` per variable | Only allowlisted vars passed |
| Mounts | Read-only `:ro` bind mounts | Writable requires `writable: true` + `allow_writable: true` |
| Resource limits | `--cpus`, `--memory` | Set via `resources.cpu` and `resources.memory` |
| Labels | `mcp-gateway.backend`, `mcp-gateway.provider` | Deterministic; no random labels |
| Privileged | Denied | `--privileged` forbidden |
| seccomp | Denied | `--seccomp=unconfined` forbidden |
| Docker socket | Denied | `/var/run/docker.sock` mount forbidden |
| Host network | Denied | `--network=host` forbidden |
| PID namespace | Denied | `--pid=host` forbidden |

### `provider: podman`

Same as Docker but uses the `podman` binary.  All restricted defaults apply.

```yaml
backends:
  my-server:
    command: "node my-mcp-server.js"
    runtime:
      provider: podman
      resources:
        cpu: 1.0
        memory: "256MiB"
```

## Security Tradeoff Table

| Feature | `local_compat` | `docker` | `podman` |
|---|---|---|---|
| Network isolation | ❌ None | ✅ `--network none` by default | ✅ `--network none` by default |
| Filesystem isolation | ❌ Host access | ✅ Read-only root, bind mounts | ✅ Read-only root, bind mounts |
| Environment isolation | ❌ Inherits host env | ✅ Explicit allowlist only | ✅ Explicit allowlist only |
| Secret handling | ⚠️ Pass-through | ✅ Redacted in audit | ✅ Redacted in audit |
| Resource limits | ❌ None | ✅ `--cpus`, `--memory` | ✅ `--cpus`, `--memory` |
| Privileged mode | N/A | ❌ Denied | ❌ Denied |
| Docker socket access | N/A | ❌ Denied | ❌ Denied |
| Log capture | ⚠️ Via stderr | ✅ Container logs | ✅ Container logs |
| Audit trail | ✅ NDJSON | ✅ NDJSON with redaction | ✅ NDJSON with redaction |
| Compatibility | ✅ Full (existing behavior) | ⚠️ Requires Docker | ⚠️ Requires Podman |
| Startup latency | ✅ Immediate | ⚠️ Pull + create | ⚠️ Pull + create |

## Policy Enforcement

All providers enforce **fail-closed** semantics:

1. Policy is validated BEFORE any process or container is started.
2. If the provider cannot enforce a requested policy (e.g. egress allowlist
   on `local_compat`), the launch is denied with an audit event.
3. Denied policies produce `AuditAction::PolicyDenied` events in the audit
   stream with human-readable reasons.

## Audit Events

Every runtime decision emits a single NDJSON line to the `runtime_audit`
tracing target.  Secret values are redacted (`<redacted>`) but secret keys
and policy content hashes are preserved for traceability.

Example audit output:

```json
{"timestamp":"2025-07-23T12:00:00Z","backend":"my-server","provider":"docker","action":"provider_selected","verdict":"allow","policy_hash":"abcd1234...","context":{}}
{"timestamp":"2025-07-23T12:00:01Z","backend":"my-server","provider":"docker","action":"started","verdict":"allow","policy_hash":"abcd1234...","context":{"command":"node my-mcp-server.js"}}
```

## Migration from `local_compat`

Existing `gateway.yaml` files work without changes — omitted `runtime` key
defaults to `local_compat`.  To migrate a backend to container isolation:

1. Install Docker or Podman.
2. Build a container image for your MCP server.
3. Add `runtime.provider: docker` (or `podman`) to the backend config.
4. Configure `resources`, `egress`, `mounts`, and `env_policy` as needed.
5. The gateway validates the policy and starts the container automatically.
