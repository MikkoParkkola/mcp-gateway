# Substrate Mapping Table

**Ticket:** MIK-5226 (RUNTIME-D)

## Supported Substrates

| Substrate | Platform      | Runtime                              | Output Format               |
|-----------|---------------|--------------------------------------|-----------------------------|
| gVisor    | Linux (Ubuntu)| `runsc` OCI bundle                   | OCI Runtime Spec v1.0.2     |
| Apple     | macOS         | Virtualization.framework (`vz`)      | Apple VM-spec JSON          |

## Auto-Detection

`SubstrateKind::auto_detect()` selects the substrate based on the host OS:

| `cfg!(target_os)` | Substrate |
|--------------------|-----------|
| `linux`            | `Gvisor`  |
| `macos`            | `Apple`   |
| other              | `Gvisor` (fallback) |

## Descriptor → Substrate Field Mapping

### gVisor (OCI Runtime Spec)

| Descriptor Field    | OCI Field                          | Notes                                |
|---------------------|------------------------------------|--------------------------------------|
| `name`              | `hostname`                         | Container hostname                   |
| `image`             | `root.path` / annotation           | Image reference in annotations       |
| `resources`         | `linux.resources.memory.limit`     | Direct mapping                       |
| `resources`         | `linux.resources.cpu.shares`       | cpu_millis → shares                  |
| `capabilities`      | `process.capabilities.bounding`    | Also effective + permitted           |
| `network_egress`    | annotation                         | Network policy enforced by runtime   |
| `env`               | `process.env`                      | `KEY=VALUE` format                   |
| `mounts`            | `mounts[]`                         | OCI mount entries with options       |
| `attestation`       | `annotations["symphony.sandbox.attestation"]` | JSON-encoded              |
| `hebb_bridge`       | `annotations["symphony.sandbox.hebb_bridge"]` | JSON-encoded              |
| `checkpoint_policy` | `annotations["symphony.sandbox.checkpoint_policy"]` | JSON-encoded          |

### Apple (Virtualization.framework VM-spec)

| Descriptor Field    | VM-spec Field       | Notes                                  |
|---------------------|---------------------|----------------------------------------|
| `name`              | `name`              | VM name                                |
| `image`             | `boot_image`        | Boot image reference                   |
| `resources.cpu`     | `cpu_cores`         | `ceil(cpu_millis / 1000)`              |
| `resources.memory`  | `memory_bytes`      | Direct mapping                         |
| `capabilities`      | N/A                 | Apple VM does not expose Linux caps    |
| `network_egress`    | `network`           | NAT or none                            |
| `env`               | `environment`       | Key-value map                          |
| `mounts`            | `mounts[]`          | Shared directories                     |
| `attestation`       | `attestation`       | JSON object                            |
| `hebb_bridge`       | `hebb_bridge`       | JSON object                            |
| `checkpoint_policy` | `checkpoint_policy` | JSON object                            |

## Override Hook

Operators can pin a sandbox to a specific substrate using `OverrideHook`:

```rust
use mcp_gateway::runtime::{OverrideHook, SubstrateKind};
use mcp_gateway::runtime::override_hook::{OverridePolicy, OverrideRule};

let hook = OverrideHook::new().with_policy(OverridePolicy {
    rules: vec![OverrideRule {
        sandbox_name: "gpu-sandbox".into(),
        substrate: SubstrateKind::Gvisor, // always gVisor
    }],
});
```
