# symphony+ Sandbox Descriptor Specification

**AC.1 (MIK-NEW.RUNTIME-D.1)** · **Version 1.0** · **B4-PLATFORM**

## Overview

The Sandbox Descriptor is the single operator-authored specification that
compiles to either a gVisor `runsc` OCI bundle (Linux) or an Apple
containerization VM-spec (macOS). The runtime picks the substrate;
the operator writes one spec.

## Schema

### SandboxDescriptor

| Field             | Type                  | Required | Description                                      |
|-------------------|-----------------------|----------|--------------------------------------------------|
| `name`            | `string`              | Yes      | Human-readable sandbox instance identifier       |
| `image`           | `string`              | Yes      | OCI image reference (e.g. `docker.io/library/ubuntu:22.04`) |
| `resources`       | [`ResourceSpec`](#resourcespec) | Yes | CPU/memory/disk limits                |
| `capabilities`    | `string[]`            | No       | Linux capabilities (e.g. `CAP_NET_BIND_SERVICE`) |
| `network_egress`  | [`NetworkEgressPolicy`](#networkegresspolicy) | No | Egress policy (default: `loopback`) |
| `env`             | `map<string,string>`  | No       | Environment variables                            |
| `mounts`          | [`MountSpec[]`](#mountspec) | No   | Filesystem mounts (read-only + writable overlay) |
| `attestation`     | [`AttestationConfig?`](#attestationconfig) | No | Image attestation requirements (B1-IDENT) |
| `hebb_bridge`     | [`HebbBridgeConfig?`](#hebbbridgeconfig) | No | Memory bridge configuration (B2-MEM) |
| `checkpoint_policy` | [`CheckpointPolicy?`](#checkpointpolicy) | No | Snapshot/persistence policy (B3-DURABLE) |
| `substrate_override` | [`Substrate?`](#substrate) | No | Pin to specific substrate (AC.5) |

### ResourceSpec

| Field       | Type   | Default | Description                                   |
|-------------|--------|---------|-----------------------------------------------|
| `cpu_cores` | `f64`  | `1.0`   | CPU cores (fractional allowed)                |
| `memory_mb` | `u64`  | `512`   | Memory limit in megabytes                     |
| `disk_mb`   | `u64`  | `0`     | Disk limit in MB (0 = image default)          |

### NetworkEgressPolicy

| Value         | Description                              |
|---------------|------------------------------------------|
| `none`        | No network access                        |
| `loopback`    | Localhost only (default)                 |
| `full`        | Full internet access                     |
| `["cidr",…]`  | Allowlist of CIDR ranges                 |

### MountSpec

| Field    | Type                      | Required | Description                           |
|----------|---------------------------|----------|---------------------------------------|
| `type`   | [`MountType`](#mounttype) | Yes      | `read_only` or `writable_overlay`     |
| `source` | `string`                  | Yes      | Host path                             |
| `target` | `string`                  | Yes      | Sandbox-internal path                 |

### MountType

| Value              | Description                                    |
|--------------------|------------------------------------------------|
| `read_only`        | Read-only bind mount; sandbox cannot modify    |
| `writable_overlay` | Copy-on-write overlay; host source is untouched |

### AttestationConfig (B1-IDENT)

| Field       | Type      | Required | Description                                     |
|-------------|-----------|----------|-------------------------------------------------|
| `method`    | `string`  | Yes      | Attestation method (e.g. `cosign`, `notary`)    |
| `signer`    | `string`  | Yes      | Expected signer identity                        |
| `rekor_url` | `string?` | No       | Transparency log URL                            |

### HebbBridgeConfig (B2-MEM)

| Field         | Type      | Required | Description                                   |
|---------------|-----------|----------|-----------------------------------------------|
| `endpoint`    | `string`  | Yes      | Hebb database endpoint URL                    |
| `namespace`   | `string`  | Yes      | Memory namespace for this sandbox             |
| `max_entries` | `usize`   | No       | Max entries to retain (default: `10000`)      |

### CheckpointPolicy (B3-DURABLE)

| Field           | Type      | Required | Description                                     |
|-----------------|-----------|----------|-------------------------------------------------|
| `interval_secs` | `u64`     | Yes      | Snapshot interval in seconds                    |
| `max_snapshots` | `usize`   | No       | Max snapshots to retain (default: `5`)          |
| `snapshot_dir`  | `string`  | Yes      | Host path for snapshot storage                  |

### Substrate

| Value      | Description                                       |
|------------|---------------------------------------------------|
| `gvisor`   | gVisor `runsc` OCI runtime (Linux)               |
| `apple_vm` | Apple containerization via Hypervisor.framework  |

## Minimal Example

```json
{
  "name": "agent-sandbox",
  "image": "ghcr.io/symphony/agent-runtime:v2",
  "resources": {
    "cpu_cores": 1.0,
    "memory_mb": 512
  }
}
```

## Full Example

```json
{
  "name": "full-sandbox",
  "image": "docker.io/library/ubuntu:22.04",
  "resources": {
    "cpu_cores": 2.0,
    "memory_mb": 2048,
    "disk_mb": 10240
  },
  "capabilities": ["CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE"],
  "network_egress": "full",
  "env": {
    "LANG": "C.UTF-8",
    "LOG_LEVEL": "debug"
  },
  "mounts": [
    {
      "type": "read_only",
      "source": "/host/models",
      "target": "/models"
    },
    {
      "type": "writable_overlay",
      "source": "/host/scratch",
      "target": "/workspace"
    }
  ],
  "attestation": {
    "method": "cosign",
    "signer": "ci@symphony.dev",
    "rekor_url": "https://rekor.sigstore.dev"
  },
  "hebb_bridge": {
    "endpoint": "http://hebb:8080",
    "namespace": "agent-session-42",
    "max_entries": 10000
  },
  "checkpoint_policy": {
    "interval_secs": 300,
    "max_snapshots": 5,
    "snapshot_dir": "/var/snapshots/agent-session-42"
  },
  "substrate_override": "gvisor"
}
```
