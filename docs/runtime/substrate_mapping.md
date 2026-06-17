# Substrate Mapping Table

**AC.2 (MIK-NEW.RUNTIME-D.2)** · RUNTIME-D Compiler Reference

## Overview

The compiler translates a single [`SandboxDescriptor`](descriptor_spec.md) into
substrate-specific output.  This table documents how each descriptor field maps
to gVisor OCI bundle fields and Apple VM-spec fields.

## Field Mapping

| Descriptor Field       | gVisor OCI Bundle                          | Apple VM-spec                       |
|------------------------|--------------------------------------------|-------------------------------------|
| `name`                 | `hostname`                                 | `vm_name`                           |
| `image`                | `root.path` (rootfs dir)                   | `image` (OCI ref)                   |
| `resources.cpu_cores`  | `linux.resources.cpu_shares` (×1024)       | `vcpu_count` (ceil)                 |
| `resources.memory_mb`  | `linux.resources.memory_limit` (×1048576)  | `memory_mb`                         |
| `resources.disk_mb`    | N/A (handled by runsc rootfs)              | `disk_mb`                           |
| `capabilities`         | N/A (OCI caps via `linux.resources`)       | `entitlements`                      |
| `network_egress:none`  | No net namespace                           | `network.enabled=false`             |
| `network_egress:full`  | Standard net namespace                     | `network.enabled=true, nat=true`    |
| `network_egress:loopback` | Net namespace, no external routes        | `network.enabled=true, nat=true`    |
| `env`                  | `env` (map)                                | `env` (map)                         |
| `mounts[*].read_only`  | `mounts[]` with option `"ro"`              | `virtiofs_mounts[]` read_only=true  |
| `mounts[*].writable_overlay` | `mounts[]` without `"ro"` option     | `virtiofs_mounts[]` read_only=false |
| `attestation`          | N/A (gVisor doesn't enforce)               | `attestation` (passthrough)         |
| `hebb_bridge`          | N/A (gVisor doesn't enforce)               | `hebb_bridge` (passthrough)         |
| `checkpoint_policy`    | N/A (gVisor doesn't enforce)               | `checkpoint_policy` (passthrough)   |
| `substrate_override`   | Compiler respects override                 | Compiler respects override          |

## Structural Differences

| Aspect            | gVisor OCI                                      | Apple VM-spec                          |
|-------------------|-------------------------------------------------|----------------------------------------|
| Mount model       | OCI bind mounts + automatic `/proc` mount       | Virtio-fs shares with tags             |
| CPU model         | CFS shares (1024 per core)                      | Virtual CPU count (integer)            |
| Memory model      | Limit in bytes                                  | Limit in megabytes                     |
| Network model     | Linux network namespace                         | VM network + NAT                       |
| Namespaces        | 5 namespaces: pid, network, ipc, uts, mount     | N/A (full VM isolation)                |
| Attestation       | Not enforced by runtime                         | Passthrough to VM configuration         |
| Hebb bridge       | Not enforced by runtime                         | Passthrough to VM configuration         |
| Checkpointing     | Not enforced by runtime                         | Passthrough to VM configuration         |

## Auto-Detection

```text
┌─────────────────┐
│ target_os check │
├─────────────────┤
│ Linux  → gVisor │
│ macOS  → AppleVM│
│ Other  → gVisor │ (fallback: OCI is most portable)
└─────────────────┘
```

The operator can override via `substrate_override` (AC.5).
