# Symphony+ Sandbox Descriptor Specification

**Version:** 1.0
**Ticket:** MIK-5226 (RUNTIME-D)

## Overview

The Sandbox Descriptor is the single, substrate-agnostic specification for an
agent sandbox. An operator writes one descriptor; the runtime compiler picks
the appropriate substrate (gVisor on Linux, Apple Virtualization.framework on
macOS).

## Schema

```yaml
name: string                    # Human-readable sandbox name
image: string                   # Container image reference (e.g. docker.io/library/ubuntu:22.04)

resources:
  cpu_millis: u32               # CPU cores in milli-cores (1000 = 1 core)
  memory_bytes: u64             # Memory limit in bytes
  disk_bytes: u64               # Ephemeral storage limit (0 = unlimited)

capabilities:                   # Linux capabilities required inside the sandbox
  - name: string                # e.g. CAP_NET_RAW, CAP_SYS_PTRACE

network_egress:
  mode: string                  # deny | allowlist | unrestricted
  allowed_destinations:         # CIDRs or hostnames (when mode = allowlist)
    - string

env:                            # Environment variables
  KEY: value

mounts:                         # Filesystem mounts
  - source: string              # Host path
    destination: string         # Container path
    mount_type: string          # bind | overlay | tmpfs
    read_only: bool             # true = read-only bind; false = writable overlay

attestation:                    # B1-IDENT: attestation requirements
  required: bool
  measurements:                 # e.g. sha256, tpm2
    - string
  allowed_runtimes:             # Runtime identities permitted
    - string

hebb_bridge:                    # B2-MEM: hebb memory-bridge configuration
  enabled: bool
  endpoint: string              # e.g. http://127.0.0.1:7331
  max_context_tokens: u64

checkpoint_policy:              # B3-DURABLE: checkpoint / durability policy
  enabled: bool
  interval_secs: u64
  storage_path: string
```

## Mount Types

| Type     | Read-Only | Description                              |
|----------|-----------|------------------------------------------|
| `bind`   | yes       | Bind-mount from host path (read-only)    |
| `bind`   | no        | Bind-mount from host path (read-write)   |
| `overlay`| no        | Writable overlay on top of a lower dir   |
| `tmpfs`  | no        | Ephemeral in-memory filesystem           |

## Example

```yaml
name: code-agent
image: symphony/agent-runtime:latest
resources:
  cpu_millis: 2000
  memory_bytes: 4294967296
  disk_bytes: 10737418240
capabilities:
  - name: CAP_NET_RAW
network_egress:
  mode: allowlist
  allowed_destinations:
    - "10.0.0.0/8"
    - api.anthropic.com
env:
  AGENT_MODE: production
  LOG_LEVEL: info
mounts:
  - source: /opt/agent
    destination: /app
    mount_type: bind
    read_only: true
  - source: tmpfs
    destination: /tmp
    mount_type: tmpfs
    read_only: false
attestation:
  required: true
  measurements: [sha256]
  allowed_runtimes: [gvisor, apple-vz]
hebb_bridge:
  enabled: true
  endpoint: "http://127.0.0.1:7331"
  max_context_tokens: 32768
checkpoint_policy:
  enabled: true
  interval_secs: 300
  storage_path: /var/lib/symphony/checkpoints
```
