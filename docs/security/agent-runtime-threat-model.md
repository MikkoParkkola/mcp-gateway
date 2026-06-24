# Agent Runtime Threat Model

## Scope

This document covers the symphony+ agent-runtime layer composed in MIK-5219:
attestation token injection, the hebb-memory bridge, sandbox checkpoint/resume,
and the dual-substrate OCI abstraction over gVisor and Apple containerization.

## Assets

- Agent identity, task UUID, capability allow-list, and attestation expiry.
- Host hebb daemon memory reachable only through the controlled bridge.
- Checkpoint images and scheduler resume metadata.
- Cross-substrate equivalence between the gVisor `runsc` OCI bundle and the
  Apple containerization VM-spec.
- Audit trails that attribute boot, bridge, checkpoint, and benchmark events.

## Threats And Mitigations

| Attack surface | Threat | Mitigation |
|---|---|---|
| Token forgery | An attacker forges or tampers with a sandbox token to impersonate an agent or widen capability scope. | Tokens are signed by bnaut-attestation key material; the gateway validates signature, issuer, expiration, rotation state, and exact capability grants at boot and every cross-boundary call. Missing or invalid boot tokens fail closed. |
| Bridge MITM | A process bypasses or intercepts host hebb IPC to read/write memory outside the sandbox policy. | The bridge is allow-listed to `127.0.0.1:39400/mcp`, carries a per-sandbox auth header, and is designed for mTLS at the transport boundary. Reads are default; writes require the `hebb:write` attestation scope. Denied bridge connections fall back to ephemeral in-sandbox memory with no host write-through. |
| Checkpoint poisoning | A malicious or stale checkpoint causes resume from corrupted state or replays completed work. | Scheduler checkpoint metadata is bound to the task UUID and should carry a checkpoint integrity hash. Resume uses the last valid checkpoint and a completed-step ledger; checkpoint failures emit `agent_runtime_checkpoint_warning_total` and the task continues with the documented replay-from-zero fallback. |
| Substrate-divergence escape | A sandbox descriptor compiles to materially different isolation or egress behavior on Linux vs macOS. | The single `SandboxDescriptor` compiles to both gVisor OCI and Apple VM-spec, records structural divergences, and runs the same 10-task matrix on Spark and macOS with identical attestation, memory bridge, and audit trail signals. |

## Residual Risk

The runtime plan is deterministic and unit-tested, but substrate enforcement still
depends on the platform launcher applying the emitted egress, mTLS, checkpoint
hash, and resume metadata exactly. Ship-time dogfood validation for MIK-5219 must
confirm the operator loop runs inside the agent-runtime stack.
