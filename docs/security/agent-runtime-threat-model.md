# Agent-Runtime Threat Model

> **MIK-NEW.RUNTIME.5** — Covers all four agent-runtime primitives:
> attestation (B1-IDENT), hebb bridge (B2-MEM), sandbox checkpoint (B3-DURABLE),
> and dual-substrate OCI (B4-PLATFORM).

## Scope

This document models threats against the symphony+ agent-runtime layer: the
software that wraps a commodity sandbox (gVisor / Apple containerization) with
first-party orchestration. The sandbox substrate itself is considered a
trusted, upstream-hardened boundary.

## Asset Inventory

| Asset | Confidentiality | Integrity | Availability |
|-------|----------------|-----------|-------------|
| Agent identity (attestation token) | High | Critical | High |
| Task execution state (checkpoint) | Medium | Critical | Medium |
| Session memory (hebb bridge) | High | High | Medium |
| Sandbox descriptor (OCI spec) | Low | Critical | High |

## Threat 1: Token Forgery (B1-IDENT)

**Attack surface**: An adversary crafts or replays an attestation token to
impersonate an agent or escalate capabilities.

**Attack vectors**:
- T1.1: Replay a captured token before its expiration
- T1.2: Forge a token with a guessed HMAC-SHA256 key
- T1.3: Modify the capability allow-list in transit (MITM)
- T1.4: Exploit token rotation to retain access after revocation

**Mitigations**:
- **M1.1 — HMAC-SHA256 signing** (`src/attestation/signer.rs:97`): Every token
  carries an HMAC-SHA256 signature over the claims. Signature verification is
  constant-time via `Mac::verify_slice`. The signing key is never exposed to
  sandboxes.
- **M1.2 — Token expiration** (`src/attestation/token.rs:48`): Every token
  carries an RFC-3339 `expires_at` claim. Expired tokens are rejected with
  `AttestationRejection::Expired`.
- **M1.3 — Rotation with grace window** (`src/attestation/validator.rs:314`):
  Rotated tokens enter a configurable grace window (default 30s) during which
  in-flight calls are not disrupted, then are rejected as `RotatedOut`.
- **M1.4 — Audit ring buffer** (`src/attestation/validator.rs:174`): Every
  rejected token is recorded with detection latency. The audit signal is
  observably distinct from other telemetry.

**Residual risk**: LOW. Token forgery requires key compromise. Key rotation
and audit logging provide defense-in-depth.

---

## Threat 2: Bridge MITM (B2-MEM)

**Attack surface**: An adversary intercepts or manipulates traffic between
the sandboxed agent and the host hebb-serve daemon on `127.0.0.1:39400`.

**Attack vectors**:
- T2.1: Intercept recall/remember calls on loopback
- T2.2: Replay a captured auth header from another sandbox
- T2.3: Inject crafted payloads that exploit hebb-serve parsing
- T2.4: Denial-of-service by saturating the bridge

**Mitigations**:
- **M2.1 — Loopback-only egress** (`src/hebb_bridge/client.rs:34`): The bridge
  enforces `127.0.0.1:39400/mcp` as the only reachable endpoint. Loopback
  traffic is isolated by the sandbox network namespace.
- **M2.2 — Per-sandbox auth header** (`src/hebb_bridge/client.rs:194`): Each
  sandbox receives a unique auth token. Cross-sandbox token reuse is
  detectable in audit logs.
- **M2.3 — Read-only by default** (`src/hebb_bridge/client.rs:243`): Write
  operations require an explicit capability grant in the attestation token.
- **M2.4 — Audit trail** (`src/hebb_bridge/audit.rs`): Every recall/remember
  call is recorded with a monotonically-increasing sequence number.
- **M2.5 — Fallback isolation** (`src/hebb_bridge/client.rs:133`): On bridge
  failure, the agent falls back to in-sandbox ephemeral memory. No host
  write-through occurs.

**Future hardening**: mTLS on the bridge loopback connection would add
transport-layer authentication (noted for post-MVP).

**Residual risk**: MEDIUM. Loopback MITM requires sandbox escape, which is
the substrate's responsibility. Auth header replay within the same sandbox
is inherent to the bearer-token model.

---

## Threat 3: Checkpoint Poisoning (B3-DURABLE)

**Attack surface**: An adversary corrupts or replaces a sandbox checkpoint
to inject malicious state that resumes after host restart.

**Attack vectors**:
- T3.1: Replace a checkpoint artifact on disk
- T3.2: Corrupt checkpoint metadata to force replay-from-zero
- T3.3: Exploit deserialization of checkpoint state
- T3.4: Exhaust disk space to prevent future checkpoints

**Mitigations**:
- **M3.1 — SHA-256 integrity hash** (`src/sandbox_checkpoint/snapshot.rs:111`):
  Every checkpoint artifact is hashed with SHA-256. The hash is verified
  before resume; mismatch triggers replay-from-zero with a security event.
- **M3.2 — Monotonic sequence numbers** (`src/sandbox_checkpoint/snapshot.rs:194`):
  Checkpoint sequence is strictly monotonic. A replayed or out-of-order
  sequence is detectable.
- **M3.3 — Fail-open on checkpoint failure** (`src/sandbox_checkpoint/snapshot.rs:176`):
  A failed checkpoint logs a warning but the task continues. No task is
  aborted due to checkpoint failure.
- **M3.4 — Replay-from-zero fallback** (`src/sandbox_checkpoint/snapshot.rs:255`):
  When no valid checkpoint exists, the task starts from zero. This is the
  safe default.
- **M3.5 — Snapshot retention policy**: `max_snapshots` limits disk usage.

**Residual risk**: MEDIUM. Checkpoint integrity depends on filesystem
permissions. A sandbox-escape attacker with filesystem write access could
modify checkpoint artifacts.

---

## Threat 4: Substrate-Divergence Escape (B4-PLATFORM)

**Attack surface**: An adversary exploits behavioural differences between the
gVisor and Apple containerization substrates to escape the sandbox or gain
privileges unavailable on the other substrate.

**Attack vectors**:
- T4.1: Exploit a gVisor-specific syscall that Apple blocks (or vice versa)
- T4.2: Exploit divergent capability handling across substrates
- T4.3: Exploit divergent network egress enforcement
- T4.4: Exploit divergent mount behaviour

**Mitigations**:
- **M4.1 — Single descriptor, two outputs** (`src/runtime/compiler.rs:325`):
  One `SandboxDescriptor` compiles to both substrates. The `compile_both`
  method produces both outputs for A/B comparison.
- **M4.2 — Divergence registry** (`src/runtime/divergence.rs`): Structural
  differences between substrate outputs are recorded and surfaced. The test
  matrix (AC.4) runs the same 10-task workload on both.
- **M4.3 — Capability allowlisting** (`src/runtime/provision.rs:45`):
  Forbidden capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, etc.) are
  rejected at the provisioning boundary regardless of substrate.
- **M4.4 — Egress config parity** (`src/runtime/compiler.rs:290`): Both
  substrates emit the same `EgressConfig` from the same descriptor. The
  `egress` field is compared for divergence.
- **M4.5 — Mount safety preflight** (`src/runtime/provision.rs:160`): Path
  traversal and sensitive host prefix mounts are blocked before compilation.

**Residual risk**: MEDIUM. Substrate divergence is inherent to dual-platform
support. The divergence registry and test matrix reduce but do not eliminate
the risk.

---

## Threat 5: Composability Boundary Violation (AC.7)

**Attack surface**: A portfolio primitive (mcp-gateway, claude-elite, pithy,
hebb) bypasses the sandbox boundary and executes directly on the host.

**Attack vectors**:
- T5.1: mcp-gateway tool invocation reaches host filesystem
- T5.2: claude-elite skill loading reads outside sandbox mounts
- T5.3: pithy live-docs write through to host
- T5.4: hebb daemon accessed directly, bypassing the bridge

**Mitigations**:
- **M5.1 — mcp-gateway routing through bridge** (`src/hebb_bridge/client.rs`):
  Gateway tool calls that require memory access go through the bridge, not
  directly to hebb.
- **M5.2 — Sandbox-mounted filesystem** (`src/runtime/descriptor.rs:128`):
  Skills and docs are loaded from read-only sandbox mounts. The host source
  is never modified.
- **M5.3 — Hebb stays on host daemon** (`src/hebb_bridge/mod.rs:24`):
  The hebb daemon runs on the host. Sandboxes reach it only through the
  controlled IPC bridge.
- **M5.4 — Composability tests** (`tests/agent_runtime_composability.rs`):
  Integration tests verify no primitive bypasses the sandbox boundary.

**Residual risk**: LOW. All cross-boundary calls go through the gateway's
attestation validator. Direct host access requires a sandbox escape first.

---

## Security Posture Summary

| Primitive | Attack Surface | Primary Mitigation | Residual Risk |
|-----------|---------------|-------------------|---------------|
| Attestation (B1) | Token forgery | HMAC-SHA256 + expiry + rotation | Low |
| Hebb Bridge (B2) | MITM on loopback | Per-sandbox auth + read-only default | Medium |
| Checkpoint (B3) | Artifact poisoning | SHA-256 integrity + monotonic seq | Medium |
| Dual-substrate (B4) | Divergence escape | Divergence registry + test matrix | Medium |
| Composability | Boundary bypass | All calls through attestation validator | Low |

## Future Hardening (Post-MVP)

1. **Bridge mTLS**: Add mutual TLS on the loopback bridge connection for
   transport-layer authentication.
2. **Checkpoint encryption**: Encrypt checkpoint artifacts at rest.
3. **Substrate fuzzing**: Differential fuzzing of gVisor vs Apple syscall
   behaviour.
4. **Attestation key rotation automation**: Automated key rotation without
   service disruption.
