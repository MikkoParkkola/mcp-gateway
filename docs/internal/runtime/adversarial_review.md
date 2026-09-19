# Runtime Substrate — Adversarial Review (PR #260 / MIK-5226)

**Reviewer:** automated adversarial pass · **Verdict:** foundation is sound but
was **dormant and fail-open by default**. Green CI proved the compiler is
*correct*, not that it is *safe to enable*. This review documents the failure
modes and the minimal wiring that closes the most dangerous ones at the call
boundary.

The wired call path (`src/runtime/provision.rs`, CLI `runtime compile`, feature
`runtime-substrate`, off by default) runs schema + security preflight **before**
the compiler. Findings marked **[GATED]** are now hard-failed there; findings
marked **[WARN]** surface a non-fatal warning; **[OPEN]** remain for a future
launcher.

## 1. Substrate selection — detection is compile-time, not a capability probe [OPEN]

`Substrate::detect()` is a `#[cfg(target_os)]` constant. On Linux it returns
`GVisor` even if `runsc` is not installed; on macOS it returns `AppleVm` even if
Apple containerization / Hypervisor.framework is unavailable. There is **no
runtime probe** for whether the selected runtime actually exists, and `detect()`
cannot return "none" — so the "neither substrate available" case is
inexpressible. A bundle for a non-existent runtime compiles fine and only fails
opaquely at launch (when a launcher eventually exists).
*Mitigation:* the wired path refuses to silently cross-compile; a launcher must
add an executable/framework probe before this is production-safe.

## 2. `compile()` never validates the descriptor [GATED]

`Compiler::compile` is infallible and never calls `SandboxDescriptor::validate()`.
An empty `name` yields `root.path = "rootfs-"` and an empty `hostname`; empty
mount sources produce malformed OCI mounts; zero memory compiles. Validation
*exists* but was never on the compile path.
*Closed:* `provision::preflight` runs `validate()` first.

## 3. Resource cleanup / lifecycle [WARN/OPEN]

The compiler allocates nothing, so there is no leak in *this* layer. But the
descriptor implies host resources a future launcher will own — `rootfs-{name}`
dirs, writable-overlay COW layers, `checkpoint_policy.snapshot_dir` — and **no
ownership or cleanup-on-crash contract is defined** for them. Separately, the
`DivergenceRegistry` is an unbounded `Arc<Mutex<Vec<_>>>`; a long-lived compiler
that compiles many descriptors grows it without cap or eviction. (The wired path
uses a fresh registry per `--both` compile, so it is bounded there.)

## 4. Privilege boundaries [GATED + WARN]

- **Capability divergence (the headline privilege bug):** `compile_gvisor`
  **silently drops** `descriptor.capabilities` — they are never emitted into the
  OCI bundle. `compile_apple_vm` passes them straight through as `entitlements`.
  The *same descriptor* therefore grants privileges on macOS but not Linux, and
  `detect_divergence` does **not** check capabilities, so AC.4 ("CI fails on
  undocumented divergence") misses exactly this. **[GATED]** dangerous caps
  (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_DAC_*`, `ALL`, …)
  are now rejected; **[WARN]** any caps on a gVisor compile warn that they are
  dropped.
- **No capability allowlist** in the original code — arbitrary strings accepted.
- **`root.readonly = false` hardcoded** for gVisor — rootfs is always writable;
  no way to request a read-only root. **[OPEN]**

## 5. Injection via runtime config [GATED + WARN]

- **Mount sources are passed through verbatim** with no sanitization. `/`,
  `/etc/...`, `../../` bind-mount the host into the sandbox. **[GATED]**: the
  preflight rejects relative sources, `..` traversal, host-root, and sensitive
  prefixes (`/etc`, `/root`, `/proc`, `/sys`, `/dev`, `/var/run`).
- **`name` flows into `root.path` and `hostname`** unsanitized (path-component /
  hostname injection). **[OPEN]** — lower severity; recommend a charset gate.
- **`env` keys/values unvalidated.** **[OPEN]**

## 6. Network egress is decorative / fail-open [WARN]

`network_egress` is **not enforced by either substrate**. On gVisor it is not
emitted into the OCI bundle at all (only a `network` namespace is created); on
Apple VM, `None` → no network, but `Loopback`, `Full`, **and `Allowlist`** all
collapse to "NAT enabled" — the allowlist comment even says enforcement happens
"at the egress firewall," which **does not exist in this code**. So `None` is
fail-open on gVisor and `Allowlist` is fail-open everywhere. **[WARN]** the
wired path warns loudly on `None` and `Allowlist`; real enforcement is **[OPEN]**
for the launcher. This is the single most security-sensitive gap.

## 7. NaN / overflow in resources [GATED]

`validate()` rejects `cpu_cores <= 0` but **NaN passes** (`NaN <= 0.0` is false),
then `NaN.ceil() as u32 == 0` → a 0-vCPU VM. `memory_mb * 1_048_576 as i64` can
silently wrap for huge values. **[GATED]** non-finite `cpu_cores` is now rejected;
the memory overflow remains **[OPEN]** (recommend a sane upper bound).

## 8. Divergence detection is incomplete (AC.4 weakness) [OPEN]

`detect_divergence` compares only mount-count, CPU, and env-count. It does **not**
compare capabilities/entitlements (finding #4), network-egress semantics,
attestation/hebb/checkpoint presence, or disk. "CI fails on undocumented
divergence" therefore misses the most security-relevant divergences. Recommend
extending it before relying on it as a gate.

## 9. `#[serde(untagged)]` on `NetworkEgressPolicy::Allowlist` [OPEN]

The untagged variant means any YAML sequence parses as `Allowlist`, and CIDR
strings are never validated as CIDRs. A typo'd policy name fails to parse rather
than falling to a safe default — acceptable (fails closed on parse) but the
CIDR contents are unchecked.

## Wiring summary

- **Call path:** `mcp-gateway runtime compile <descriptor.yaml> [--both]`
  → `runtime::provision::compile_descriptor_file` → `preflight` → `Compiler`.
- **Feature:** `runtime-substrate` (NOT in `default`). The dormant compiler stays
  unreachable in production until an operator opts in.
- **Does NOT launch a sandbox** — provisioning a live runtime is deliberately out
  of scope until a launcher (and the substrate capability probe from finding #1)
  exists.
- **Tests:** 19 wiring tests in `src/runtime/provision_tests.rs`, each named for
  the finding it covers.
