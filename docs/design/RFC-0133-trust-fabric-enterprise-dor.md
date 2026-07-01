# RFC-0133: Trust Fabric enterprise slices — DoR, design, and test plans

**Date**: 2026-07-01
**Status**: Draft (DoR pending approval)
**Deciders**: Mikko Parkkola
**References**: ADR-004, ADR-005, ADR-006; MIK-6691, MIK-6684, MIK-6685, MIK-6688, MIK-6689
**Technical review**: GPT-5.5 advisory + adversarial (2026-07-01)

---

## Purpose

Bring the four active, Mac-buildable enterprise slices to Definition-of-Ready:
testable acceptance criteria with stable IDs, interface/architecture design, and
a test plan per slice. No slice starts implementation until its section here is
approved. Heavy/operator/durable-DB work is demand-gated (ADR-004/005) and out of
scope.

---

## Slice A — MIK-6691: enterprise Helm chart (+ MIK-6684 supply-chain)

### Requirements
Enterprises must be able to deploy, upgrade, and roll back mcp-gateway on
Kubernetes with no adoption blockers: signed OCI-distributed chart, hardened
secure-by-default posture, air-gap support, and a stable values contract. No
bespoke operator (ADR-004). The Helm **values file is the supported contract**;
CRDs remain experimental and ship in a *separate* opt-in chart.

### Architecture / design
- `deploy/helm/mcp-gateway/` — application chart. Templates the existing
  Deployment/Service/ConfigMap/RBAC/NetworkPolicy from `values.yaml`.
- `deploy/helm/mcp-gateway-crds/` — separate chart carrying the 5 alpha CRDs.
  Not a dependency of the app chart. Documents Helm's CRD-upgrade limitation
  (Helm does not manage CRD upgrade/delete lifecycle).
- `values.schema.json` validates values (image, resources, replicas, security,
  networkPolicy, config).
- Secure-by-default = Pod Security `restricted`: `runAsNonRoot`, no privilege
  escalation, `cap-drop: ALL`, `seccompProfile: RuntimeDefault`, read-only root
  FS. Default-deny NetworkPolicy with explicit ingress/egress incl. DNS.
- Image pinned by `@sha256` digest (MIK-6684), overridable for private/air-gapped
  registries. FIPS/hardened image is an *override knob*, not an official FIPS
  claim.
- Supply chain: chart + image cosign-signed with provenance; SBOM published.

### Acceptance criteria
- **MIK-6691.HELM.1** `helm template` renders exactly the required set —
  Deployment `mcp-gateway`, Service `mcp-gateway`, ConfigMap `mcp-gateway-config`,
  ServiceAccount + Role + RoleBinding, NetworkPolicy — with no extra Kinds;
  `helm lint` clean; `values.schema.json` rejects an invalid values file.
- **MIK-6691.HELM.2** kind CI: `helm install` the chart, `helm upgrade` to a new
  image, assert rollout, `helm rollback`, assert convergence (extends MIK-6679,
  now via the chart not raw manifests).
- **MIK-6691.HELM.3** rendered pods satisfy Pod Security `restricted` — enforced
  authoritatively in kind CI via a namespace labeled
  `pod-security.kubernetes.io/enforce=restricted` (admission rejects violators),
  with a fast offline field pre-check; the NetworkPolicy is workload-scoped and
  restrictive (ingress to the service port, egress to HTTPS + DNS), not a
  namespace-wide default-deny (an app chart must not impose that on the namespace).
- **MIK-6691.HELM.4** CRDs live in a separate `mcp-gateway-crds` chart; the app
  chart installs and runs with zero CRDs present.
- **MIK-6691.HELM.5** `helm package` + push to an **ephemeral OCI registry**,
  then pull and render the *same* artifact (not a push dry-run); image is
  digest-pinned (`@sha256`) and overridable via `values.image.*`.
- **MIK-6691.HELM.6** release workflow signs chart + image with `cosign` and the
  test runs `cosign verify` against the exact chart OCI ref and image ref; an
  SBOM (SPDX/CycloneDX) is attached and its presence asserted.
- **MIK-6691.HELM.7** **air-gap proof**: chart + image + signatures + provenance
  + SBOM export to, and import from, a registry with no internet, then a
  successful render/install from that offline registry.
- **MIK-6691.HELM.8** **RBAC least-privilege**: the ServiceAccount grants only
  the verbs/resources the gateway needs (assert the Role rules explicitly); token
  automount is disabled unless required.
- **MIK-6691.HELM.9** `values.schema.json` is versioned; a documented
  compatibility policy (additive-only within a minor) with a schema-diff check in
  CI.

### Fail-fast
HELM.2 (chart upgrade+rollback on a real kind cluster) lands first — if the chart
cannot upgrade+rollback, packaging is wrong before security/supply-chain polish.

### Test plan
`helm lint` + `helm template | kubeconform`; `values.schema.json` negative test;
extend `kind-rollback-smoke.sh` to install via `helm`; Pod Security + NetworkPolicy
+ RBAC-rule assertions (conftest/kubectl jsonpath); ephemeral-OCI package/push/pull
round-trip; air-gap export/import round-trip; `cosign verify` + SBOM presence in
the release workflow; schema-version diff check.

---

## Slice B — MIK-6685: `ControlPlaneStore` trait + file backend + audit view

### Requirements
The control-plane grants/policies must persist across restarts (single-node
free/core), and the audit-evidence view must stop being empty — fed by the
existing tamper-evident log, not a new DB (ADR-005).

### Architecture / design
- `ControlPlaneStore` trait: `list/get/put/delete` for grants and policies;
  `append_audit(event)` + `read_audit(filter)` for governance events.
- **Config backend** (grants/policies): whole-file atomic write per collection —
  read-modify-validate → write temp in same dir → `fsync` file → `rename` →
  `fsync` dir. Cross-process safety: a CLI writer and the server writer are
  *separate processes*, so a Rust `Mutex` is insufficient (GPT-5.5 catch). Guard
  each collection with an **OS advisory file lock** (`flock`) held across the
  read-modify-write, plus a monotonic `generation` field for compare-and-swap so
  a stale write is rejected. Malformed JSON fails closed: load errors and the
  last-good file is never overwritten. Files are `0600`, owned by the gateway
  user. Versioned JSON, one file per collection. File locking uses
  `rustix::fs::flock` — `rustix` is already a **transitive** dependency
  (`Cargo.lock`), so it is *promoted to a direct dependency*: a manifest change
  with zero new compile cost, not "already present." No new crate is compiled.
- **Audit backend**: reuse `TransparencyLogger` (hash-chain, append-only,
  `verify_log`) as a governance-scoped log instance, kept *separate* from the
  invocation log. `read_audit(filter)` returns entries in chain order with an
  explicit limit/offset; an invalid filter errors rather than returning all.
- In-memory impl for tests. Server-backed durable impl is demand-gated (MIK-6692).

### Acceptance criteria
- **MIK-6685.STORE.1** trait has in-memory + atomic-file impls; both pass a
  shared conformance test suite.
- **MIK-6685.STORE.2** crash-safety proven by **fault injection at each write
  phase** (fail after temp-write, after temp-fsync, after rename, after
  dir-fsync): every case leaves either the complete old file or the complete new
  file, never a partial one.
- **MIK-6685.STORE.3** cross-process concurrent writes do not lose updates — the
  `flock` + generation compare-and-swap rejects a stale writer, which must
  re-read (test uses two processes/handles, not two threads).
- **MIK-6685.STORE.4** control-plane `audit_events` view is populated from a
  governance-scoped `TransparencyLogger` (separate from the invocation log); a
  governance action appears in the view and passes `verify_log`.
- **MIK-6685.STORE.5** malformed collection JSON fails closed: load errors and a
  write never truncates the good file.
- **MIK-6685.STORE.6** `read_audit` honors chain order + limit/offset; an invalid
  filter errors. Files are `0600`.
- **MIK-6685.STORE.7** no new *compiled* crate: file locking promotes the
  already-transitive `rustix` to a direct dependency (verified by `cargo tree`
  diff showing no newly-built crate, only a manifest entry).

### Fail-fast
STORE.2 + STORE.3 first — if atomic-write is not torn-file-safe under
phase-fault injection and cross-process writes lose updates, the backend is
unshippable.

### Test plan
Trait conformance suite against both impls; phase-fault-injection torn-write test
(harness that aborts after each phase); a two-process lost-update test asserting
the stale writer is rejected; corrupt-JSON fail-closed test; audit round-trip
(append → view → `verify_log`); `cargo tree` dep-diff check. `cargo test` +
clippy + fmt.

---

## Slice C — MIK-6688: OIDC group → ControlPlaneRole mapping

### Requirements
Control-plane actors must get a real role (Admin / SecurityReviewer / Developer /
Auditor) from their verified identity, not the current hardcoded admin-bool →
Admin/Auditor projection. Reuse MIK-6648 (merged): `VerifiedIdentity.groups` +
the policy engine already match on group.

### Architecture / design
- A `role_mapping` config: ordered list of rules, first-match-wins, mirroring the
  existing `resolve_scopes` policy shape (reuse, don't invent). **Each rule is
  issuer-scoped** — a rule matches on `{ issuer + (group|email|domain) → role }`
  so a group name from a *different* identity provider cannot map into a
  privileged role (GPT-5.5 catch: cross-IdP group-name collision).
- `actor_from_client` consumes the `VerifiedIdentity` (bound into request
  extensions by MIK-6648) and resolves the role via the mapping.
- **Two distinct fallbacks, no overlap:** (1) a verified identity is present but
  no rule matches → **Auditor** (least privilege); (2) no verified identity /
  no mapping configured → unchanged legacy behavior (admin key → Admin, else
  Auditor).
- Invalid `role_mapping` config **fails closed** at startup / reload — the
  gateway refuses to start rather than silently falling back to Admin.
- Admin is grantable by mapping only via an explicit `role: admin` rule; there is
  no implicit path to Admin.

### Acceptance criteria
- **MIK-6688.ROLE.1** an issuer-scoped rule maps an OIDC group to
  `SecurityReviewer` / `Developer` / `Admin`; a verified caller from that issuer
  in that group gets that role.
- **MIK-6688.ROLE.2** verified identity present + no matching rule → Auditor
  (least privilege). First-match-wins order honored.
- **MIK-6688.ROLE.3** no verified identity / no mapping configured → unchanged
  legacy behavior (admin key → Admin, else Auditor). Backward-compatible.
- **MIK-6688.ROLE.4** the same group name from a *different* issuer does NOT
  match an issuer-scoped rule (cross-IdP collision blocked).
- **MIK-6688.ROLE.5** invalid `role_mapping` config fails closed at startup /
  reload — no silent Admin fallback.
- **MIK-6688.ROLE.6** RBAC then authorizes per mapped role (integration:
  SecurityReviewer reads evidence, cannot mutate).

### Fail-fast
ROLE.3 + ROLE.4 first — backward-compat must hold for existing single-key
deployments, and the issuer guard must block cross-IdP privilege escalation
before any role is honored.

### Test plan
Unit tests for the resolver (issuer+group/email/domain, order, no-match default,
cross-IdP rejection, invalid-config fail-closed); integration test wiring
`VerifiedIdentity` → actor → RBAC authorize; backward-compat test with no mapping.

---

## Slice D — MIK-6689: SIEM/OTel evidence export

### Requirements
Enterprises must be able to stream control-plane + invocation audit evidence to
their SIEM. Reuse the existing `TransparencyLogger` NDJSON (ADR-005) — this is a
sink adapter, not a new export subsystem.

### Architecture / design
- An export sink trait with implementations: file/stdout NDJSON (core) and an
  HTTP/OTel-log sink (enterprise). The sink tails both the invocation and the
  governance transparency logs and forwards new, **hash-verified** entries.
- **Delivery contract: at-least-once with idempotency.** Each entry's
  `entry_hash` (plus chain counter) is the idempotency key, letting the SIEM
  dedupe. The durable cursor advances **only after sink ack**; a crash re-sends
  un-acked entries instead of dropping them.
- **Bounded durable spool** decouples export from the invocation path. Entries
  are appended to the already-durable transparency log; the exporter reads via a
  cursor. Under a prolonged sink outage the exporter lags but never blocks
  invocations and never grows unbounded in memory (the on-disk log is the
  buffer; a max-lag alert fires).
- The exporter **halts and alerts** on a corrupted / tampered / failed-verify
  entry and never forwards an unverified entry. Log rotation/truncation is
  handled by tracking (file-id, offset) and re-anchoring on rotation.

### Acceptance criteria
- **MIK-6689.SIEM.1** new entries from **both** the invocation log and the
  governance log are forwarded to the sink in chain order.
- **MIK-6689.SIEM.2** at-least-once with idempotency: the durable cursor advances
  only after ack; a mid-stream restart re-sends un-acked entries, and each entry
  carries `entry_hash` as the dedupe key (test: kill after send-before-ack, entry
  is re-sent not dropped).
- **MIK-6689.SIEM.3** sink failure/backpressure never blocks or fails a tool
  invocation, and memory stays bounded (the on-disk log is the buffer); a max-lag
  metric/alert fires (test: erroring sink, invocations still succeed, no
  unbounded growth).
- **MIK-6689.SIEM.4** the exporter halts and alerts on a failed-verification
  entry and never forwards it; forwarded entries retain hash-chain fields plus a
  trusted checkpoint anchor so the SIEM side can verify contiguity.
- **MIK-6689.SIEM.5** log rotation/truncation is handled — export resumes across
  a rotation with no gap, within the at-least-once guarantee.

### Fail-fast
SIEM.3 (non-blocking and bounded) first — an audit export that can stall the
gateway, or exhaust its memory, is worse than none.

### Test plan
Cursor-advances-after-ack test (kill before ack, assert re-send); failing-sink
test asserting invocation success plus bounded memory plus a lag alert; ordering
test across both log sources; tampered-entry halt-and-alert test; log-rotation
resume test; verify forwarded entries pass `verify_log`-style chain checks
against a checkpoint.

---

## Cross-slice DoR checklist

| Gate | A (6691) | B (6685) | C (6688) | D (6689) |
|---|---|---|---|---|
| Testable AC + stable IDs | ✅ | ✅ | ✅ | ✅ |
| Architecture/interface defined | ✅ | ✅ | ✅ | ✅ |
| Fail-fast check named | ✅ | ✅ | ✅ | ✅ |
| Test plan | ✅ | ✅ | ✅ | ✅ |
| New deps named (build-cost tier) | none beyond Helm tooling | `rustix` promoted transitive→direct (0 new compile) | none | none (sink is std/http) |
| Reuse-first (ADR-006) | manifests | TransparencyLogger | MIK-6648 | TransparencyLogger |
| Mac-buildable (no Spark) | ✅ | ✅ | ✅ | ✅ |

Sequencing: A and B are independent and highest-value (deploy story + persistence
foundation). C depends on MIK-6648 (merged). D depends on B's audit wiring.
