# Divergence Registry

**Ticket:** MIK-5226 (RUNTIME-D)

## Overview

When the same Sandbox Descriptor is compiled to two different substrates,
behavioral deltas are expected for substrate-specific fields. The divergence
registry tracks **known, accepted** divergences so CI can fail on any
**undocumented** divergence.

## Detection Mechanism

`detect_divergence()` compiles the descriptor on both substrates and compares:

| Field              | Divergence Key        | Notes                                  |
|--------------------|-----------------------|----------------------------------------|
| Hostname vs Name   | `hostname_vs_name`    | OCI `hostname` vs Apple `name`         |
| Memory Limit       | `memory_limit`        | Should always match                    |
| OCI Version        | `oci_version`         | gVisor has `1.0.2`; Apple has N/A      |
| Environment        | `environment`         | Same env vars, different encoding      |
| Capabilities       | `capabilities`        | gVisor has Linux caps; Apple does not  |

## Known Divergences (Documented)

These are expected, accepted divergences between substrates:

| Key              | gVisor Value             | Apple Value               | Justification                      |
|------------------|--------------------------|---------------------------|------------------------------------|
| `oci_version`    | `1.0.2`                  | `N/A (Apple VM)`         | Apple uses VM-spec, not OCI        |
| `capabilities`   | Linux capabilities list  | `[]` (empty)             | Apple VM has no Linux cap concept  |

## CI Enforcement

Any divergence **not** in the documented set above causes the test suite to
fail. To add a new accepted divergence:

1. Add the divergence key to the `DivergenceRegistry` via `.document(key)`.
2. Update this table with the key, values, and justification.

## Audit Trail

Every divergence — documented or not — is recorded in the `AuditTrail` with:

- `substrate_id` tags for both substrates
- Field name
- Values from each substrate
- Timestamp (ms since epoch)
