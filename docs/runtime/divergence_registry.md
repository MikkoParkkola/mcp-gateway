# Divergence Registry

**AC.4 (MIK-NEW.RUNTIME-D.4)** · RUNTIME-D Audit & CI Enforcement

## Overview

The divergence registry records structural differences between gVisor and
Apple VM compiled outputs for the same descriptor.  Each entry carries:

- **Descriptor name** — which Sandbox spec produced the divergence
- **Substrate A tag** — `gvisor` or `apple_vm`
- **Substrate B tag** — `gvisor` or `apple_vm`
- **Description** — human-readable delta description

## Known Divergences

These are structural differences that are **expected and documented**.
CI will NOT fail on these.

### 1. Mount count difference (`mount-count`)

**Cause**: gVisor compiles an additional `/proc` mount.
Apple VM-spec uses virtio-fs and doesn't require `/proc`.

**Severity**: Low — no behavioral impact.

### 2. CPU accounting (`cpu`)

**Cause**: gVisor uses CFS shares (1024 = 1 core). Apple VM-spec uses
integer vCPU count. Rounding differences may produce minor divergences.

**Severity**: Low — in practice, resources allocated are equivalent.

## CI Enforcement

The divergence registry is thread-safe and can be queried at any point:

```rust
let registry = DivergenceRegistry::new();
let compiler = Compiler::with_divergence(registry.clone());

// Compile and detect divergences
let (gvisor, apple, divergences) = compiler.compile_both(&descriptor);

// CI check: fail on undocumented divergence
if registry.has_divergence() {
    for record in registry.get_all() {
        eprintln!("DIVERGENCE: {} ({} vs {}): {}",
            record.descriptor_name,
            record.substrate_a,
            record.substrate_b,
            record.description,
        );
    }
    // CI: exit 1 on undocumented divergence
}
```

### Undocumented Divergence Policy

1. Any divergence NOT listed in "Known Divergences" above causes CI failure.
2. To document a new divergence: add it to this registry AND to the compiler's
   allowed-divergence list.
3. Divergences that reflect actual behavioral differences (not just structural)
   must be accompanied by a test demonstrating the behavior is equivalent.

## Registry CLI

```bash
# List all divergences from the last compile
cargo test --test mik_5226_acs -- ac_4 -- --nocapture

# Check divergence count
# (CI: fails if unexpected divergences found)
```

## Adding a New Divergence

1. Identify the divergence in `Compiler::detect_divergence()`
2. Add a test that exercises the divergence
3. Document it in this registry under "Known Divergences"
4. Update the compiler's allowed list if needed
