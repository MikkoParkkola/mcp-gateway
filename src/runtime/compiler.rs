//! Descriptor → substrate compiler.
//!
//! Compiles a [`SandboxDescriptor`] into a gVisor OCI bundle or an Apple
//! Virtualization.framework VM-spec.  Both compilers are pure functions —
//! the same descriptor always produces the same output.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::runtime::descriptor::SandboxDescriptor;

/// gVisor `runsc` OCI bundle.
///
/// Conforms to the OCI runtime spec structure: `ociVersion`, `process`,
/// `root`, `mounts`, `hostname`, `linux`, and `annotations`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GvisorBundle {
    /// OCI runtime spec version.
    pub oci_version: String,

    /// Process specification (args, env, cwd, capabilities).
    pub process: Value,

    /// Root filesystem specification.
    pub root: Value,

    /// Mount entries in OCI format.
    pub mounts: Vec<BTreeMap<String, Value>>,

    /// Container hostname.
    pub hostname: String,

    /// Linux-specific configuration (namespaces, resources, capabilities).
    pub linux: Value,

    /// Annotations — includes attestation, hebb-bridge, and checkpoint metadata.
    pub annotations: BTreeMap<String, Value>,
}

/// Apple Virtualization.framework VM-spec.
///
/// Maps the sandbox descriptor to the Apple containerization VM
/// configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppleVmSpec {
    /// VM / sandbox name.
    pub name: String,

    /// Memory limit in bytes.
    pub memory_bytes: u64,

    /// CPU core count.
    pub cpu_cores: u32,

    /// Boot image reference.
    pub boot_image: String,

    /// Network configuration.
    pub network: Value,

    /// Mount specifications.
    pub mounts: Vec<Value>,

    /// Environment variables.
    pub environment: BTreeMap<String, String>,

    /// Attestation requirements.
    pub attestation: Value,

    /// Hebb memory-bridge configuration.
    pub hebb_bridge: Value,

    /// Checkpoint policy.
    pub checkpoint_policy: Value,
}

/// Compile a descriptor into a gVisor OCI bundle.
pub fn gvisor_compile(descriptor: &SandboxDescriptor) -> Result<GvisorBundle> {
    let mut mounts: Vec<BTreeMap<String, Value>> = Vec::new();

    for mount in &descriptor.mounts {
        let mut m = BTreeMap::new();
        m.insert("destination".into(), Value::String(mount.destination.clone()));
        m.insert("type".into(), Value::String(mount.mount_type.clone()));
        m.insert("source".into(), Value::String(mount.source.clone()));
        let mut opts = vec![Value::String("nosuid".into())];
        if mount.read_only {
            opts.push(Value::String("ro".into()));
        }
        m.insert("options".into(), Value::Array(opts));
        mounts.push(m);
    }

    let env: Vec<Value> = descriptor
        .env
        .iter()
        .map(|(k, v)| Value::String(format!("{k}={v}")))
        .collect();

    let cap_names: Vec<Value> = descriptor
        .capabilities
        .iter()
        .map(|c| Value::String(c.name.clone()))
        .collect();

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "symphony.sandbox.name".into(),
        Value::String(descriptor.name.clone()),
    );
    annotations.insert(
        "symphony.sandbox.image".into(),
        Value::String(descriptor.image.clone()),
    );
    annotations.insert(
        "symphony.sandbox.attestation".into(),
        serde_json::to_value(&descriptor.attestation)?,
    );
    annotations.insert(
        "symphony.sandbox.hebb_bridge".into(),
        serde_json::to_value(&descriptor.hebb_bridge)?,
    );
    annotations.insert(
        "symphony.sandbox.checkpoint_policy".into(),
        serde_json::to_value(&descriptor.checkpoint_policy)?,
    );

    let process = serde_json::json!({
        "terminal": false,
        "user": { "uid": 0, "gid": 0 },
        "args": ["/bin/sh"],
        "env": env,
        "cwd": "/",
        "capabilities": {
            "bounding": cap_names.clone(),
            "effective": cap_names.clone(),
            "permitted": cap_names,
        },
    });

    let root = serde_json::json!({
        "path": "rootfs",
        "readonly": false,
    });

    let namespaces = serde_json::json!([
        { "type": "pid" },
        { "type": "ipc" },
        { "type": "uts" },
        { "type": "mount" },
        { "type": "network" },
    ]);

    let linux = serde_json::json!({
        "resources": {
            "memory": { "limit": descriptor.resources.memory_bytes },
            "cpu": { "shares": descriptor.resources.cpu_millis },
        },
        "namespaces": namespaces,
    });

    Ok(GvisorBundle {
        oci_version: "1.0.2".into(),
        process,
        root,
        mounts,
        hostname: descriptor.name.clone(),
        linux,
        annotations,
    })
}

/// Compile a descriptor into an Apple Virtualization.framework VM-spec.
pub fn apple_compile(descriptor: &SandboxDescriptor) -> Result<AppleVmSpec> {
    let cpu_cores = descriptor.resources.cpu_millis.div_ceil(1000);

    let network = match descriptor.network_egress.mode.as_str() {
        "deny" => serde_json::json!({ "type": "none" }),
        "allowlist" => serde_json::json!({
            "type": "nat",
            "allowed_destinations": descriptor.network_egress.allowed_destinations,
        }),
        _ => serde_json::json!({ "type": "nat", "mode": "unrestricted" }),
    };

    let mounts: Vec<Value> = descriptor
        .mounts
        .iter()
        .map(|m| {
            serde_json::json!({
                "source": m.source,
                "destination": m.destination,
                "read_only": m.read_only,
                "type": m.mount_type,
            })
        })
        .collect();

    let mut environment = BTreeMap::new();
    for (k, v) in &descriptor.env {
        environment.insert(k.clone(), v.clone());
    }

    Ok(AppleVmSpec {
        name: descriptor.name.clone(),
        memory_bytes: descriptor.resources.memory_bytes,
        cpu_cores,
        boot_image: descriptor.image.clone(),
        network,
        mounts,
        environment,
        attestation: serde_json::to_value(&descriptor.attestation)?,
        hebb_bridge: serde_json::to_value(&descriptor.hebb_bridge)?,
        checkpoint_policy: serde_json::to_value(&descriptor.checkpoint_policy)?,
    })
}
