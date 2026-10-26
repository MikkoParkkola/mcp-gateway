// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config revision id: which configuration decided a recorded call.
//!
//! Keyed, never a plain hash: every input can hold a secret (inline in
//! gateway.yaml, in an env file, a `file:` secret), and a published plain
//! digest would let a low-entropy one be guessed offline. The key derives from
//! the record key, so ids are stable per install and a key rotation starts
//! new ids for configurations applied after it; ids are never recomputed.
//! An identifier, not a proof: verifying an exported log never recomputes it.
//!
//! Encoding (shared with configuration history, which keys stored versions by
//! this id):
//! ```text
//! key  = HKDF-SHA-256(salt: none, ikm: record key, info: TAG), 32 bytes
//! id   = "hmac-sha256:" + hex(HMAC-SHA-256(key,
//!          TAG || part(gateway.yaml)
//!              || (part(grants file) | ABSENT)
//!              || count || (part(path) || (part(bytes) | ABSENT)) per env file, configured order
//!              || count || (part(path) || part(bytes)) per capability file, sorted by path
//!              || count || (part(source) || part(name) || part(value)) per consumed value,
//!                          sorted by (source tag, name, value)))
//! part(b) = 0x01 || u64_be(len b) || b;  ABSENT = 0x00;  count = u64_be(n)
//! ```

/// Domain tag and HKDF info of the revision.
pub(crate) const TAG: &[u8] = b"mcp-gateway/config-revision/v1";

/// Where a consumed value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsumedSource {
    /// An `MCP_GATEWAY_*` process override.
    ProcessOverride,
    /// A `${VAR}` or `env:NAME` value, from the process or a dotenv file.
    EnvVar,
    /// A `file:` secret's contents.
    SecretFile,
}

impl ConsumedSource {
    fn tag(self) -> &'static str {
        match self {
            Self::ProcessOverride => "process_override",
            Self::EnvVar => "env_var",
            Self::SecretFile => "secret_file",
        }
    }
}

/// One value the loader consumed from outside the files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsumedInput {
    pub source: ConsumedSource,
    pub name: String,
    pub value: Vec<u8>,
}

/// The exact inputs an applied configuration was built from. Held in memory
/// only; configuration history stores the files, never `consumed`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AppliedInputs {
    pub gateway_yaml: Vec<u8>,
    pub grants: Option<Vec<u8>>,
    /// Configured env files in order; `None` for one that does not exist
    /// (the loader skips it), so a missing file and an empty one differ.
    pub env_files: Vec<(String, Option<Vec<u8>>)>,
    pub capabilities: Vec<(String, Vec<u8>)>,
    pub consumed: Vec<ConsumedInput>,
}

/// The revision id of `inputs` under `key` (the derived revision key).
pub(crate) fn config_revision(key: &[u8; 32], inputs: &AppliedInputs) -> String {
    fn part(out: &mut Vec<u8>, bytes: &[u8]) {
        out.push(1);
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    fn count(out: &mut Vec<u8>, n: usize) {
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    let mut m = TAG.to_vec();
    part(&mut m, &inputs.gateway_yaml);
    match &inputs.grants {
        Some(grants) => part(&mut m, grants),
        None => m.push(0),
    }
    count(&mut m, inputs.env_files.len());
    for (path, bytes) in &inputs.env_files {
        part(&mut m, path.as_bytes());
        match bytes {
            Some(bytes) => part(&mut m, bytes),
            None => m.push(0),
        }
    }
    let mut caps: Vec<_> = inputs.capabilities.iter().collect();
    caps.sort();
    count(&mut m, caps.len());
    for (path, bytes) in caps {
        part(&mut m, path.as_bytes());
        part(&mut m, bytes);
    }
    let mut consumed: Vec<_> = inputs
        .consumed
        .iter()
        .map(|c| (c.source.tag(), c.name.as_str(), c.value.as_slice()))
        .collect();
    consumed.sort_unstable();
    count(&mut m, consumed.len());
    for (source, name, value) in consumed {
        part(&mut m, source.as_bytes());
        part(&mut m, name.as_bytes());
        part(&mut m, value);
    }
    format!("hmac-sha256:{}", crate::hashing::hmac_sha256_hex(key, &m))
}

#[cfg(test)]
#[path = "revision_tests.rs"]
mod tests;
