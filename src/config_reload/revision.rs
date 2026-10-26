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
//! The loader hands over [`RawInputs`]; publishing reduces them at once to
//! [`AppliedInputs`], keyed digests of every part, and the raw bytes are
//! dropped. Only the digests outlive the publish, so a later grants change can
//! recompute the id without the process holding any input's bytes.
//!
//! Not yet covered: capability definitions (their part is an empty list until
//! the capability loader hands its bytes over), so nothing may present an id
//! as naming capability state; and CLI flag overrides applied after the load,
//! which are process arguments rather than inputs.
//!
//! Encoding (shared with configuration history, which keys stored versions by
//! this id):
//! ```text
//! key  = HKDF-SHA-256(salt: none, ikm: record key, info: TAG), 32 bytes
//! D(x) = HMAC-SHA-256(key, PART_TAG || 0x00 || x)
//! id   = "hmac-sha256:" + hex(HMAC-SHA-256(key,
//!          TAG || part(D(gateway.yaml))
//!              || (part(D(grants file)) | ABSENT)
//!              || count || part(path) || (part(D(bytes)) | ABSENT) per env file, configured order
//!              || count || part(path) || part(D(bytes)) per capability file, sorted
//!              || count || part(source) || part(name) || part(D(value)) per consumed value,
//!                          sorted, duplicates once))
//! part(b) = 0x01 || u64_be(len b) || b;  ABSENT = 0x00;  count = u64_be(n)
//! ```

use std::fmt;

/// Domain tag and HKDF info of the revision.
pub(crate) const TAG: &[u8] = b"mcp-gateway/config-revision/v1";
/// Domain tag of a part digest.
const PART_TAG: &[u8] = b"mcp-gateway/config-revision/v1/part";

/// Input bytes between the load and the publish: moved into the publish and
/// dropped there, never cloned past it. One alias, so the buffer type that
/// wipes on drop (`WipedBytes`, #4162) replaces it in one place; that switch
/// lands in this change's second part at the latest.
pub(crate) type RawBytes = Vec<u8>;

/// A keyed digest of one input part.
pub(crate) type PartDigest = [u8; 32];

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
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ConsumedInput<V> {
    pub source: ConsumedSource,
    pub name: String,
    pub value: V,
}

/// The inputs as the load read them. Short-lived: moved into
/// [`AppliedInputs::digest`] at publish.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct RawInputs {
    pub gateway_yaml: RawBytes,
    pub grants: Option<RawBytes>,
    /// Configured env files in order; `None` for one that does not exist
    /// (the loader skips it), so a missing file and an empty one differ.
    pub env_files: Vec<(String, Option<RawBytes>)>,
    pub capabilities: Vec<(String, RawBytes)>,
    pub consumed: Vec<ConsumedInput<RawBytes>>,
}

/// The inputs an applied configuration was built from, as keyed digests.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct AppliedInputs {
    pub gateway_yaml: PartDigest,
    pub grants: Option<PartDigest>,
    pub env_files: Vec<(String, Option<PartDigest>)>,
    pub capabilities: Vec<(String, PartDigest)>,
    pub consumed: Vec<ConsumedInput<PartDigest>>,
}

/// `D(x)`: the keyed digest of one part.
pub(crate) fn part_digest(key: &[u8; 32], bytes: &[u8]) -> PartDigest {
    use hmac::{KeyInit as _, Mac as _};
    // invariant: HMAC-SHA256 takes a key of any length, and this one is 32 bytes.
    let mut mac =
        crate::hashing::HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(PART_TAG);
    mac.update(&[0]);
    mac.update(bytes);
    mac.finalize().into_bytes().into()
}

impl AppliedInputs {
    /// Digest `raw` under `key`; the raw bytes are dropped here.
    pub(crate) fn digest(key: &[u8; 32], raw: RawInputs) -> Self {
        let d = |bytes: &[u8]| part_digest(key, bytes);
        // Consumed field by field: each buffer drops as soon as it is digested.
        Self {
            gateway_yaml: d(&raw.gateway_yaml),
            grants: raw.grants.map(|grants| d(&grants)),
            env_files: raw
                .env_files
                .into_iter()
                .map(|(path, bytes)| (path, bytes.map(|b| d(&b))))
                .collect(),
            capabilities: raw
                .capabilities
                .into_iter()
                .map(|(path, bytes)| (path, d(&bytes)))
                .collect(),
            consumed: raw
                .consumed
                .into_iter()
                .map(|c| ConsumedInput {
                    source: c.source,
                    name: c.name,
                    value: d(&c.value),
                })
                .collect(),
        }
    }
}

impl<V: AsRef<[u8]>> fmt::Debug for ConsumedInput<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumedInput")
            .field("source", &self.source)
            .field("name", &self.name)
            .field("value_len", &self.value.as_ref().len())
            .finish()
    }
}

impl fmt::Debug for RawInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawInputs")
            .field("gateway_yaml_len", &self.gateway_yaml.len())
            .field("grants_len", &self.grants.as_ref().map(Vec::len))
            .field("env_files", &self.env_files.len())
            .field("capabilities", &self.capabilities.len())
            .field("consumed", &self.consumed.len())
            .finish()
    }
}

impl fmt::Debug for AppliedInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppliedInputs")
            .field("grants", &self.grants.is_some())
            .field("env_files", &self.env_files.len())
            .field("capabilities", &self.capabilities.len())
            .field("consumed", &self.consumed.len())
            .finish_non_exhaustive()
    }
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
    for (path, digest) in &inputs.env_files {
        part(&mut m, path.as_bytes());
        match digest {
            Some(digest) => part(&mut m, digest),
            None => m.push(0),
        }
    }
    let mut caps: Vec<_> = inputs.capabilities.iter().collect();
    caps.sort();
    count(&mut m, caps.len());
    for (path, digest) in caps {
        part(&mut m, path.as_bytes());
        part(&mut m, digest);
    }
    let mut consumed: Vec<_> = inputs
        .consumed
        .iter()
        .map(|c| (c.source.tag(), c.name.as_str(), &c.value))
        .collect();
    consumed.sort_unstable();
    // A value resolved twice during one load is one input, not two.
    consumed.dedup();
    count(&mut m, consumed.len());
    for (source, name, digest) in consumed {
        part(&mut m, source.as_bytes());
        part(&mut m, name.as_bytes());
        part(&mut m, digest);
    }
    format!("hmac-sha256:{}", crate::hashing::hmac_sha256_hex(key, &m))
}

#[cfg(test)]
#[path = "revision_tests.rs"]
mod tests;
