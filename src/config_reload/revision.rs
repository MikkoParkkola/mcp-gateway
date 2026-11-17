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
//! Capability files are a [`CapabilityPart`]. `Loaded` is the count and the
//! sorted entries, the bytes a gateway with capabilities disabled already
//! publishes, including the empty list. `NotLoaded` is `u64::MAX` and nothing
//! after it: the files have not been read. `Partial` is `u64::MAX - 1`, then
//! that same count and entries: a directory or a file could not be read. A
//! file count a process can hold sits below either marker, so the frame stays
//! v1. The load sequence is not an input. CLI flag overrides applied after
//! the load are process arguments rather than inputs.
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
//!              || capability part:
//!                   Loaded:    count || part(path) || part(D(bytes)) per file, sorted
//!                   NotLoaded: u64_be(u64::MAX)
//!                   Partial:   u64_be(u64::MAX - 1) || count || entries, as Loaded
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

/// How much of the capability catalogue this revision names.
///
/// `T` is [`RawBytes`] on the way in and [`PartDigest`] once published.
/// `Loaded` is today's list. The other two variants exist so a startup that
/// has not read the files, and a read that missed a directory or a file, are
/// not the same value as an empty catalogue. `Default` is the empty loaded
/// list: an in-memory config and a derived `AppliedInputs` stay what they
/// were when the list was a `Vec`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum CapabilityPart<T> {
    /// The files have not been read.
    NotLoaded,
    /// Some configured directory or file could not be read. The vec is what
    /// was read.
    Partial(Vec<(String, T)>),
    /// Every configured directory was read. The vec is every served file.
    Loaded(Vec<(String, T)>),
}

impl<T> Default for CapabilityPart<T> {
    fn default() -> Self {
        Self::Loaded(Vec::new())
    }
}

impl<T> CapabilityPart<T> {
    /// The entries a loaded or partial part carries. `NotLoaded` has none.
    pub(crate) fn entries(&self) -> &[(String, T)] {
        match self {
            Self::NotLoaded => &[],
            Self::Partial(entries) | Self::Loaded(entries) => entries,
        }
    }
}

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
    pub capabilities: CapabilityPart<RawBytes>,
    pub consumed: Vec<ConsumedInput<RawBytes>>,
}

/// The inputs an applied configuration was built from, as keyed digests.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct AppliedInputs {
    pub gateway_yaml: PartDigest,
    pub grants: Option<PartDigest>,
    pub env_files: Vec<(String, Option<PartDigest>)>,
    pub capabilities: CapabilityPart<PartDigest>,
    /// Load sequence of [`Self::capabilities`]. Not an input: [`config_revision`]
    /// does not write it. A reload copies it with the part, so a gateway.yaml
    /// reload does not look like sequence zero.
    pub capability_seq: u64,
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
        let digest_entries = |entries: Vec<(String, RawBytes)>| {
            entries
                .into_iter()
                .map(|(path, bytes)| (path, part_digest(key, &bytes)))
                .collect()
        };
        // Consumed field by field: each buffer drops as soon as it is digested.
        Self {
            gateway_yaml: d(&raw.gateway_yaml),
            grants: raw.grants.map(|grants| d(&grants)),
            env_files: raw
                .env_files
                .into_iter()
                .map(|(path, bytes)| (path, bytes.map(|b| d(&b))))
                .collect(),
            capabilities: match raw.capabilities {
                CapabilityPart::NotLoaded => CapabilityPart::NotLoaded,
                CapabilityPart::Partial(entries) => {
                    CapabilityPart::Partial(digest_entries(entries))
                }
                CapabilityPart::Loaded(entries) => CapabilityPart::Loaded(digest_entries(entries)),
            },
            // The sequence is published state, not bytes the load read.
            capability_seq: 0,
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
            .field("capabilities", &self.capabilities.entries().len())
            .field("consumed", &self.consumed.len())
            .finish()
    }
}

impl fmt::Debug for AppliedInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppliedInputs")
            .field("grants", &self.grants.is_some())
            .field("env_files", &self.env_files.len())
            .field("capabilities", &self.capabilities.entries().len())
            .field("consumed", &self.consumed.len())
            .finish_non_exhaustive()
    }
}

fn push_part(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(1);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_count(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_be_bytes());
}

/// The count and the sorted entries `Loaded` and `Partial` share.
fn write_capability_entries(out: &mut Vec<u8>, entries: &[(String, PartDigest)]) {
    let mut caps: Vec<_> = entries.iter().collect();
    caps.sort();
    push_count(out, caps.len() as u64);
    for (path, digest) in caps {
        push_part(out, path.as_bytes());
        push_part(out, digest);
    }
}

/// The capability section of the preimage.
///
/// A count of zero is the empty loaded list. `NotLoaded` is `u64::MAX`, which
/// that count cannot be, or a gateway that has not read the files would
/// publish the same id as one with an empty catalogue. `Partial` is
/// `u64::MAX - 1` and then the same count and entries as `Loaded`. The load
/// sequence is not written: it is not an input.
fn write_capability_part(out: &mut Vec<u8>, part: &CapabilityPart<PartDigest>) {
    match part {
        CapabilityPart::NotLoaded => push_count(out, u64::MAX),
        CapabilityPart::Partial(entries) => {
            push_count(out, u64::MAX - 1);
            write_capability_entries(out, entries);
        }
        CapabilityPart::Loaded(entries) => write_capability_entries(out, entries),
    }
}

/// The capability section alone, so a test can compare it to bytes it built.
#[cfg(test)]
pub(crate) fn capability_preimage(part: &CapabilityPart<PartDigest>) -> Vec<u8> {
    let mut out = Vec::new();
    write_capability_part(&mut out, part);
    out
}

/// The revision id of `inputs` under `key` (the derived revision key).
pub(crate) fn config_revision(key: &[u8; 32], inputs: &AppliedInputs) -> String {
    let mut m = TAG.to_vec();
    push_part(&mut m, &inputs.gateway_yaml);
    match &inputs.grants {
        Some(grants) => push_part(&mut m, grants),
        None => m.push(0),
    }
    push_count(&mut m, inputs.env_files.len() as u64);
    for (path, digest) in &inputs.env_files {
        push_part(&mut m, path.as_bytes());
        match digest {
            Some(digest) => push_part(&mut m, digest),
            None => m.push(0),
        }
    }
    write_capability_part(&mut m, &inputs.capabilities);
    let mut consumed: Vec<_> = inputs
        .consumed
        .iter()
        .map(|c| (c.source.tag(), c.name.as_str(), &c.value))
        .collect();
    consumed.sort_unstable();
    // A value resolved twice during one load is one input, not two.
    consumed.dedup();
    push_count(&mut m, consumed.len() as u64);
    for (source, name, digest) in consumed {
        push_part(&mut m, source.as_bytes());
        push_part(&mut m, name.as_bytes());
        push_part(&mut m, digest);
    }
    format!("hmac-sha256:{}", crate::hashing::hmac_sha256_hex(key, &m))
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "revision_tests.rs"]
mod tests;

#[cfg(tp3)]
#[cfg(test)]
#[path = "revision_encoding_tests.rs"]
mod encoding_tests;
