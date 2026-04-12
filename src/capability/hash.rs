//! Capability file SHA-256 hash pinning.
//!
//! ## Why
//!
//! Invariant Labs' "Tool Poisoning Attacks" writeup describes rug-pull attacks
//! where an MCP server changes its tool descriptions after user approval. The
//! same threat applies to locally-loaded capability YAMLs: a file approved on
//! Monday might be silently rewritten on Tuesday, for example by a dependency
//! update or a compromised sync tool.
//!
//! Pinning defuses this by embedding an expected SHA-256 hash inside the YAML
//! itself. On every load (and on every hot-reload / file-watch event) the
//! loader recomputes the hash and refuses to accept a mismatched file.
//!
//! ## Anchoring strategy
//!
//! The hash is computed over the **raw file contents with the `sha256:` line
//! removed**. This is a deliberate choice:
//!
//! - **Full file** binds every byte a human sees, including comments and
//!   provider order — the exact thing a rug-pull would mutate.
//! - **Canonical YAML** would ignore comments and reordering, which is
//!   exactly the kind of silent drift we need to detect.
//! - **Just the tools section** would miss poisoned auth or endpoint changes.
//!
//! Stripping the `sha256:` line (rather than replacing it with `sha256: null`)
//! means the hash is stable when rewritten with `mcp-gateway cap pin` and can
//! be reproduced from a shell with:
//!
//! ```bash
//! grep -v '^sha256:' capability.yaml | sha256sum
//! ```

use sha2::{Digest, Sha256};

/// Strip the top-level `sha256:` line from a YAML document.
///
/// Only lines that begin at column 0 with `sha256:` are removed — a nested
/// `sha256:` field inside a provider block is left untouched.
#[must_use]
pub fn strip_sha256_line(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.split_inclusive('\n') {
        // Only strip top-level `sha256:` — anything indented is a nested
        // field (e.g. some future provider key) and must stay in the hash.
        if line.starts_with("sha256:") {
            continue;
        }
        out.push_str(line);
    }
    out
}

/// Compute the canonical capability hash over the raw file contents,
/// excluding the top-level `sha256:` field.
///
/// Returns a lowercase hex-encoded SHA-256 digest.
#[must_use]
pub fn compute_capability_hash(file_content: &str) -> String {
    let stripped = strip_sha256_line(file_content);
    let digest = Sha256::digest(stripped.as_bytes());
    hex::encode(digest)
}

/// Rewrite a capability YAML so that it begins with a `sha256:` pin line.
///
/// If the file already contains a top-level `sha256:` line it is replaced.
/// The returned string is suitable for writing back in place.
#[must_use]
pub fn rewrite_with_pin(original: &str, hash: &str) -> String {
    let stripped = strip_sha256_line(original);
    let mut out = String::with_capacity(stripped.len() + hash.len() + 16);
    out.push_str("sha256: ");
    out.push_str(hash);
    out.push('\n');
    out.push_str(&stripped);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_top_level_sha256_only() {
        let input = "sha256: abc123\nname: foo\nproviders:\n  primary:\n    sha256: nested\n";
        let stripped = strip_sha256_line(input);
        assert_eq!(
            stripped,
            "name: foo\nproviders:\n  primary:\n    sha256: nested\n"
        );
    }

    #[test]
    fn strip_on_unpinned_file_is_identity() {
        let input = "name: foo\ndescription: bar\n";
        assert_eq!(strip_sha256_line(input), input);
    }

    #[test]
    fn hash_is_stable_across_pinning_cycle() {
        // Hash of an unpinned file...
        let unpinned = "name: foo\ndescription: bar\nproviders:\n  primary:\n    service: rest\n";
        let h1 = compute_capability_hash(unpinned);

        // ...must equal the hash of the same file after `cap pin` rewrote it.
        let pinned = rewrite_with_pin(unpinned, &h1);
        let h2 = compute_capability_hash(&pinned);
        assert_eq!(h1, h2, "hash must be stable across pin rewrite");
    }

    #[test]
    fn hash_excludes_sha256_field_itself() {
        // Two files with different sha256 pins but identical content below
        // must hash to the same value.
        let a = "sha256: aaaaaa\nname: foo\n";
        let b = "sha256: bbbbbb\nname: foo\n";
        assert_eq!(compute_capability_hash(a), compute_capability_hash(b));
    }

    #[test]
    fn hash_detects_body_change() {
        let original = "name: foo\ndescription: original\n";
        let tampered = "name: foo\ndescription: poisoned\n";
        assert_ne!(
            compute_capability_hash(original),
            compute_capability_hash(tampered)
        );
    }

    #[test]
    fn rewrite_with_pin_produces_leading_sha_line() {
        let body = "name: foo\n";
        let pinned = rewrite_with_pin(body, "deadbeef");
        assert!(pinned.starts_with("sha256: deadbeef\n"));
        assert!(pinned.contains("name: foo\n"));
    }

    #[test]
    fn rewrite_replaces_existing_pin() {
        let already_pinned = "sha256: old\nname: foo\n";
        let pinned = rewrite_with_pin(already_pinned, "new");
        assert!(pinned.starts_with("sha256: new\n"));
        assert!(!pinned.contains("sha256: old"));
    }

    #[test]
    fn rewrite_is_idempotent() {
        let body = "name: foo\ndescription: bar\n";
        let hash = compute_capability_hash(body);
        let once = rewrite_with_pin(body, &hash);
        let twice = rewrite_with_pin(&once, &hash);
        assert_eq!(once, twice);
    }
}
