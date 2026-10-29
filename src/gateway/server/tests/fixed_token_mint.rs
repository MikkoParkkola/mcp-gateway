// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A propagation strategy that mints a fixed, known token, for counting the
//! copies a dispatch makes of a caller's credential.
//!
//! A real strategy mints a different value each call, unknown before the
//! call, so nothing could be scanned for. This one mints the same token every
//! time through the same strategy interface, so the gateway's mint core,
//! send check and lender run unchanged around it.
//!
//! TEST ONLY. A strategy that hands every caller the same token is a
//! credential bug in any real build. This file sits under the `cfg(test)`
//! module `server/tests`, so a production build cannot compile it, and
//! [`no_fixed_token_mint_outside_tests`] fails if its name appears in any
//! source file that is not a test file.

use crate::identity_propagation::{
    BackendDescriptor, IdentityPropagation, PropagatedCredential, PropagationError,
};
use crate::key_server::oidc::VerifiedIdentity;

/// The length of a signed assertion the gateway mints, roughly.
pub(crate) const LONG: usize = 600;
/// The length of a short passthrough bearer, roughly.
pub(crate) const SHORT: usize = 40;

/// A token of `len` bytes no other code writes: a fixed prefix, then a
/// repeating pattern.
pub(crate) fn token(len: usize) -> &'static str {
    let prefix = "fixtok-7c1e9a4b-";
    assert!(len > prefix.len(), "a token longer than its prefix");
    let mut value = String::with_capacity(len);
    value.push_str(prefix);
    let pattern = b"Qz8Lm2Vx";
    let mut at = 0;
    while value.len() < len {
        value.push(char::from(pattern[at % pattern.len()]));
        at += 1;
    }
    Box::leak(value.into_boxed_str())
}

/// Mints `Authorization: Bearer <token>` for every caller and backend.
pub(crate) struct FixedTokenMint {
    pub(crate) token: &'static str,
}

#[async_trait::async_trait]
impl IdentityPropagation for FixedTokenMint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        Ok(PropagatedCredential {
            expiry_synthetic: false,
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer {}", self.token),
            )],
            expires_at: i64::MAX,
            cache_binding: format!("{}@{}", identity.subject, backend.audience),
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// The fixed-token mint exists only in test code: its type name appears in no
/// source file outside a test path.
#[test]
fn no_fixed_token_mint_outside_tests() {
    fn is_test_path(path: &std::path::Path) -> bool {
        path.components().any(|part| part.as_os_str() == "tests")
            || path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.ends_with("_tests"))
    }
    fn scan(dir: &std::path::Path, name: &str, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                scan(&path, name, hits);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && !is_test_path(&path)
                && std::fs::read_to_string(&path)
                    .expect("a source file")
                    .contains(name)
            {
                hits.push(path.display().to_string());
            }
        }
    }
    // Built at run time, so this row's own text is not a hit anywhere else.
    let name = format!("{}{}", "FixedToken", "Mint");
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    scan(&src, &name, &mut hits);
    assert!(
        hits.is_empty(),
        "the fixed-token mint is named outside test code: {hits:?}"
    );
}
