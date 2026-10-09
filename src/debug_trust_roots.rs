// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A test CA the gateway trusts on every platform, in debug builds only
//! (MIK-8188).
//!
//! Integration tests run the gateway binary as a child and make it trust a
//! temporary CA. `SSL_CERT_FILE` does that on Linux, where the platform
//! verifier reads it; macOS asks its keychain instead. So a debug build also
//! reads `MCP_GATEWAY_TEST_TRUST_CA`, a PEM file whose certificates it adds as
//! extra roots beside the platform's. It replaces none.
//!
//! A release build compiles none of this: no read and no variable name. CI
//! greps release binaries for the name (release.yml on each shipped artifact,
//! docker.yml on a pull request), as for
//! `MCP_GATEWAY_TEST_CLOCK`. Forcing debug assertions on in a release build
//! brings the hook back; whoever does that already controls the binary, and
//! a Linux release honours `SSL_CERT_FILE` from the same environment anyway
//! (design-8188 section 8, seat ruling kimi-20261009T080254Z-92689).

/// The variable naming the PEM file of extra test roots. The grep in
/// release.yml and docker.yml spells it out; keep the three in step.
#[cfg(debug_assertions)]
const VAR: &str = "MCP_GATEWAY_TEST_TRUST_CA";

/// `builder`, plus the test roots `MCP_GATEWAY_TEST_TRUST_CA` names, in a
/// debug build when the variable is set; `builder` unchanged otherwise.
///
/// # Panics
/// In a debug build, when the variable names a file that cannot be read or
/// holds no certificate: a test that set it must fail at once, never run
/// against the platform roots alone.
pub(crate) fn extra_roots(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    #[cfg(debug_assertions)]
    {
        let path = std::env::var_os(VAR);
        with_roots_from(builder, path.as_deref().map(std::path::Path::new))
    }
    #[cfg(not(debug_assertions))]
    {
        builder
    }
}

/// [`extra_roots`] with the variable's value passed in, so a test needs no
/// process environment.
#[cfg(debug_assertions)]
fn with_roots_from(
    mut builder: reqwest::ClientBuilder,
    path: Option<&std::path::Path>,
) -> reqwest::ClientBuilder {
    let Some(path) = path else {
        return builder;
    };
    tracing::warn!(
        variable = VAR,
        file = %path.display(),
        "test-only trust roots in use; never set this outside tests"
    );
    let pem = std::fs::read(path)
        .unwrap_or_else(|error| panic!("{VAR}: cannot read {}: {error}", path.display()));
    let roots = reqwest::Certificate::from_pem_bundle(&pem)
        .unwrap_or_else(|error| panic!("{VAR}: {} is not PEM: {error}", path.display()));
    assert!(
        !roots.is_empty(),
        "{VAR}: {} holds no certificate",
        path.display()
    );
    for root in roots {
        builder = builder.add_root_certificate(root);
    }
    builder
}

#[cfg(test)]
#[path = "debug_trust_roots_tests.rs"]
mod tests;
