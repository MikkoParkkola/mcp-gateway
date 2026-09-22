// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 §7.3 — the first producer of a `descriptor_revision`.
//!
//! WHAT THIS VALUE DOES AND DOES NOT BUY. Nothing in the tree compares a live
//! descriptor's fingerprint against a stored `descriptor_revision`: every
//! occurrence is a field copy, a format validator, or a comparison of two
//! values that both came from stored records (§7.3, O7 / MIK-7524). So this
//! produces a value that VALIDATES (`storage.rs:135` demands 64 lowercase hex)
//! and is ready for a fence when one is built. It detects no descriptor change
//! today, and this module does not claim otherwise.
//!
//! THE FIELD SET IS WHAT THE KEY CANNOT SEE. `AccountKey` already carries
//! `resource` and `oauth_issuer`, so a change to either moves the key and the
//! old record is simply never found — hashing them here would duplicate the
//! key and add nothing. What the key is blind to is every OTHER declared field,
//! and the security-critical one is `scopes`: widening it leaves a narrower
//! token in place while the configuration asserts the new set.
//!
//! COUPLING, AND IT IS LOUD. Whatever MIK-6745/6746's consent journey computes
//! must be THIS function, not a reimplementation. A different value makes
//! `commit.rs:433` reject every migrated grant whose caller captured the other
//! one, and every migrated user is asked to reconnect — the outcome the row
//! exists to prevent.

use sha2::{Digest as _, Sha256};

use super::super::AccountError;
use super::super::config::{AccountDescriptor, DescriptorMode};
use super::encode_fields;

/// Domain tag, distinct from the account-key tag so the two hashes can never
/// collide even over identical field bytes.
const DOMAIN: &[u8] = b"mcp-gateway/descriptor-revision/v1";

/// Fingerprint the declared fields an `AccountKey` cannot discriminate.
///
/// `client_secret_ref` is hashed as the REFERENCE it is (`env:VARIABLE`), never
/// resolved: `config.rs:272-274` keeps it a reference precisely so no secret is
/// materialised into a serialized or `Debug`-rendered configuration, and
/// hashing a resolved value would undo that.
#[cfg_attr(
    all(not(test), not(kani)),
    expect(dead_code, reason = "MIK-6744.STORE.1 entry point not yet landed")
)]
pub(super) fn descriptor_revision(descriptor: &AccountDescriptor) -> Result<String, AccountError> {
    // `Option` fields encode as a presence marker plus the value, so "declared
    // empty" and "not declared" are different bytes. A bare `unwrap_or("")`
    // would collide them, and for `send_resource_parameter` the two genuinely
    // differ in what gets sent.
    let mode = match descriptor.mode {
        DescriptorMode::PersonalManaged => "personal_managed",
        DescriptorMode::Shared => "shared",
        DescriptorMode::External => "external",
    };
    // Sorted and deduped, because scope ORDER is not semantic: the same grant
    // declared in another order is the same grant, and a fingerprint that moved
    // on reordering would ask every user to reconnect over a cosmetic config
    // edit. This is also the order §7.2a(b) puts scopes into the record, so the
    // two agree by construction.
    let scopes = descriptor
        .scopes
        .as_ref()
        .map(|scopes| {
            let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            sorted.dedup();
            sorted.join(" ")
        })
        .unwrap_or_default();
    let send_resource = match descriptor.send_resource_parameter {
        Some(true) => "true",
        Some(false) => "false",
        None => "",
    };
    let external = descriptor
        .external_strategy
        .as_ref()
        .map(|strategy| format!("{strategy:?}"))
        .unwrap_or_default();
    let fields = [
        // Excluded on purpose: `resource` and `issuer`. Both are in the key.
        descriptor.provider.as_str(),
        mode,
        scopes.as_str(),
        opt(descriptor.client_id.as_deref()),
        opt(descriptor.client_secret_ref.as_deref()),
        opt(descriptor.token_endpoint.as_deref()),
        opt(descriptor.authorization_endpoint.as_deref()),
        opt(descriptor.revocation_endpoint.as_deref()),
        opt(descriptor.redirect_uri.as_deref()),
        send_resource,
        external.as_str(),
    ];
    let encoded = encode_fields(DOMAIN, &fields)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

/// A declared-but-absent field is the empty string; `encode_fields` prefixes
/// every field with its length, so an absent field and an empty one are the
/// same bytes here. That is acceptable for every field above EXCEPT
/// `send_resource_parameter`, which is why that one is rendered as a tri-state
/// rather than through this helper.
fn opt(value: Option<&str>) -> &str {
    value.unwrap_or("")
}

#[cfg(test)]
#[path = "migration_revision_tests.rs"]
mod migration_revision_tests;
