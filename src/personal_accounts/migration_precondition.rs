// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 §5.3a and §7.1/§7.1b — the preconditions a backend must
//! satisfy before any of its credential material is touched.
//!
//! Both checks answer the same question in different currencies: will the grant
//! this migration writes actually WORK afterwards? A migration that commits a
//! grant which cannot refresh produces an account that looks connected and is
//! not, and the user is never prompted to re-authenticate because nothing
//! thinks anything is wrong. That is the failure §7.2a already refuses two
//! other routes into.

use url::Url;

use super::super::config::AccountDescriptor;

/// Why a declared backend fails its preconditions.
///
/// Secret-free: issuers, endpoints and client ids are configuration, not
/// credentials, and none of the credential material is in scope here at all —
/// these run before the record is read.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(in crate::personal_accounts) enum PreconditionRefusal {
    /// §5.3a requirement 3. The attested legacy issuer is not the destination's.
    ///
    /// The correct outcome is re-authentication, not migration: the credential
    /// genuinely belongs to a different authorization server, and no
    /// attestation makes it portable. `provider.rs` enforces the same rule at
    /// refresh time, so migrating across issuers would only produce a grant
    /// that is refused on first use.
    #[error(
        "the attested 3.x issuer {attested} is not this descriptor's issuer {destination}; \
         a credential from another authorization server must be re-authorized, not migrated"
    )]
    IssuerMoved {
        attested: String,
        destination: String,
    },
    /// §5.3a requirement 2. The record's own endpoint contradicts the attestation.
    ///
    /// This is evidence the RECORD supplies, and it costs one comparison. A 3.x
    /// record may carry the token endpoint its credential was actually issued
    /// against, and if that endpoint's origin is not the attested issuer's, the
    /// attestation is wrong about this file.
    #[error(
        "the 3.x record's token endpoint origin {found} contradicts the attested issuer \
         origin {attested}"
    )]
    IssuerContradicted { attested: String, found: String },
    /// The record's `token_endpoint` is not a URL at all.
    ///
    /// Refused rather than ignored: treating an unreadable field as "nothing to
    /// contradict" turns a corrupt record into a silent pass. The value itself
    /// is NOT carried -- the field is a plain `String` in a hand-editable file,
    /// so it may hold anything, including a credential.
    #[error(
        "the 3.x record's token endpoint is not a readable URL, so it cannot be \
         checked against the attested issuer origin {attested}; its value is not \
         shown because that field may hold anything"
    )]
    IssuerUnreadable { attested: String },
    /// §7.1b. The destination cannot refresh what would be migrated into it.
    ///
    /// The refresh provider reads `descriptor.client_id`, never the record's,
    /// so recovering the record's id gives a complete `GrantRecord` and nothing
    /// more. Without a client id on the descriptor the first refresh is refused
    /// as `Unavailable`.
    #[error("this descriptor declares no client_id, so a migrated grant could never refresh")]
    DescriptorCannotRefresh,
    /// §7.1b. The descriptor is registered as a different client.
    ///
    /// Tokens minted for one registered application are not redeemable by
    /// another, so a mismatch is a re-authorization, not a migration.
    #[error("the 3.x record's client_id does not match this descriptor's registered client")]
    ClientIdMismatch,
}

/// §5.3a — the attested issuer must equal the destination's and must not be
/// contradicted by the record.
///
/// `recorded_endpoint` is the 3.x record's `token_endpoint`, which is a genuine
/// 3.x field rather than one 4.0.0 added, so a real record may carry it. When
/// it is absent there is nothing to contradict and the equality check stands
/// alone.
pub(super) fn check_issuer(
    attested: &str,
    destination_issuer: &str,
    recorded_endpoint: Option<&str>,
) -> Result<(), PreconditionRefusal> {
    if attested != destination_issuer {
        return Err(PreconditionRefusal::IssuerMoved {
            attested: attested.to_owned(),
            destination: destination_issuer.to_owned(),
        });
    }
    let Some(endpoint) = recorded_endpoint else {
        return Ok(());
    };
    // Origin, not exact equality: a provider may host its token endpoint at a
    // different path, and some at a different subdomain — the conservative
    // default per O5 is to refuse an origin mismatch and let a rename be made
    // explicit, rather than to accept any endpoint the file happens to name.
    // NEVER echo the raw field. A 3.x record is hand-editable and this value is
    // whatever is in it: a credential accidentally pasted into `token_endpoint`
    // would otherwise reach stderr and any `Debug` rendering. The same class the
    // position-only parse wrapper exists for, in a field that wrapper does not
    // cover -- an unparseable endpoint gets past serde because the field is a
    // plain `String`.
    let (Some(found), Some(want)) = (origin(endpoint), origin(attested)) else {
        return Err(PreconditionRefusal::IssuerUnreadable {
            attested: attested.to_owned(),
        });
    };
    if found != want {
        return Err(PreconditionRefusal::IssuerContradicted {
            attested: want,
            found,
        });
    }
    Ok(())
}

/// Scheme, host and port — the comparable part of a URL.
fn origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

/// §7.1 step 2 and §7.1b — recover the client id, and refuse a destination that
/// could not use what is recovered.
///
/// Precedence is operator config first, and that ordering is not cosmetic:
/// `restore_persisted_client_id` is a no-op once a configured id is set, and
/// `drop_credentials_from_other_issuer` deliberately keeps a configured id
/// across an issuer change because it belongs to the operator rather than to an
/// issuer. So an install that used Dynamic Client Registration in 3.x and was
/// later given an operator client id legitimately holds both, and they
/// legitimately differ. A blanket refusal on disagreement would refuse that
/// install and force the re-authentication this row exists to avoid.
pub(super) fn recover_client_id(
    descriptor: &AccountDescriptor,
    registered: Option<&str>,
    recorded: Option<&str>,
) -> Result<String, PreconditionRefusal> {
    // The destination must be able to refresh, whatever is recovered: the
    // provider reads THIS field and refuses without it.
    let Some(configured) = descriptor.client_id.as_deref() else {
        return Err(PreconditionRefusal::DescriptorCannotRefresh);
    };
    // Operator config wins. A disagreement with either disk source is reported
    // by the caller, not refused here.
    for source in [registered, recorded].into_iter().flatten() {
        if source != configured {
            // Only a mismatch against the RECORD's own id is fatal: that id
            // names the client the token was actually minted for, and another
            // client cannot redeem it.
            if Some(source) == recorded {
                return Err(PreconditionRefusal::ClientIdMismatch);
            }
        }
    }
    Ok(configured.to_owned())
}

#[cfg(test)]
#[path = "migration_precondition_tests.rs"]
mod migration_precondition_tests;
