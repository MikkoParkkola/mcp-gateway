// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What an applied grant reload changed, in counts.

use std::collections::BTreeSet;

use crate::identity_grants::IdentityGrant;

/// Rows added and removed by grant id, and the signed change in revoked rows.
///
/// The grants file is authoritative on reload, so a restored backup silently
/// un-revokes every grant revoked since it was taken. Deliberately given no
/// mechanism (design §4); a negative revocation count in the reload report and
/// log is the tripwire that makes a rollback visible.
pub(super) fn grant_delta(outgoing: &[IdentityGrant], incoming: &[IdentityGrant]) -> String {
    let ids = |rows: &[IdentityGrant]| {
        rows.iter()
            .map(|row| row.grant_id.as_str())
            .collect::<BTreeSet<_>>()
    };
    let revoked =
        |rows: &[IdentityGrant]| rows.iter().filter(|row| row.revoked_at.is_some()).count();
    let (before, after) = (ids(outgoing), ids(incoming));
    let (was, now) = (revoked(outgoing), revoked(incoming));
    let revoked = if now >= was {
        format!("+{}", now - was)
    } else {
        format!("-{}", was - now)
    };
    format!(
        "{} added, {} removed, revoked {revoked}",
        after.difference(&before).count(),
        before.difference(&after).count(),
    )
}
