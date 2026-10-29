// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who reads which identity grants in the control-plane snapshot. Each grant
//! names who may use which server and tool, so a caller without a role that
//! governs grants must not read other users' grants.

use super::*;
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};

/// A grant for the developer the fixture signs in as, and one for another user.
const GRANTS: [(&str, &str); 2] = [("grant-of-dev", DEV), ("grant-of-other", OTHER_DEV)];

fn grant(grant_id: &str, subject: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new("oidc", subject, None),
        agent: GrantAgent::Any,
        capability: "matrix-capability".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "local-file".to_string(),
        reason: "matrix".to_string(),
    }
}

/// The snapshot `caller` reads with both users' grants loaded.
async fn snapshot_as(caller: Caller) -> (StatusCode, String) {
    let fx = fixture(caller.gateway(), false).await;
    fx.state
        .meta_mcp
        .set_identity_grants(LocalIdentityGrantStore::from_grants(
            GRANTS.iter().map(|(id, subject)| grant(id, subject)),
        ));
    let router = create_router(Arc::clone(&fx.state));
    let cookie = session(&fx.state);
    let req = ("GET", routes::UI_CONTROL_PLANE, "plain");
    let (status, body) = send(&router, request(caller, req, &fx, Some(&cookie))).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// An unprivileged API key and a signed-in identity no role rule maps both
/// read the snapshot today; neither may read another user's grant.
#[tokio::test]
async fn an_unprivileged_caller_does_not_read_another_users_grant() {
    for caller in [Caller::StandardKey, Caller::OidcUnmapped] {
        let (status, body) = snapshot_as(caller).await;
        assert_eq!(status, StatusCode::OK, "{caller:?}: {body}");
        assert!(
            !body.contains("grant-of-other"),
            "{caller:?} reads another user's grant: {body}"
        );
    }
}

/// The control: callers whose role governs grants keep the full list.
#[tokio::test]
async fn an_admin_auditor_or_reviewer_reads_every_grant() {
    for caller in [
        Caller::AdminKey,
        Caller::OidcAdmin,
        Caller::OidcAuditor,
        Caller::OidcReviewer,
    ] {
        let (status, body) = snapshot_as(caller).await;
        assert_eq!(status, StatusCode::OK, "{caller:?}: {body}");
        for (grant_id, _) in GRANTS {
            assert!(
                body.contains(grant_id),
                "{caller:?} misses {grant_id}: {body}"
            );
        }
    }
}
