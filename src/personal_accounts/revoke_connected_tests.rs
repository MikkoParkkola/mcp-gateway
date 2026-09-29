// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2327: the account connections page reports a grant as connected only when
//! a dispatch would serve it. A grant stored under another descriptor revision
//! is refused at dispatch (#2249), so the page must not list it as connected.

use super::AccountKey;
use super::revoke_fixture::{ISSUER, RevocationEndpoint, RevokeFixture, Seed, grant};

const ACCOUNT: &str = "work";
const RESOURCE: &str = "https://api.fixture.test/";

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_from_another_descriptor_revision_is_not_connected() {
    let key = AccountKey {
        principal_authority: "openwebui-adapter:20:fixture-installation".into(),
        principal_subject: "alice".into(),
        backend_id: ACCOUNT.into(),
        resource: RESOURCE.into(),
        oauth_issuer: ISSUER.into(),
    };
    let seeded = grant("alice");
    let fixture = RevokeFixture::start(
        ACCOUNT,
        RESOURCE,
        &[(key.clone(), seeded.clone(), Seed::Connected)],
        RevocationEndpoint::Configured,
    )
    .await;
    let revocation = fixture.handles().revocation;

    assert!(
        revocation
            .connected(&key, &seeded.descriptor_revision)
            .await
            .expect("the store answers"),
        "positive control: the grant's own revision is connected"
    );
    assert!(
        !revocation
            .connected(&key, &"f".repeat(64))
            .await
            .expect("the store answers"),
        "a grant from another descriptor revision must not read as connected"
    );
}
