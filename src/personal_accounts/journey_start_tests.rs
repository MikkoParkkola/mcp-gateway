// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195 W6: custody's journey `start` when the provider cannot build the
//! authorize URL. The journey names an account custody's provider does not
//! manage, so the URL fails after the arm; that is a descriptor fault, never a
//! refusal the user could act on and never a URL.

use super::revoke_fixture::{ISSUER, RevocationEndpoint, RevokeFixture, descriptor};
use super::{AccountError, AccountKey, JourneyError, JourneyLimits, JourneyStatus};

const RESOURCE: &str = "https://api.fixture.test/";

fn limits() -> JourneyLimits {
    JourneyLimits {
        journeys_total: 1024,
        journeys_per_user: 8,
        starts_per_minute_per_user: 10,
        journeys_created_per_minute: 120,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_url_the_provider_cannot_build_is_a_configuration_fault() {
    let fixture =
        RevokeFixture::start_journeys(&["work"], RESOURCE, RevocationEndpoint::Configured).await;
    let journeys = fixture.handles().journeys;
    let owner = AccountKey {
        principal_authority: "openwebui-adapter:20:fixture-installation".into(),
        principal_subject: "alice".into(),
        backend_id: "unmanaged".into(),
        resource: RESOURCE.into(),
        oauth_issuer: ISSUER.into(),
    };
    let created = journeys
        .create(
            limits(),
            owner.clone(),
            descriptor(RESOURCE, RevocationEndpoint::Configured),
            "/".into(),
        )
        .await
        .expect("custody admits")
        .expect("the journey table accepts the owner");

    let id = created.journey_id;
    let principal = (
        owner.principal_authority.clone(),
        owner.principal_subject.clone(),
    );

    let started = journeys
        .start(limits(), id.clone(), owner)
        .await
        .expect("custody admits");
    assert!(
        matches!(
            started,
            Err(JourneyError::Storage(AccountError::InvalidConfiguration))
        ),
        "an unbuildable authorize URL is a configuration fault, got {:?}",
        started.map(|s| s.max_age)
    );
    // The fault is the URL's, after the arm: the journey did reach Started.
    let view = journeys
        .status(limits(), id, principal)
        .await
        .expect("custody admits")
        .expect("the owner reads its own journey");
    assert_eq!(view.status, JourneyStatus::Started);
}
