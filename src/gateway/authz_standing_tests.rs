// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin standing rule over every key shape.

use super::{AdminStanding, admin_standing};

fn list(backends: &[&str]) -> Vec<String> {
    backends.iter().map(|b| (*b).to_string()).collect()
}

#[test]
fn only_an_admin_scoped_to_every_backend_stands_gateway_wide() {
    let cells = [
        ("admin, *", true, list(&["*"]), AdminStanding::Gateway),
        (
            "admin, [alpha, *]",
            true,
            list(&["alpha", "*"]),
            AdminStanding::Gateway,
        ),
        ("admin, []", true, list(&[]), AdminStanding::Gateway),
        (
            "admin, [alpha]",
            true,
            list(&["alpha"]),
            AdminStanding::InScope,
        ),
        (
            "admin, [alpha, beta]",
            true,
            list(&["alpha", "beta"]),
            AdminStanding::InScope,
        ),
        ("standard, *", false, list(&["*"]), AdminStanding::None),
        ("standard, []", false, list(&[]), AdminStanding::None),
        (
            "standard, [alpha]",
            false,
            list(&["alpha"]),
            AdminStanding::None,
        ),
    ];
    let wrong: Vec<String> = cells
        .iter()
        .filter_map(|(who, admin, backends, want)| {
            let got = admin_standing(*admin, backends);
            (got != *want).then(|| format!("{who}: got {got:?}, want {want:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The rank a re-judged task compares: a step down is `fresh < captured`.
#[test]
fn the_standings_rank_gateway_over_in_scope_over_none() {
    assert!(AdminStanding::Gateway > AdminStanding::InScope);
    assert!(AdminStanding::InScope > AdminStanding::None);
}

/// `CallerStanding::admin_standing` inverts `CallerStanding::of`
/// for both variants. The conversion is lossy one way only: `of` folds an
/// in-scope admin into `Standard`, so `InScope` comes back as `None`.
#[test]
fn caller_standing_round_trips_through_admin_standing() {
    use crate::gateway::router::CallerStanding;
    for standing in [CallerStanding::Admin, CallerStanding::Standard] {
        assert_eq!(
            CallerStanding::of(standing.admin_standing()),
            standing,
            "{standing:?} round trip"
        );
    }
    assert_eq!(
        CallerStanding::Admin.admin_standing(),
        AdminStanding::Gateway
    );
    assert_eq!(
        CallerStanding::Standard.admin_standing(),
        AdminStanding::None
    );
    assert_eq!(
        CallerStanding::of(AdminStanding::InScope).admin_standing(),
        AdminStanding::None,
        "the documented loss"
    );
}

/// The one optional-client predicate holds only for an admin
/// scoped to every backend; an absent client, an in-scope admin and a
/// standard key are not gateway admins.
#[test]
fn only_a_gateway_wide_admin_is_a_gateway_admin() {
    use crate::gateway::auth::{AuthenticatedClient, is_gateway_admin};
    let client = |admin: bool, backends: &[&str]| AuthenticatedClient {
        admin,
        backends: list(backends),
        authenticated: true,
        // Empty, as no secret was presented: the predicate reads the standing only.
        principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
        ..crate::gateway::auth::anonymous_client()
    };
    assert!(!is_gateway_admin(None), "no client");
    let cells = [
        (
            "admin, *",
            client(true, &["*"]),
            AdminStanding::Gateway,
            true,
        ),
        ("admin, []", client(true, &[]), AdminStanding::Gateway, true),
        (
            "admin, [alpha]",
            client(true, &["alpha"]),
            AdminStanding::InScope,
            false,
        ),
        (
            "standard, *",
            client(false, &["*"]),
            AdminStanding::None,
            false,
        ),
    ];
    let wrong: Vec<String> = cells
        .iter()
        .filter_map(|(who, c, standing, want)| {
            // The fixture's standing first, so a fixture drift fails here
            // rather than passing for the wrong reason.
            let got = (c.admin_standing(), is_gateway_admin(Some(c)));
            (got != (*standing, *want))
                .then(|| format!("{who}: got {got:?}, want {:?}", (standing, want)))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
