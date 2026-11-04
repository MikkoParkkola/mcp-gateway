// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin standing rule over every key shape (MIK-9158).

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
