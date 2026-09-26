// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 Amendment A3, backend half: under `closed`, a cold-slot fill that
//! fails on transport returns the transport error (the caller answers as a
//! failed dispatch would), and a reachable backend whose list cannot be read
//! keeps text U. The cooldown's fast-fail answers as the failure it stands in
//! for. `standard` forwards either way.

use super::*;

/// A3-T4a: a transport failure, then a cold call inside the cooldown: both
/// return the transport class, and only one list went out. New-API row (base
/// answers text U); mutants M15 (map transport to text U) and M17 (drop the
/// stamp's transport bit) redden it.
#[tokio::test(start_paused = true)]
async fn a3_t4a_a_transport_failure_and_its_cooldown_answer_as_transport() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let first = check(&backend, "edit", &undeclared()).await;
    assert!(
        matches!(first, Err(crate::Error::TransportConnect(_))),
        "{first:?}"
    );
    tokio::time::advance(Duration::from_millis(10)).await;
    let second = check(&backend, "edit", &undeclared()).await;
    assert!(
        matches!(second, Err(ref e) if crate::backend::fill_check::is_transport_failure(e)),
        "the cooldown fast-fail must answer as the transport failure: {second:?}"
    );
    assert_eq!(lister.lists(), 1, "a list went out inside the cooldown");
}

/// A3-T3 / A3-T4b: a reachable backend whose `tools/list` answers with a
/// JSON-RPC error keeps text U, and so does its cooldown fast-fail. Mutant
/// M18 (class `JsonRpc` as transport) reddens the first call; M17 the second.
#[tokio::test(start_paused = true)]
async fn a3_t4b_an_unreadable_list_and_its_cooldown_keep_text_u() {
    let lister = Lister::new(Mode::Fail);
    let backend = backend(InputSchemaEnforcement::Closed, &no_breaker(), &lister);
    let unavailable = Some(TEXT_UNAVAILABLE.to_owned());
    for _ in 0..2 {
        let answer = check(&backend, "edit", &undeclared()).await;
        assert_eq!(answer.expect("text U is a result"), unavailable);
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    assert_eq!(lister.lists(), 1);
}

/// A3-T5 (backend half): under `standard` a transport failure forwards
/// (`Ok(None)`), so the dispatch fails on its own and is charged once. Mutant:
/// dropping the `closed` condition from the A3 arm reddens it.
#[tokio::test(start_paused = true)]
async fn a3_t5_standard_forwards_a_transport_failure() {
    let lister = Lister::new(Mode::Down);
    let backend = backend(InputSchemaEnforcement::Standard, &no_breaker(), &lister);
    let answer = check(&backend, "edit", &undeclared()).await;
    assert!(matches!(answer, Ok(None)), "{answer:?}");
}
