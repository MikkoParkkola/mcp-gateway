// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Origin decisions made outside the error-count rows: each pins one
//! variant's answer so a later reclassification fails here.

use super::Error;
use crate::protocol::Origin;

/// A merge-time decision: `AmbiguousBackend` arrived with the dispatch
/// name-clash refusal after the exhaustive `Error::origin` match, and it is
/// the gateway's own refusal (built only by the gateway, sharing
/// `BackendNotFound`'s code), so it counts as the gateway's, as that does.
#[test]
fn an_ambiguous_backend_refusal_is_the_gateways_own() {
    let ambiguous = Error::AmbiguousBackend {
        server: "shared".to_owned(),
        rule: None,
    };
    assert_eq!(ambiguous.origin(), Origin::Gateway);
    assert_eq!(
        ambiguous.origin(),
        Error::BackendNotFound("shared".to_owned()).origin(),
        "classified as a missing backend is"
    );
}
