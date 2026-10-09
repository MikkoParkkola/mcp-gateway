// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8207: a personal-account token refresh follows the one `expires_in`
//! rule every token answer follows. Beside `provider_tests.rs` and on its
//! rig, which is already past the file-size ceiling.

use super::provider_tests::{GOOGLE_ISSUER, NOW, RESOURCE, account, google_rig, grant, ok};
use crate::personal_accounts::service::{ProviderRefreshError, RefreshProvider};

/// An `expires_in` above 100 years is malformed even where the sum still
/// fits: the refresh is refused, never trusted for centuries. It used to be
/// refused only when the sum overflowed.
#[tokio::test]
async fn an_expires_in_above_100_years_is_refused() {
    let at = |expires_in: u64| {
        ok(&format!(
            r#"{{"access_token":"fresh-access","token_type":"Bearer","expires_in":{expires_in}}}"#
        ))
    };
    let (_, lying) = google_rig(at(3_155_760_001), true, NOW).await;
    assert_eq!(
        lying
            .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
            .await
            .err(),
        Some(ProviderRefreshError::Unavailable)
    );
    let (_, longest) = google_rig(at(3_155_760_000), true, NOW).await;
    let kept = longest
        .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &grant())
        .await
        .expect("100 years is the bound, not past it");
    assert_eq!(kept.expires_at, NOW + 3_155_760_000);
}
