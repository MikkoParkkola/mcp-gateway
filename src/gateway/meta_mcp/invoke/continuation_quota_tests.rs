// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659 (operator decision 2026-10-22): an anonymous caller on the direct
//! route is charged to the meta route's shared key-name quota, not refused.

use super::direct_quota_key;
use crate::protocol::continuation::{QuotaKey, QuotaSource};

#[test]
fn an_anonymous_direct_caller_gets_the_meta_routes_key_name_quota() {
    let client = crate::gateway::auth::anonymous_client();
    let key = direct_quota_key((None, (None, None), Some(&client)));
    assert_eq!(key, Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))));
}
