// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the service does with what the provider returned — including the two
//! cases where it must not call the provider at all, or must not believe it.

use std::sync::atomic::Ordering;

use super::*;

const ROTATED_ACCESS: &str = "synthetic-alice-access-rotated-private-material-b2e14";
const SUPPLIED_REFRESH: &str = "synthetic-alice-refresh-rotated-private-material-77d0";

/// One cell of the scope/refresh-token presence matrix, end to end.
///
/// RFC 6749 §5.1/§6 lets a provider omit `scope` and `refresh_token`
/// independently, and the two fields are handled by different code. Testing
/// them only together lets a service that couples them — dropping the stored
/// refresh token whenever scopes arrive, say — pass every case.
///
/// The scopes supplied here are always the granted set, so the epoch must not
/// move: this case is about field PRESENCE. Scope movement is asserted in the
/// refresh suite.
fn refresh_presence_case(
    supplied_scopes: Option<Vec<String>>,
    supplied_refresh: Option<&str>,
    token_type: &str,
) {
    block_on(async {
        let original = grant();
        let (tmp, store) = seed(&[(&alice(), original.clone())]);
        let provider = ScriptedProvider::new();
        let rotated = TokenRefresh {
            access_token: ROTATED_ACCESS.into(),
            refresh_token: supplied_refresh.map(str::to_owned),
            scopes: supplied_scopes.clone(),
            token_type: token_type.into(),
            expires_at: u64::MAX,
        };
        let calls = provider.ready(&alice(), Ok(rotated.clone()));
        let (observer, observer_calls) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        // Omission preserves what was granted; presence replaces it exactly.
        let expected_scopes = supplied_scopes.unwrap_or_else(|| original.scopes.clone());
        let expected_refresh = supplied_refresh
            .map(str::to_owned)
            .or_else(|| original.refresh_token.clone());

        let lease = refuse_scaffold(
            service.refresh_if_expired(&alice()).await,
            "presence-matrix refresh",
        )
        .expect("expired refresh succeeds whatever the provider omitted");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(lease.token_revision > original.token_revision);
        assert_eq!(lease.scopes, expected_scopes);
        assert_eq!(lease.generation, original.generation);
        assert_eq!(lease.authorization_epoch, original.authorization_epoch);

        let updated = expect_connected(
            service
                .store()
                .lookup(&alice())
                .expect("lookup after presence-matrix refresh"),
        );
        assert!(updated.token_revision > original.token_revision);
        assert_eq!(updated.token_revision, lease.token_revision);
        assert_eq!(updated.scopes, expected_scopes);
        assert!(
            updated.refresh_token == expected_refresh,
            "a supplied refresh token must be stored and an omitted one preserved"
        );
        assert!(
            updated.access_token == rotated.access_token,
            "durable access token must match provider rotation"
        );
        assert!(
            updated.token_type == token_type,
            "the provider's token type decides how the credential is presented"
        );
        assert_eq!(updated.expires_at, u64::MAX);

        let credentials = refuse_scaffold(service.release(&lease), "presence-matrix release")
            .expect("positive release after presence-matrix refresh");
        assert_eq!(
            credentials,
            ReleasedCredentials {
                access_token: ROTATED_ACCESS.into(),
                token_type: token_type.into(),
            }
        );
        assert_eq!(observer_calls.load(Ordering::SeqCst), 1);

        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let reopened = expect_connected(store.lookup(&alice()).expect("reopen after refresh"));
        assert_eq!(reopened.token_revision, updated.token_revision);
        assert_eq!(reopened.scopes, expected_scopes);
        assert!(
            reopened.refresh_token == expected_refresh,
            "reopen must preserve the refresh token the refresh decided on"
        );
        assert!(
            reopened.access_token == rotated.access_token,
            "reopen must preserve the rotated access token"
        );
        assert!(reopened.token_type == token_type);
    });
}

#[test]
fn refresh_omitting_scopes_and_refresh_token_preserves_both_and_advances_token_revision() {
    refresh_presence_case(None, None, "Bearer");
}

#[test]
fn refresh_supplying_scopes_and_refresh_token_stores_both_and_the_token_type() {
    refresh_presence_case(Some(grant().scopes), Some(SUPPLIED_REFRESH), "DPoP");
}

#[test]
fn refresh_supplying_scopes_only_keeps_the_stored_refresh_token() {
    refresh_presence_case(Some(grant().scopes), None, "DPoP");
}

#[test]
fn refresh_supplying_a_refresh_token_only_keeps_the_granted_scopes() {
    refresh_presence_case(None, Some(SUPPLIED_REFRESH), "Bearer");
}

/// Every other case seeds an expired grant, which lets an implementation that
/// always contacts the provider pass the whole suite. During an outage that
/// implementation fails sessions that had no need to be refreshed.
#[test]
fn an_unexpired_grant_is_returned_without_contacting_the_provider() {
    block_on(async {
        let record = unexpired_grant();
        let fx = Fixture::seeded(&[(&alice(), record.clone())]);

        let lease = refuse_scaffold(
            fx.service.refresh_if_expired(&alice()).await,
            "unexpired refresh",
        )
        .expect("an unexpired grant needs no provider round trip");
        assert_eq!(lease, expected_lease(alice(), &record));
        assert_eq!(
            fx.provider_calls.load(Ordering::SeqCst),
            0,
            "a valid session must survive a provider outage untouched"
        );

        let credentials = refuse_scaffold(fx.service.release(&lease), "unexpired release")
            .expect("the unrefreshed lease still releases");
        assert_eq!(credentials, expected_credentials(&record));
        assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fx.provider_calls.load(Ordering::SeqCst), 0);

        let durable = expect_connected(
            fx.service
                .store()
                .lookup(&alice())
                .expect("unexpired lookup"),
        );
        assert!(
            durable == record,
            "nothing rotated, so nothing durable may move"
        );

        let Fixture { tmp, service, .. } = fx;
        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        assert!(expect_connected(store.lookup(&alice()).expect("unexpired reopen")) == record);
    });
}

/// A refusal the user can do nothing about must not be spent on the user. An
/// outage is transient; reconnect-required is not, and writing one during an
/// outage costs a re-consent journey per outage.
#[test]
fn an_unavailable_provider_leaves_the_account_connected_and_untouched() {
    block_on(async {
        let record = grant();
        let (tmp, store) = seed(&[(&alice(), record.clone())]);
        let provider = ScriptedProvider::new();
        let calls = provider.ready(&alice(), Err(ProviderRefreshError::Unavailable));
        let (observer, observer_calls) = counting_observer();
        let service = AccountService::new(store, provider, observer);

        assert_eq!(
            domain_err(
                service.refresh_if_expired(&alice()).await,
                "unavailable provider refresh",
            ),
            AccountServiceError::ProviderUnavailable
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer_calls.load(Ordering::SeqCst), 0);

        let durable = expect_connected(
            service
                .store()
                .lookup(&alice())
                .expect("account is still connected after an outage"),
        );
        assert!(
            durable == record,
            "an outage must not move a single durable field"
        );
        let lease = refuse_scaffold(service.resolve(&alice()), "resolve after outage")
            .expect("an outage does not disconnect the account");
        assert_eq!(lease, expected_lease(alice(), &record));

        drop(service);
        let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let reopened = store.lookup(&alice()).expect("reopen after outage");
        assert_eq!(
            lookup_kind(&reopened),
            "connected",
            "an outage must not durably fence the account"
        );
        assert!(expect_connected(reopened) == record);
    });
}
