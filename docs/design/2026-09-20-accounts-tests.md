# Accounts surface — test plan, Stage 1, with bodies

Companion to `docs/design/2026-09-20-accounts-surface.md`. That document listed
test **names**; this one carries the **bodies**, so they can be reviewed as
tests before any implementation exists.

**Status:** draft for external review. No production code written. Not wired
into the build — see "Why this is a document and not a `.rs` file".

## Scope of this artifact

In scope: the subset that Stage 1 of §11 needs, plus two tests that depend on
no open ruling.

| Test | Target file | Section | Compiles today? |
|---|---|---|---|
| `a_first_grant_record_passes_the_store_validator` | `src/personal_accounts/storage.rs` (new `#[cfg(test)] mod`) | §2.4 | **Yes** |
| `a_zero_counter_first_grant_is_refused_by_the_validator` | same | §2.4 | **Yes** |
| `s10_a_production_revoke_path_reaches_the_store` | `src/personal_accounts/fence_tests.rs` | §5 | No — needs the meta-tool |
| `s11_a_revoke_of_a_never_connected_descriptor_is_a_success` | same | §5 | **Yes** |
| `s12_a_revoke_is_idempotent_across_a_restart` | same | §5 | **Yes** |
| `a_self_revoke_through_the_meta_tool_refuses_the_next_dispatch` | `src/gateway/meta_mcp/account_rest_tests.rs` | §5 | No — needs the meta-tool |
| `a_reconnect_after_a_self_revoke_yields_a_usable_new_grant` | same | §5 | No — needs connect |
| `a_cross_site_navigation_to_the_callback_is_admitted` | origin-guard tests | §2.6 | No — needs the exemption |
| `a_cross_site_request_to_mcp_is_still_refused` | origin-guard tests | §2.6 | **Yes** (guards today's behaviour) |

Out of scope, and **why**, so absence is not read as oversight:

- **The three §6.5 admin tests.** Genuinely blocked. Options 1, 2 and 3 for
  conferring admin standing produce three different test *setups*, so the test
  cannot be written before the ruling. Deferring the test is correct; guessing
  the setup would produce a test that has to be rewritten.
- **The STORE.1 migration tests (§10.6).** Blocked on the same operator ruling
  the design flagged: the 3.x key has no principal field, so migrating means
  choosing whose credential it was.
- **The remaining §10.3 journey names.** Stage 4 in §11. Writing them now
  inverts the design's own staging.

## Why this is a document and not a `.rs` file

Most of these tests name a route, tool or type that does not exist yet. In Rust
a test file that does not compile is not a failing test — it breaks
`cargo test` and `cargo clippy --all-targets -- -D warnings` for the whole
workspace, both of which this repo gates on. That is a manufactured red line,
not test-first discipline.

The two validator tests are the exception: they compile against code that
exists today. They are marked for landing first, in their own commit, ahead of
any implementation.

**One of them is expected to pass on arrival.** `a_first_grant_record_passes_
the_store_validator` was written because §2.4's original table specified
`token_revision: 0`, which `validate_record` rejects — the connect path could
never have committed a single grant. That table was corrected at `6ddd2484`, so
the test now lands green, as a regression guard. Green here means "the
correction holds", not "the test did not run"; its companion negative test is
what proves it can fail.

---

## 1. The store validator (§2.4)

`validate_record` is private to `src/personal_accounts/storage.rs:127`, so these
live in a `#[cfg(test)] mod` in that file. `GrantRecord`
(`src/personal_accounts/mod.rs:137-149`) has eleven fields; all are
`pub(crate)`, so construction in-crate is direct.

The five rules the validator actually enforces, read at
`src/personal_accounts/storage.rs:127-143`:

| Rule | Rejected when |
|---|---|
| `access_token` | empty, or over 65,536 bytes |
| `refresh_token` | present and empty, or over 65,536 bytes |
| `generation` | not exactly 32 lowercase hex characters |
| `descriptor_revision` | not exactly 64 lowercase hex characters |
| `token_revision` | `== 0` |
| `authorization_epoch` | `== 0` |
| `scopes` | `windows(2).any(\|p\| p[0] >= p[1])` — **`>=`, so a duplicate is fatal, not only an unsorted pair** |

```rust
/// §2.4's first-grant table, transcribed field for field. If the design
/// specifies a record the store cannot hold, connect can never commit, and
/// that is a checkable claim rather than a matter of taste.
#[test]
fn a_first_grant_record_passes_the_store_validator() {
    let record = first_grant_record();
    validate_record(&record).expect("the first grant §2.4 specifies must be storable");
}

/// The companion that proves the test above can fail. These are the values
/// §2.4 carried before `6ddd2484`: both counters start at zero, which
/// `validate_record` refuses outright.
#[test]
fn a_zero_counter_first_grant_is_refused_by_the_validator() {
    for (token_revision, authorization_epoch) in [(0, 1), (1, 0), (0, 0)] {
        let record = GrantRecord {
            token_revision,
            authorization_epoch,
            ..first_grant_record()
        };
        assert!(
            matches!(validate_record(&record), Err(AccountError::NotAuthentic)),
            "a zero counter must be refused: \
             token_revision={token_revision} authorization_epoch={authorization_epoch}"
        );
    }
}

/// `>=` in the scope check encodes two rules, and a design that says only
/// "sorted" has met half of it. A duplicate is as fatal as a swap.
#[test]
fn a_duplicated_scope_is_refused_like_an_unsorted_one() {
    let duplicated = GrantRecord {
        scopes: vec!["email".into(), "email".into()],
        ..first_grant_record()
    };
    let unsorted = GrantRecord {
        scopes: vec!["profile".into(), "email".into()],
        ..first_grant_record()
    };
    for (label, record) in [("duplicated", duplicated), ("unsorted", unsorted)] {
        assert!(
            matches!(validate_record(&record), Err(AccountError::NotAuthentic)),
            "{label} scopes must be refused"
        );
    }
}

/// Exactly what §2.4 says a first grant is. Every field is named rather than
/// defaulted: a `Default` impl here would let a later field addition silently
/// acquire an unreviewed initial value.
fn first_grant_record() -> GrantRecord {
    GrantRecord {
        // 32 lowercase hex. A first grant mints a fresh generation; the value
        // is arbitrary, the shape is not.
        generation: "0".repeat(32),
        // Not zero. §2.4, corrected at 6ddd2484.
        token_revision: 1,
        authorization_epoch: 1,
        // 64 lowercase hex: the descriptor's current revision.
        descriptor_revision: "0".repeat(64),
        // Sorted and deduplicated, in that order.
        scopes: vec!["email".into(), "profile".into()],
        access_token: "first-grant-access-token".into(),
        refresh_token: Some("first-grant-refresh-token".into()),
        token_type: "Bearer".into(),
        expires_at: 0,
        provider_account_id: None,
        client_id: "fixture-client-id".into(),
    }
}
```

**Note for the implementer.** The stronger version of the first test round-trips
through `seal_token` → `open_token` (`src/personal_accounts/storage.rs:105`),
because `open_token` is where the validator actually runs in production. That
version was not written here: it needs `seal_token`'s signature and the `aad`
construction confirmed at source, and this artifact does not assert against
code it has not read. Prefer it if the signatures allow.

---

## 2. Revoke reaches the store from production code (§5, criterion STORE.2)

This is the row's actual blocker, and it is worth stating precisely because the
name alone understates it.

**Verified at source, this session.** Nothing outside `src/personal_accounts/`
calls revoke, and nothing outside `#[cfg(test)]` code calls it *anywhere*:

| Layer | Symbol | Visibility | Reachable from production? |
|---|---|---|---|
| Store | `revoke` (`mod.rs:525`) | `pub(crate)` | No — `expect(dead_code)` outside test/kani |
| Writer | `commit::revoke` (`commit.rs:479`) | `pub(in crate::personal_accounts)` | No |
| Service | `AccountService::invalidate` (`service.rs:317-327`) | crate | No — same annotation |
| Worker | `CustodyHandle::invalidate` (`worker.rs:241-244`) | inherent method | No — same annotation |
| Trait | `AccountCustody` (`vault.rs:46-55`) | `refresh_if_expired`, `release` only | **No revoke method at all** |

Searches run: `rg -n "\.revoke\(|::revoke\(" src --glob '!src/personal_accounts/**'`
returned one hit, `src/identity_grants_tests.rs:127`, which is a different
store (`IdentityGrant::revoke`, `src/identity_grants.rs:547`) and not this one.
`rg -n "\.invalidate\(" src/ --glob '!src/personal_accounts/**'` returned only
`#[cfg(test)]` fixtures.

So `s10` is not a coverage test. It is the test that fails until a production
caller exists, and it is the honest form of the criterion.

```rust
/// STORE.2's blocker, stated as an assertion: a caller OUTSIDE
/// `src/personal_accounts/` commits a revocation. Today no such caller exists
/// at any layer, so this test cannot pass by accident — it fails to compile
/// until the meta-tool handler of §5 is built, and that is the point.
///
/// The assertion is deliberately on the STORE, not on the tool's response. A
/// handler that returns `{"revoked": true}` without reaching the store would
/// satisfy a response-shaped test and leave the credential live.
#[tokio::test]
async fn s10_a_production_revoke_path_reaches_the_store() {
    let account = fixture_account_key();
    let custody = custody_with(&[(account.clone(), connected_grant())]);

    // The call under test goes through the shipped meta-tool, not through
    // `CustodyHandle::invalidate` directly. Calling the handle here would
    // re-assert what s08 already proves and would leave the gap open.
    let response = gateway_account_revoke(&custody, DESCRIPTOR_ID, &verified_identity(SUBJECT))
        .await
        .expect("a self-revoke of one's own grant must succeed");
    assert!(response.revoked);

    assert_eq!(
        custody.lookup(&account),
        AccountLookup::Revoked,
        "the tool reported success, so the store must hold a tombstone"
    );
}

/// §5: `commit::revoke` returns `Ok(())` with no IO when the account has no
/// entry (`commit.rs:488`). The handler must not add a lookup-first guard —
/// it would reintroduce the TOCTOU the single locked call removes, AND it
/// would turn the tool into an oracle for "does a grant exist for a descriptor
/// I never connected".
#[tokio::test]
async fn s11_a_revoke_of_a_never_connected_descriptor_is_a_success() {
    let custody = custody_with(&[]);

    let response = gateway_account_revoke(&custody, DESCRIPTOR_ID, &verified_identity(SUBJECT))
        .await
        .expect("revoking a descriptor that was never connected is a success, not an error");
    assert!(response.revoked);

    // The success must not have manufactured state.
    assert_eq!(custody.lookup(&fixture_account_key()), AccountLookup::Absent);
}

/// A tombstone is durable, and a second revoke over it is still a success.
/// Reopening the store between the two calls is what makes this different from
/// the in-process idempotency s08 covers.
#[test]
fn s12_a_revoke_is_idempotent_across_a_restart() {
    let root = tempfile::TempDir::new().expect("fixture tempdir");
    let config = store_config(root.path());
    let account = fixture_account_key();

    let store = PersonalAccountStore::initialize(config.clone()).expect("store initialize");
    store.commit_grant(&account, &connected_grant()).expect("seed grant");
    store.revoke(&account).expect("first revoke");
    drop(store);

    let reopened = PersonalAccountStore::initialize(config).expect("store reopens");
    assert_eq!(
        reopened.lookup(&account),
        AccountLookup::Revoked,
        "the tombstone must survive the reopen"
    );
    reopened
        .revoke(&account)
        .expect("a second revoke over a tombstone is a success with no write");
    assert_eq!(reopened.lookup(&account), AccountLookup::Revoked);
}
```

**Deliberately not asserted here.** The non-unix stub
(`commit.rs:613-619`) returns `AccountError::InvalidConfiguration` rather than
succeeding silently. It needs its own `#[cfg(not(unix))]` test; these three are
`#[cfg(unix)]` like their neighbours in `fence_tests.rs`, and a refusal that is
only asserted on the platform that never executes it is not asserted.

### 2.1 Through the meta-tool, end to end

```rust
/// The dispatch half. A grant that resolved a moment ago must stop resolving
/// once revoked — and the assertion is on the NEXT dispatch, because a cached
/// prepared credential is exactly how a revoke leaks past the store.
#[tokio::test]
async fn a_self_revoke_through_the_meta_tool_refuses_the_next_dispatch() {
    let custody = custody_with(&[(fixture_account_key(), connected_grant())]);
    let (meta, registry) = installed_gateway(&[(ACCOUNT, managed_descriptor())], &custody_dyn(&custody));

    // Resolve once, so a cache entry genuinely exists to be invalidated.
    let prepared = prepared_caching_context(&registry, SUBJECT, ACCOUNT, KEY).await;
    assert!(prepared.account_credential().is_some());

    gateway_account_revoke_via(&meta, DESCRIPTOR_ID, &verified_identity(SUBJECT))
        .await
        .expect("self-revoke");

    let refused = registry.resolve(ACCOUNT, KEY, Some(&verified_identity(SUBJECT))).await;
    assert!(
        matches!(refused, Err(AccountError::ReconnectRequired)),
        "a revoked account must refuse the next dispatch, not serve a cached credential; got {refused:?}"
    );
}

/// §5's closing claim: revoke writes no terminal state and does not blocklist
/// the key. `fence_tests.rs:139-140` records that re-consent minting a new
/// generation over a tombstone is legitimate; with §1 in place that is
/// testable end to end for the first time.
#[tokio::test]
async fn a_reconnect_after_a_self_revoke_yields_a_usable_new_grant() {
    let custody = custody_with(&[(fixture_account_key(), connected_grant())]);
    let (meta, registry) = installed_gateway(&[(ACCOUNT, managed_descriptor())], &custody_dyn(&custody));

    gateway_account_revoke_via(&meta, DESCRIPTOR_ID, &verified_identity(SUBJECT))
        .await
        .expect("self-revoke");
    complete_consent_journey(&meta, DESCRIPTOR_ID, SUBJECT).await;

    let resolved = registry
        .resolve(ACCOUNT, KEY, Some(&verified_identity(SUBJECT)))
        .await
        .expect("the reconnected grant must resolve");
    assert!(matches!(resolved, AccountCredential::Prepared(_)));

    // The new grant must be a NEW generation, not a resurrection of the old
    // one — otherwise the fence cannot tell them apart.
    assert_ne!(
        custody.generation_of(&fixture_account_key()),
        connected_grant().generation,
        "re-consent must mint a fresh generation over the tombstone"
    );
}
```

---

## 3. The origin-guard exemption (§2.6) — not blocked

The design lists §2.6 as a blocker because the **edit** needs approval: it
touches a global security guard. The **behaviour** is fully specified, so the
tests are writable now, and one of them asserts today's behaviour and should
land before the edit rather than after it.

What the guard does today, per the design's own citations: it is a global layer
outside auth (`src/gateway/router/mod.rs:345-348`) and admits only
`Sec-Fetch-Site: same-origin` or `none` (`src/gateway/origin_guard.rs:246-248`).
A provider's redirect arrives as `cross-site`, so every browser connect is
refused with 403 before the handler runs.

The pair below is deliberately a *pair*. The first is the feature; the second is
the containment. An exemption implemented as a prefix match rather than an exact
path match would pass the first test and fail the second — which is the whole
reason the second exists.

```rust
/// §2.6. A provider redirect carries `Sec-Fetch-Site: cross-site`. The one
/// exact callback path must admit it. `Host` and `Origin` checking is
/// unchanged — only the `Sec-Fetch-Site` rule is exempted.
#[tokio::test]
async fn a_cross_site_navigation_to_the_callback_is_admitted() {
    let response = request(CALLBACK_PATH)
        .header("Sec-Fetch-Site", "cross-site")
        .header("Sec-Fetch-Mode", "navigate")
        .send()
        .await;

    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the provider's redirect must reach the handler; \
         a 403 here means no browser can ever complete consent"
    );
}

/// The containment. If the exemption were written as a prefix or a
/// `starts_with`, this test fails — and it must, because that would open every
/// cross-site POST to the tool surface.
#[tokio::test]
async fn a_cross_site_request_to_mcp_is_still_refused() {
    for path in [
        "/mcp",
        // A path that shares the callback's prefix but is not the callback.
        concat!(CALLBACK_PATH, "/../mcp"),
        concat!(CALLBACK_PATH, "x"),
    ] {
        let response = request(path)
            .header("Sec-Fetch-Site", "cross-site")
            .send()
            .await;

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "the exemption must not widen beyond the exact callback path, but {path} was admitted"
        );
    }
}
```

**Honest limitation.** The two bodies above are written against the guard's
documented behaviour, not against its test harness: this session read the
design's citations but did not open `src/gateway/origin_guard.rs` itself. The
assertions are the contract; `request(...)` stands in for whatever the existing
origin-guard tests use to build a request, and the implementer must adopt that
rather than introduce a second harness. This is flagged rather than papered
over, because a test written against an imagined harness is a test that gets
rewritten at implementation time and quietly loses its assertions on the way.

---

## 4. What a reviewer should push back on

Four things, named so a reviewer does not have to find them:

1. **`s10` asserts on the store, not on the response.** If a reviewer thinks a
   response assertion is sufficient, say so — but the reason it is not is that a
   handler returning `{"revoked": true}` without reaching the store passes a
   response test and leaves a live credential at the provider.
2. **`a_first_grant_record_passes_the_store_validator` lands green.** A
   regression guard, not a red test. If a reviewer wants the test-first
   sequence to show red first, the honest way is to land it *before* reverting
   `6ddd2484` — which nobody should do. The negative companion is the evidence
   that it can fail.
3. **The §2.6 harness is a placeholder** (§3 above). That is the weakest part of
   this artifact.
4. **`a_reconnect_after_a_self_revoke_yields_a_usable_new_grant` spans two
   stages.** It needs connect (Stage 2) as well as revoke (Stage 1). It is
   listed here because §5 makes the claim; it cannot land in Stage 1.

---

## 5. Review round one — findings and fixes

`gpt-review`: **SHIP-WITH-FIXES**, six NOW-gate findings. All six accepted. The
two most serious are below with corrected bodies; the rest are recorded with
their fix so an implementer does not rediscover them.

### 5.1 HIGH — single-principal tests cannot detect cross-user targeting

The reviewer's point: every revoke test above seeds **one** principal and
**one** descriptor. A handler that ignores the caller's verified identity and
revokes by descriptor alone — the exact bug §7 exists to prevent — passes every
one of them. This is the single place where a mistake lets one user destroy
another's grant, and the tests could not see it.

Accepted without modification. The fixture must seed two principals:

```rust
/// The isolation property, which the one-principal version could not see.
/// A handler that revokes by descriptor alone passes s10/s11/s12 and fails
/// here — which is the correct ordering of sensitivity.
#[tokio::test]
async fn a_self_revoke_touches_only_the_calling_principals_grant() {
    let alice = account_key_for(SUBJECT_ALICE, DESCRIPTOR_ID);
    let bob = account_key_for(SUBJECT_BOB, DESCRIPTOR_ID);
    let custody = custody_with(&[
        (alice.clone(), connected_grant()),
        (bob.clone(), connected_grant()),
    ]);

    gateway_account_revoke(&custody, DESCRIPTOR_ID, &verified_identity(SUBJECT_ALICE))
        .await
        .expect("alice revokes her own grant");

    assert_eq!(custody.lookup(&alice), AccountLookup::Revoked);
    assert_eq!(
        custody.lookup(&bob),
        AccountLookup::Connected,
        "bob shares the descriptor but not the principal; his grant must be untouched"
    );
}

/// The two refusals that pair with it. §7.2: no verified identity, no account
/// principal. §2.1/§7.4: a principal named in the request is not a principal.
#[tokio::test]
async fn a_revoke_without_a_verified_identity_is_refused() {
    let custody = custody_with(&[(account_key_for(SUBJECT_ALICE, DESCRIPTOR_ID), connected_grant())]);

    let refused = gateway_account_revoke_unauthenticated(&custody, DESCRIPTOR_ID).await;
    assert!(matches!(refused, Err(AccountError::IdentityRequired)), "got {refused:?}");

    assert_eq!(
        custody.lookup(&account_key_for(SUBJECT_ALICE, DESCRIPTOR_ID)),
        AccountLookup::Connected,
        "a refused revoke must not have written a tombstone"
    );
}

#[tokio::test]
async fn a_caller_supplied_principal_field_does_not_select_the_account() {
    let alice = account_key_for(SUBJECT_ALICE, DESCRIPTOR_ID);
    let custody = custody_with(&[(alice.clone(), connected_grant())]);

    // Bob authenticates as himself and names alice in the payload.
    let response = gateway_account_revoke_naming(
        &custody, DESCRIPTOR_ID, SUBJECT_ALICE, &verified_identity(SUBJECT_BOB),
    ).await;

    // Whether this refuses or silently revokes bob's own (absent) grant is a
    // design choice; what must NOT happen is alice's grant changing.
    assert_eq!(
        custody.lookup(&alice),
        AccountLookup::Connected,
        "a principal in the request body must never select the account"
    );
    drop(response);
}
```

### 5.2 HIGH — the next-dispatch test re-resolves instead of reusing

The reviewer is right and the original body was subtly circular: it warmed a
cache with `prepared_caching_context`, then asserted that a **second
`resolve`** refuses. But re-resolving is the path that consults the store; the
leak being tested for is a *already-prepared* credential that never resolves
again. The original test passes against an implementation that leaks.

```rust
#[tokio::test]
async fn a_self_revoke_through_the_meta_tool_refuses_the_next_dispatch() {
    let custody = custody_with(&[(account_key_for(SUBJECT_ALICE, DESCRIPTOR_ID), connected_grant())]);
    let (meta, registry) = installed_gateway(&[(ACCOUNT, managed_descriptor())], &custody_dyn(&custody));

    // Prepare a credential BEFORE the revoke and hold it, exactly as an
    // in-flight request would.
    let context = prepared_caching_context(&registry, SUBJECT_ALICE, ACCOUNT, KEY).await;
    let executor = caching_executor(&registry, None);

    gateway_account_revoke_via(&meta, DESCRIPTOR_ID, &verified_identity(SUBJECT_ALICE))
        .await
        .expect("self-revoke");

    // Dispatch with the credential prepared before the revoke. This is the
    // leak path: nothing here re-enters `resolve`.
    let dispatched = executor
        .execute(&cacheable_capability(&base_url, KEY, Some(ACCOUNT)), &context)
        .await;
    assert!(
        dispatched.is_err(),
        "a credential prepared before the revoke must not still dispatch after it"
    );
}
```

### 5.3 The four remaining findings, accepted with their fixes

| Finding | Fix |
|---|---|
| `s12` calls `initialize` twice; the initializer **refuses** an existing store rather than reopening it — verified at source: `initialize` is `mod.rs:431`, **`open` is `mod.rs:436`** | `s12` reopens with `PersonalAccountStore::open(config)`. The original body could not have compiled into a passing test. |
| Every tool-level revoke case succeeds, so a handler that swallows a custody failure and still reports `revoked: true` is undetected | Add `a_revoke_that_fails_in_custody_is_reported_as_a_failure`: inject a custody error, assert the response is an error and that no success is reported. §5's honest sentence — "revoked here; the provider did not confirm" — is a *different* case and needs its own test. |
| `assert_ne!(status, FORBIDDEN)` on the callback accepts 401, 404 and 500, so it does not establish the handler was reached | Assert the exact downstream response of an identifiable stub handler, not the absence of one status. |
| The §2.6 tests never challenge `Host` or `Origin` on the callback itself, so an exemption that bypasses the **whole** guard would pass | Add exact-callback requests carrying an invalid `Host`, an invalid HTTP/2 `:authority` and a foreign `Origin`, each asserted refused. The exemption is `Sec-Fetch-Site` only. |

### 5.4 Two improvements accepted, one deferral narrowed

The reviewer challenged both deferrals, and was half right.

- **Admin tests (§6.5).** Narrowed. `the_admin_tool_is_not_permitted_to_a_non_admin_caller` and
  `an_admin_cannot_reach_another_principal_through_the_self_service_tool` hold
  across all three options for conferring admin standing, so they are writable
  now and move to Stage 1. Only
  `an_admin_revoking_another_principal_writes_an_audit_row_naming_actor_and_subject`
  genuinely needs the ruling, because the actor's identity is what the options
  differ on.
- **STORE.1 migration.** Partly narrowed. Choosing *whose* credential a 3.x
  token was still needs the operator. But three properties do not: that the
  3.x files are left in place unmodified, that they remain readable, and that
  **no principal is implicitly assigned**. That last one is a real test of the
  migrate-nothing position and should exist regardless of which rule is chosen.
- **`s12` no-write claim.** §5 says a repeat revoke performs *no IO*. The test
  asserts only the resulting state, which an implementation that rewrites an
  equivalent tombstone also satisfies. A write observer distinguishes them.

---

## 6. Review round two — the assertions in §5 do not compile

Second reviewer: **SHIP-WITH-FIXES**, five improvements. Four are refinements
and are folded below. The fifth exposed a defect in §5.1 that matters more than
any of them, so it leads.

### 6.1 BLOCKING — the isolation assertion has no seam to assert through

§5.1 asserts `assert_eq!(custody.lookup(&bob), AccountLookup::Connected)`. Two
independent reasons that cannot compile, both verified at source:

| Claim | Source | Consequence |
|---|---|---|
| `AccountLookup` variants carry payloads: `Connected(GrantRecord)`, `Revoked(GrantVersion)` | `src/personal_accounts/mod.rs:168-173` | A bare `AccountLookup::Connected` is not an expression |
| The test fixture's `Custody` exposes exactly three methods — `releases()`, `refreshes()`, `installed()` | `src/gateway/meta_mcp/account_resolver_fixture.rs:371-387` | There is no `lookup` to call |

So the most important test in this plan — the one that catches a revoke
targeting the wrong user — was written against an observation seam that does
not exist. This is the same class of defect the companion design shipped with
(§2.4's table specified a record the validator rejects): a plausible-looking
assertion that never met the type it asserts on.

**The seam that does exist.** `PersonalAccountStore` has
`pub(crate) fn lookup(&self, account: &AccountKey) -> Result<AccountLookup, AccountError>`
(`mod.rs:476`), and `open` (`mod.rs:436`) reopens a closed store. So the
isolation check reads the store directly rather than asking custody:

There is no accessor to add, because there is nothing to return. `Custody`
holds four fields — `handle`, `refresh_calls`, `observer`, and
`_root: tempfile::TempDir` (`account_resolver_fixture.rs:363-368`) — and the
`StoreConfig` is built inside `custody_with_rotation` from `store_config(root.path())`
(`:284`, `:396`) and then dropped. So Stage 1 must either **store** the config
on `Custody`, or expose `_root.path()` and rebuild it. Storing it is the
smaller change and the one that cannot drift from what custody actually opened:

```rust
// Add `config: StoreConfig` to the fixture's `Custody` and a `config()`
// borrow. One field, one accessor, both `#[cfg(test)]`.
let after = PersonalAccountStore::open(custody.config().clone()).expect("reopen");
assert!(
    matches!(after.lookup(&bob), Ok(AccountLookup::Connected(_))),
    "bob shares the descriptor but not the principal; his grant must survive"
);
assert!(matches!(after.lookup(&alice), Ok(AccountLookup::Revoked(_))));
```

`matches!` with `(_)` is deliberate: the test's subject is *which account
changed state*, not the record's contents. Asserting the payload as well would
couple the isolation test to token rotation and make it fail for reasons that
have nothing to do with isolation.

**This is the one fixture change Stage 1 needs**, and it is confined to a
`#[cfg(test)]` fixture, so it widens nothing that ships.

Worth naming why this correction is here at all: §6.1 first prescribed
"an accessor returning the config" without opening the struct, which is the
same defect §6.1 exists to report — a symbol named from plausibility rather
than from the definition. The struct head is four lines and settles it.

### 6.2 The four refinements, accepted

| Improvement | Why it is right |
|---|---|
| Round-trip the first-grant fixture through `seal_token` → `open_token` rather than calling `validate_record` directly | The direct call proves the record is *valid*; the round trip proves the write path *checks*. A commit path that bypassed the validator would pass the direct version. |
| Build `s10`/`s11` keys with `identity::account_key(identity, descriptor)`, not a parallel fixture helper | A never-connected revoke can otherwise return `Absent` for a key the handler never touched — the test passes by looking in the wrong place. |
| Write `s12` with the existing `empty_store` / `reopen` / `grant` helpers and assert `Ok(AccountLookup::Revoked(version))` | Same reason as §6.1, and it puts the restart case beside `s08` where a reader will find it. |
| Give the callback-admission request a real `?code=&state=` query string | An origin exemption matched against the full URI rather than `path()` fails here instead of in a browser. |

The fifth — replacing `assert_ne!(status, FORBIDDEN)` with an explicit admitted
outcome — is §5.3 row 3, already accepted.

### 6.3 One correction to the review

The second reviewer cites `src/server/mod.rs:408` for where `GatewayCustody`
lives. That file does not exist. The type is in **`src/gateway/server/mod.rs`**
(`rg -l GatewayCustody src` returns that path and the fixture, nothing else).
The reviewer's *point* stands unchanged — `MetaMcp` does not hold custody, so a
self-revoke test at the meta-tool layer must reach it the way the production
dispatcher does — but the citation would have sent an implementer to a missing
file.

### 6.4 Where Stage 1 now stands

Two independent reviewers, two rounds, both landing on SHIP-WITH-FIXES. Round
one found that the tests could not distinguish a correct implementation from
one that revokes the wrong user's grant. Round two found that the fix for it
did not compile. Neither round found a test that was *wrong about the
behaviour* — the design's specification has held through both.

What an implementer picks up: the bodies in §5 and §6, the one fixture
accessor named in §6.1, and the two rulings §4 still parks with the operator
(admin standing, STORE.1 migration). Nothing else in Stage 1 is blocked.
