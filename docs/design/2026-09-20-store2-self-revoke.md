<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# STORE.2 self-revoke — design

> **SUPERSEDED 2026-09-20** by `docs/design/2026-09-20-accounts-surface.md` — the operator ruling widened to the full connect + revoke surface; §0 here remains accurate, §1–§7 are too narrow.

**Criterion**: MIK-6744.STORE.2 · **Operator ruling**: option B, self-revoke only
· **Status**: design for review, no code written
· **Date**: 2026-09-20

A caller may revoke their OWN personal-account grant and nobody else's. Admin
revoke, revoking another principal's grant, and any new audit surface are out of
scope by operator ruling and are enumerated in §7.

---

## §0. Two corrections to the briefed premise

Both are load-bearing for §1. Stated once, then the operator's scope continues
unchanged.

### 0.1 `account_rest_tests.rs` is not an inbound account API

The brief points at `src/gateway/meta_mcp/account_rest_tests.rs` as "an account
REST surface" to extend. It is not one. Its own header states the claim under
test: "REST capabilities dispatching through the ONE account credential
boundary… A REST capability whose `auth.account` names an
`accounts.descriptors` map key executes as the VERIFIED caller"
(`src/gateway/meta_mcp/account_rest_tests.rs:3-10`). That is **outbound**
dispatch — a capability calling a third-party API as the end user. It exposes no
inbound endpoint for managing an account, and its fixture builds an HTTP
*capture endpoint* to observe egress, not a route the product serves
(`src/gateway/meta_mcp/account_rest_fixture.rs:26-32`).

There is no inbound personal-account management surface anywhere today. The
served HTTP routes are `/.well-known/jwks.json`, `/.well-known/oauth-protected-resource`,
`/health`, `/api/costs`, `/mcp`, `/mcp/{name}`, `/sse`, `/metrics`
(`src/gateway/router/mod.rs:217-321`) plus the dashboard namespace
(`src/gateway/ui/control_plane.rs:42-46`). No meta-tool names an account either
(`src/gateway/meta_mcp/mod.rs:2160-2178`).

### 0.2 No production connect path exists either

`AccountService::commit_grant_if` carries the same `expect(dead_code)`
(`src/personal_accounts/service.rs:338`), as does
`PersonalAccountStore::commit_grant_if_unchanged`
(`src/personal_accounts/consent.rs:73-75`). Outside the `personal_accounts`
module the only `commit_grant*` callers are
`control_plane::store::commit_grant_audited`
(`src/control_plane/store.rs:292`, `:778`;
`src/gateway/ui/control_plane.rs:195`, `:1172`, `:1195`) — the **policy** grant
store, an unrelated subsystem.

So the briefed consequence ("a user who connects an OAuth account has NO way to
disconnect it") overstates by one step: in 4.0.0 a user cannot connect one
through the product either. This does not change the deliverable — the operator
asked for self-revoke and self-revoke is what this designs — but it changes two
things in the doc, and those changes are the point of recording it:

* §1 cannot place self-revoke "beside the existing connect surface"; there is
  none to sit beside.
* §6 cannot name an end-to-end connect→revoke→re-consent test. Re-consent is
  pinnable only at store/service level against `commit_grant`, and §6 says so
  rather than naming a test nobody can write.

---

## §1. The call site

### 1.1 The blocking constraint: who can reach `invalidate`

`AccountCustody` is a two-method trait — `refresh_if_expired` and `release`, and
nothing else (`src/personal_accounts/vault.rs:46-56`). Its doc is explicit that
it is "Type erasure only… Nothing here is a seam for a second resolution path"
(`:40-45`). `invalidate` is **not** on it; it is an inherent method on the
concrete handle (`src/personal_accounts/worker.rs:241`).

`VaultStrategy` holds `Arc<dyn AccountCustody>`
(`src/personal_accounts/vault.rs:82`), so the strategy is a dead end for revoke.
Searching the gateway tree for personal-account custody outside tests returns
only `src/gateway/server/mod.rs` and `src/gateway/server/account_bindings.rs`;
neither `MetaMcp` nor `AppState` holds it. The concrete handle lives on the
`Gateway` struct:

```
custody: Option<Arc<crate::personal_accounts::GatewayCustody>>   server/mod.rs:408
```

where `GatewayCustody = worker::CustodyHandle<GatewayRefreshProvider, AccountReleaseAudit>`
(`src/personal_accounts/mod.rs:646`). At startup it is downgraded to the trait
object for installation and the concrete `Arc` is retained
(`src/gateway/server/mod.rs:1725-1732`).

**Consequence for the design**: the revoke path must be given the concrete
handle. It must NOT widen the `AccountCustody` trait — adding a third method
would contradict the invariant the trait's own doc asserts, and every other
implementor (`GatedCustody`, `RendezvousCustody` —
`src/gateway/meta_mcp/account_resolver_gate.rs:85`, `:125`) would grow a method
it has no reason to hold.

### 1.2 Recommendation: a dashboard-namespace route, not a meta-tool

Two candidates are real. Recommendation is the first.

**(A) `POST /ui/api/accounts/revoke` — recommended.**

*Reachable by the caller this criterion is about.* The UI api routes are merged
into the SAME router that serves `/mcp`, not mounted behind a separate listener
(`src/gateway/router/mod.rs:267-270`), so they sit behind the same auth layer.
`/ui/api/*` is not a public path — the default `public_paths` are `/health` and
`/metrics`, and the bucket test asserts `/mcp` and `/` are *not* public
(`src/gateway/auth.rs:1163-1173`). The dashboard bootstrap is a separate
mechanism that fires only on the literal path `/dashboard`
(`src/gateway/auth.rs:695-696`) and does not gate this namespace. An end user
holding the OIDC credential they use at `/mcp` therefore reaches this route with
that same credential.

*The extractor is declared here already.* Neighbouring handlers take
`identity: Option<Extension<VerifiedIdentity>>`
(`src/gateway/ui/control_plane.rs:82`, `:109`, `:178`, `:203`, `:255`), and the
namespace already uses POST-with-body for mutations (`:43-45`). `AppState` gains
one field, populated at the single construction site
(`src/gateway/server/mod.rs:1922`) where `self.custody` is already in scope — it
is read seven lines earlier at `:1725`. No trait change, no new abstraction, no
second custody lookup path.

*The trap in this namespace — a MUST NOT.* That `Option` is genuinely optional:
`actor_from_client` (`src/gateway/ui/control_plane.rs:478-516`) deliberately
falls back, when no OIDC identity is present, to an `AuthenticatedClient` and
then to a literal `"anonymous"` actor (`:496-512`). That is correct for a
read-mostly dashboard and **catastrophic** for revoke — it would hand a
bearer-only or anonymous caller a principal they did not prove. The revoke
handler MUST NOT call `actor_from_client`, MUST NOT construct a
`ControlPlaneActor`, and MUST refuse a `None` identity per §2.4. A reviewer
should treat any reuse of that helper as a rejection.

**(B) A new meta-MCP tool.** Viable — `MetaMcpCallerContext` already carries the
identity (`src/gateway/meta_mcp/mod.rs:163`) — and admissible under the locked
decision on its own terms, since a revoke tool is not a dynamic-discovery tool
and 11→12 stays inside the 9–17 range CLAUDE.md fixes. It is the runner-up on
cost, not on principle: every meta-tool change must update README,
`benchmarks/public_claims.json` and the badges in one PR, which CLAUDE.md names
as a known drift source. Spending that on the disconnect half while the connect
half does not exist (§0.2) is not yet defensible. **If review judges that the
dashboard namespace is the wrong product home for an end-user action — a fair
reading, given the trap above — B is the fallback and §2 transfers unchanged.**

**Caveats to record with the recommendation:**

* **The UI api router is merged under `#[cfg(feature = "webui")]`
  (`src/gateway/router/mod.rs:268-270`), and that is not a cosmetic caveat — it
  decides §4.** `webui` is a default feature (`Cargo.toml:179`), so the route
  ships in default builds; a `--no-default-features` build would have no revoke
  path *and no caller for the four items whose annotations §4.1 removes*, which
  turns the `--no-default-features` clippy combo red. §4.4 states the constraint
  and the two ways out. Taking the first — registering the route outside the
  `webui` gate — resolves this bullet rather than accepting it, and is the
  design's choice.
* The handler must NOT build a `ControlPlaneActor`
  (`src/gateway/ui/control_plane.rs:480-514`) and must write no control-plane
  audit event. That is the admin-shaped path the operator deferred (§7).
* If connect later lands as a meta-tool, revoke should move beside it. The
  authorization rule in §2 is surface-independent and survives that move
  unchanged.
* Personal-account storage is unix-only: the non-unix `revoke` is a stub
  returning `AccountError::InvalidConfiguration`
  (`src/personal_accounts/commit.rs:613-619`). Self-revoke on a non-unix build
  therefore refuses explicitly rather than silently reporting success.

### 1.3 Shape

Request body names exactly one thing: the `accounts.descriptors` map key.

```
POST /ui/api/accounts/revoke     { "descriptor_id": "<map key>" }
```

Nothing else is read from the request. §2 explains why that is the whole of the
input.

---

## §2. The authorization rule

**The rule, stated precisely:**

> The caller's `AccountKey` is CONSTRUCTED from the verified identity the
> transport attached, never compared against one the caller supplied. Two of the
> key's five fields are taken from `VerifiedIdentity` and the other three from
> the configured descriptor. No request field contributes a principal. A request
> with no verified identity is refused, never defaulted.

### 2.1 Why there is no comparison step

The obvious design — accept a principal id, compare it to the caller, revoke on
match — is deliberately not used. A comparison can be got wrong: a normalisation
mismatch, a case fold, an early return on a parse error, and one user revokes
another. This design makes that bug **inexpressible**, because the request has
no field in which another user's principal could be named.

The mechanism already exists and is already the one the credential path uses:

```rust
// src/personal_accounts/identity.rs:76-96
pub(crate) fn account_key(
    identity: Option<&VerifiedIdentity>,
    descriptor: &AccountDescriptor,
) -> Result<AccountKey, IdentityBindingError> {
    let identity = identity.ok_or(IdentityBindingError::MissingVerifiedPrincipal)?;
    let key = AccountKey {
        principal_authority: identity.issuer.clone(),
        principal_subject:   identity.subject.clone(),
        backend_id:          descriptor.descriptor_id.clone(),
        resource:            descriptor.resource.clone(),
        oauth_issuer:        descriptor.issuer.clone(),
    };
    key.digest()?;
    Ok(key)
}
```

* `principal_authority` ← `VerifiedIdentity::issuer`, `principal_subject` ←
  `VerifiedIdentity::subject` (`identity.rs:84-89`). The caller cannot influence
  either; both come from a validated OIDC ID token
  (`src/key_server/oidc.rs:106-120`).
* `backend_id`, `resource`, `oauth_issuer` ← the configured descriptor
  (`identity.rs:38-46`), immutable within a configuration revision.
* `email`, `name` and `groups` are excluded **by construction**, not by
  omission: the module comment at `identity.rs:20-25` records that a mutable
  label inside the isolation boundary would let one user's rename silently
  re-point custody, and the function does not mention those fields, so admitting
  one would appear in a diff.
* No verified principal → `IdentityBindingError::MissingVerifiedPrincipal`
  (`identity.rs:59`, raised at `:82`). There is no anonymous, operator-token or
  API-key fallback for personal mode.

The revoke handler calls this same function. It does not re-derive a key, does
not re-implement the length-prefixed digest (`AccountKey::digest`,
`src/personal_accounts/mod.rs:57-62`), and does not construct `AccountKey`
literally. The only production caller today is `VaultStrategy::prepare`
(`src/personal_accounts/vault.rs:133`); revoke becomes the second, using the
identical call.

### 2.2 Where the identity comes from

Attached by the auth layer as an axum extension and read at the transport edge:

```
http_request.extensions().get::<VerifiedIdentity>().cloned()   handlers.rs:588
```

For the recommended surface (§1.2 A) the handler declares
`identity: Option<Extension<VerifiedIdentity>>` exactly as the neighbouring
control-plane handlers do (`src/gateway/ui/control_plane.rs:82`). For surface
(B) it would read `MetaMcpCallerContext::verified_identity`
(`src/gateway/meta_mcp/mod.rs:163`) — the same value, carried uncollapsed
precisely so the account boundary can see the real user.

`VerifiedIdentity::stable_actor_id` (`src/key_server/oidc.rs:132-141`) is the
collision-safe length-prefixed derivation of the same two fields; `AccountKey`
applies the same length-prefixing over five fields
(`src/personal_accounts/mod.rs:57-80`). The revoke path needs neither
separately — it needs only that the two principal fields are taken from the
verified identity and nothing else.

**The one construction constraint, and the one forbidden path.** An `AccountKey`
on this path is built ONLY by `account_key()`
(`src/personal_accounts/identity.rs:76-96`), and its two principal fields come
ONLY from a `VerifiedIdentity` (`identity.rs:84-89`). The handler MUST NOT route
through `actor_from_client` (`src/gateway/ui/control_plane.rs:478-516`) — the
helper its five sibling handlers use — because that helper falls back to an
`AuthenticatedClient` and then to a literal `"anonymous"` actor when no verified
identity is present (`:496-512`). A bearer-derived or anonymous actor id is
attacker-influenced; feeding one into `account_key()` IS the "one user
disconnects another" failure this section exists to prevent. Copying the
neighbouring handler pattern wholesale writes that bug. §1.2 records the same
MUST NOT at the call site; it is repeated here because a reader of §2 alone must
not miss it.

Fail-closed is what the `Option` buys. The extension is absent exactly when auth
did not verify an identity, and the handler answers `MissingVerifiedPrincipal`
(`identity.rs:59`, raised at `:82`) rather than substituting anything. No request
field names a principal, so there is nothing to fall back TO — §2.1's "no
comparison step" guarantee holds only while both of those remain true.

### 2.3 Admin plays no part

`MetaMcpCallerContext::is_admin` (`src/gateway/meta_mcp/mod.rs:165-167`) is NOT
consulted. Any authenticated caller may revoke their own grant; no caller,
admin included, can revoke another's through this path, because no request field
names a principal. Admin-mediated revoke is §7.

### 2.4 Refusal vocabulary

| Condition | Outcome |
|---|---|
| No verified identity | `MissingVerifiedPrincipal` (`identity.rs:59`) — refuse |
| `descriptor_id` absent from `accounts.descriptors` | `IdentityBindingError` variant at `identity.rs:66` — refuse; see §4 |
| Empty/oversized key field | `AccountError::InvalidAccountKey` via `digest()` (`mod.rs:59`, refused at `:77`) — refuse |
| Custody not configured | `AppState` field is `None` — refuse; never a silent success |
| Non-unix build | `AccountError::InvalidConfiguration` (`commit.rs:613-619`) — refuse |

No refusal carries token material; the account errors are secret-free by
construction (`src/personal_accounts/mod.rs:83-100`).

---

## §3. What `invalidate` already guarantees

The revoke machinery is built and correct. The caller's job is to call it with
the right key and then get out of the way. This section exists so a reviewer can
reject any implementation that re-implements one of these.

### 3.1 The call chain is three thin frames

```
CustodyHandle::invalidate      worker.rs:241   — offloads onto the custody worker
  AccountService::invalidate   service.rs:326  — one line: self.store.revoke(account)?
    PersonalAccountStore::revoke  mod.rs:525   — takes the authority lock
      storage::commit::revoke     commit.rs:479 — tombstone, then unlink token bytes
```

Nothing in that chain is a placeholder. `AccountService::invalidate` is
deliberately one statement (`service.rs:326-329`); the durability, ordering and
fencing all live below it.

### 3.2 Guarantees the caller MUST NOT re-implement

**Durable tombstone before success.** `PersonalAccountStore::revoke` takes the
authority lock and commits before returning (`mod.rs:525-530`). Token bytes are
unlinked only after the authority says they are unreferenced
(`commit.rs:495-498`). A caller must not attempt its own ordering, its own
delete, or a read-then-write.

**Idempotency, already in the store.** `commit.rs:488-491` returns `Ok(())` with
no IO in two cases: nothing was ever committed, and the entry is already
`GrantState::Revoked`. See §5.2 — the caller must not add a lookup-first guard.

**Cache-entry invalidation happens by generation, not by eviction.** The vault
publishes a five-field account digest widened with the grant generation,
authorization epoch, token revision and descriptor revision
(`src/identity_propagation/account_strategies.rs:106-110`), and a revoked
account therefore produces a DIFFERENT binding rather than a reused one. The
binding is copied into every cache key and never re-hashed or parsed (`:124-127`).
The caller must not walk a cache, evict keys, or bump a version.

**The lease is rechecked at the durable half of `revalidate`.** `revalidate`
runs before any cache entry may be selected and before any egress
(`account_strategies.rs:545-548`); its last and most important check re-releases
the lease against the store, which "is the only one that can see a revocation
committed since the mint" (`:607-630`). A refusal there does not fall back to
the gateway-held credential and does not degrade into a cache miss (`:556-559`).
The caller must not notify the resolver, the registry or the executor.

**Release-time recheck is unconditional.** `AccountService::release` re-reads
current state and compares the WHOLE lease — "a superseded generation,
authorization or descriptor is just as retired" (`service.rs:300-307`), returning
`LeaseRetired`. The caller must not try to cancel outstanding leases.

### 3.3 What the caller therefore does

Resolve the descriptor → build the key via `identity::account_key` (§2) → call
`CustodyHandle::invalidate` → map the error → return. No cache work, no lease
bookkeeping, no store access of its own.

---

## §4. The `expect(dead_code)` annotations to remove

### 4.1 Come off

Four, spanning the whole call chain in §3.1. The brief named the first two; the
store and storage frames are reached only transitively and are annotated too, so
they come off in the same change or the build stays red.

| # | Symbol | Annotation | Item | Gate |
|---|---|---|---|---|
| 1 | `CustodyHandle::invalidate` | `worker.rs:234-240` | `worker.rs:241` | `not(test)` |
| 2 | `AccountService::invalidate` | `service.rs:319-325` | `service.rs:326` | `all(not(test), not(kani))` |
| 3 | `PersonalAccountStore::revoke` | `mod.rs:518-524` | `mod.rs:525` | `all(not(test), not(kani))` |
| 4 | `storage::commit::revoke` (unix) | `commit.rs:472-478` | `commit.rs:479` | `all(not(test), not(kani))` |

**The gates are not symmetric, and the asymmetry is informative.** #1 is a bare
`not(test)`, so its `expect` applies under kani; #2–#4 add `not(kani)`, so theirs
do not. The service, store and storage revoke frames are therefore already live
under a kani proof harness today, while the custody handle is not — further
evidence for §3.1's claim that nothing in the chain is a placeholder. The
removal diff must not be assumed uniform; reviewers should read each site.

Possibly a fifth, depending on §2.4: the `IdentityBindingError` variant at
`identity.rs:66` carries `#[expect(dead_code, …)]` at `identity.rs:62-65` and is
constructed nowhere today. If the handler refuses an unconfigured `descriptor_id`
with it — as §2.4 proposes — that annotation comes off as a direct consequence of
this work. If instead the handler refuses earlier (descriptor lookup returns
`None` before any key construction), the annotation stays. **This is a decision
for design review**, not an implementation detail: it determines whether the
refusal vocabulary is the account module's or the handler's.

### 4.2 Stay — do not bulk-remove

`commit_grant_if` is untouched by self-revoke: `service.rs:338` and
`worker.rs:250` keep their annotations, as does
`PersonalAccountStore::commit_grant_if_unchanged` (`consent.rs:73-75`) and the
`RuntimeNotImplemented` variant (`identity.rs:52-56`). Likewise the remaining
`dead_code` sites at `service.rs:145`, `:164`, `:236`, `:248` and
`worker.rs:56`, `:76`, `:133`, `:190` are on other symbols. Connect is a separate
ticket (§7); an implementer who greps for the shared reason string and deletes
every match will light up the consent scaffolding with no caller.

### 4.3 Why removing them breaks nothing else — the argument

This is design-only, so no build was run; the argument is analytical and holds
without one.

The attribute is `expect`, not `allow`. An `expect` whose lint does not fire is
itself an `unfulfilled_lint_expectation` warning, and the repo gates on
`cargo clippy --all-targets -- -D warnings` (CLAUDE.md, Quality Gates). That
makes the annotation and the production caller **mutually forcing**:

* Remove the annotation without adding a caller → `dead_code` fires → red.
* Add the caller without removing the annotation → the expectation is
  unfulfilled → red.

There is no state in which one is wrong and CI is green, so "breaks nothing
else" is not a claim needing empirical support — it is enforced by the gate. Two
riders:

* The gates differ (§4.1), and removal deletes the whole `cfg_attr`, so every
  configuration converges on the same unannotated item. Convergence is the fix
  only if every configuration also gains the caller. It does not come free —
  see §4.4, which is a hard constraint on §1.2, not a footnote.
* Every current call site outside the module is a test file. Removing the
  annotations does not change test reachability — tests already compile these
  items without the `expect` applying, since each gate excludes `test`.

### 4.4 The caller must not be feature-gated

"Enforced by the gate" is true *per build configuration*, and CI builds many.
The `feature-combos` job (`.github/workflows/ci.yml:203-239`) runs
`cargo clippy <combo> -- -D warnings` over seventeen combinations, including
bare `--no-default-features` (`:216`), on library and binaries.

`personal_accounts` is declared unconditionally (`src/lib.rs:63`), so all four
items in §4.1 exist in every one of those builds. `src/gateway/ui` — and with it
`control_plane.rs` — is behind `#[cfg(feature = "webui")]`
(`src/gateway/mod.rs:31-32`). `webui` is a default feature (`Cargo.toml:179`), so
a handler placed there satisfies `--features default` and the `--all-features`
clippy job at `ci.yml:201`, and leaves `--no-default-features` with the
annotations gone and no caller. `dead_code` fires on all four frames. Red.

Two ways out. The design takes the first:

1. **Register the route outside the `webui` gate.** The `AppState` custody field
   is unconditional (`src/gateway/server/mod.rs:408` — no `cfg`), and the route
   literals in `src/gateway/router/mod.rs:217-321` are unconditional except the
   UI merge block at `:267-270`. A revoke route registered outside that block
   exists in every build carrying the HTTP transport, so one caller satisfies
   `dead_code` in every configuration at once. It is also the better product
   answer: disconnecting your own account belongs to the HTTP surface, not to an
   optional web UI. The handler body, the extractor and all of §2 are unchanged
   by the move — only the registration line differs.
2. **Narrow the annotations instead of removing them**, e.g.
   `cfg_attr(all(not(test), not(kani), not(feature = "webui")), expect(dead_code, …))`.
   Mutual forcing (§4.3) is preserved per configuration and CI stays green, but
   a triple-negative `cfg` on four frames reads worse than one unconditional
   route, and it ships a 4.0.0 in which the criterion's own surface is absent
   from every non-default build.

Kani is unaffected by the choice: `cargo kani` (`ci.yml:287-305`) builds with
default features, so a `webui`-gated caller exists there too, and annotation #1
— the only one whose `expect` applies under kani today — is satisfied either
way. `--no-default-features` is the single configuration this argument turns on,
and it is a blocking one.

**If review moves the route into `control_plane.rs` after all, §4.1 must move to
option 2 in the same change.** Route placement and annotation treatment are one
decision, not two.

---

## §5. Failure and edge behaviour

Two of the three cases already have known-good reference behaviour asserted at
store level. The new path must preserve it, which mostly means **not getting in
its way**.

### 5.1 Revoke during an in-flight refresh

Reference: `s08_a_stale_snapshot_cannot_land_after_a_durable_revoke`
(`src/personal_accounts/fence_tests.rs:105-128`). A refresh snapshots the grant
version before the provider call, exactly as a real refresh does (`:112`); the
revoke commits; the refresh response then arrives and
`store.refresh_tokens(&key, &staged, …)` returns `RefreshOutcome::Rejected`
(`:115-119`) — "a response that raced a durable revoke must not land". The
lookup afterwards is `AccountLookup::Revoked(version(&first))`, and the tombstone
"discloses the version it retired, unchanged" (`:120-124`). After reopening the
store, "restart resurrects neither the old token nor the rejected one"
(`:125-128`).

**What the new path must preserve:** the revoke does not wait for, cancel, or
coordinate with an in-flight refresh. It takes the authority lock, commits the
tombstone, returns. The losing refresh is rejected by the store's own version
fence, not by anything the handler does. Any design that polls for quiescence,
holds a lock across the provider call, or retries the revoke is wrong.

Ordering note: `CustodyHandle::invalidate` offloads onto the custody worker
(`worker.rs:241-245`), the same serialization every other custody operation uses.
The revoke is therefore ordered against refresh and release by the existing
worker, not by a new mechanism.

### 5.2 Revoke of an already-revoked grant

Reference: the store itself, `commit.rs:488-491`. Two early returns before any
IO — `None` when nothing was ever committed ("there is nothing to retire") and
`Some(entry) if matches!(entry.state, GrantState::Revoked)` ("Already
tombstoned: idempotent, and no IO").

**What the new path must preserve:** a second revoke succeeds. The handler
returns the same success it returns for the first. It must NOT look up state
first to decide — a check-then-act would reintroduce the TOCTOU the single
locked store call exists to remove, and would also let the endpoint disclose
whether a grant exists for a descriptor the caller has never connected. Revoking
a descriptor that was never connected is also a success, for the same reason.

### 5.3 Revoke then immediate re-consent

Reference: `s09_a_late_refresh_cannot_overwrite_a_newer_generation`
(`fence_tests.rs:132-160`). Revoke, then reconnect: "re-consent mints a new
generation over the tombstone, which is legitimate" (`:139-140`). A refresh
snapshotted against the retired generation is then `Rejected` — "a refresh
snapshotted against a retired generation must not apply" (`:145-149`).

**What the new path must preserve:** revoke leaves the account re-connectable.
It does not blocklist the key, does not write a terminal state, and the tombstone
does not bar a later `commit_grant` with a new generation. The revoke handler
therefore writes nothing beyond the tombstone `invalidate` already produces.

Caveat recorded honestly: this case cannot be exercised end-to-end today,
because no production connect path exists (§0.2). §6 pins it at store/service
level, which is where `s09` pins it too.

### 5.4 What revoke does NOT guarantee

Stated plainly so a reviewer does not have to find it.

**A response already on the wire is not recalled.** `revalidate` runs before a
cache entry may be selected and before egress
(`account_strategies.rs:545-548`), and the durable custody recheck is its last
step (`:607-630`). A revoke is therefore caught at the *next* dispatch's
recheck. A request that had already passed `revalidate` when the revoke
committed completes with the credential it was released. This is the existing
design of the recheck boundary, not a gap this work introduces.

**"No audit surface" means no NEW one.** The operator deferred an audit surface
for revoke. That is not licence to suppress the existing `audit_refusal` path
that fires when `revalidate` refuses (`account_strategies.rs:636`) or the
`AccountReleaseAudit` observer baked into `GatewayCustody`
(`src/personal_accounts/mod.rs:646`). Those are existing behaviour on other code
paths and stay untouched.

---

## §6. Test plan

Names and the rule each pins. No code, per the design-only gate. Suggested home
is a new `src/gateway/ui/account_revoke_tests.rs` for the handler tests, with the
store/service-level tests going beside their existing siblings.

### 6.1 The authorization rule (§2) — the load-bearing group

| Test | Pins |
|---|---|
| `self_revoke_builds_the_account_key_from_the_verified_identity_alone` | §2.1 — the key's principal fields equal the caller's `issuer`/`subject`; positive control that the path reaches the store |
| `a_revoke_naming_another_principal_in_the_body_still_revokes_only_the_callers_own` | §2.1 — extra body fields are inert; Bob's grant survives Alice's request carrying Bob's subject |
| `alices_revoke_leaves_bobs_grant_on_the_same_descriptor_connected` | §2 — two principals, one descriptor; the isolation that a mis-identified caller would break |
| `a_revoke_with_no_verified_identity_is_refused_and_commits_nothing` | §2.4 — `MissingVerifiedPrincipal`; store unchanged, proved by absence |
| `a_revoke_with_an_api_key_but_no_oidc_identity_is_refused` | §2.1 — no operator-token fallback for personal mode |
| `an_admin_caller_revoking_another_principal_is_refused_like_any_other_caller` | §2.3 — `is_admin` grants nothing here |
| `a_revoke_for_an_unconfigured_descriptor_is_refused_before_any_store_call` | §2.4 — descriptor resolution precedes custody; settles the §4.1 fifth-annotation question |

The first test is the positive control. Without it every refusal test above
could pass vacuously — a handler that refuses everything satisfies all six.

### 6.2 The four STORE.2 conjuncts and the edge cases (§5)

| Test | Pins |
|---|---|
| `a_self_revoke_tombstones_the_grant_durably_before_reporting_success` | §3.2 — conjunct: durable before success; survives a store reopen |
| `a_refresh_in_flight_when_a_self_revoke_commits_is_rejected` | §5.1 — the `fence_tests.rs:105` behaviour, reached through the new path |
| `a_second_self_revoke_of_the_same_grant_succeeds_without_io` | §5.2 — idempotency (`commit.rs:488-491`) |
| `a_self_revoke_of_a_never_connected_descriptor_succeeds` | §5.2 — the `None` arm; no existence disclosure |
| `a_revoked_account_can_be_re_consented_and_the_new_generation_holds` | §5.3 — store/service level only, see the note below |
| `a_late_refresh_against_the_retired_generation_is_rejected_after_re_consent` | §5.3 — the `fence_tests.rs:132` behaviour preserved |
| `a_dispatch_after_a_self_revoke_is_refused_at_revalidate_not_served_from_cache` | §3.2 — the revoke is observed by the recheck; no cache walk needed |
| `a_self_revoke_does_not_fall_back_to_the_gateway_held_credential` | §3.2 — refusal does not degrade into the legacy path; asserted by zero requests at a capture endpoint, the `account_rest_tests.rs:11-17` pattern |

**Coverage note, recorded rather than papered over.** The re-consent tests sit at
store/service level against `commit_grant`, not end to end, because no production
connect path exists (§0.2). An end-to-end connect→revoke→re-consent test is not
writable in 4.0.0 and is not named here. It belongs to the connect ticket.

### 6.3 Plumbing

| Test | Pins |
|---|---|
| `the_revoke_route_is_refused_when_custody_is_not_configured` | §2.4 — `AppState` field `None`; no panic, no silent success |
| `the_revoke_handler_writes_no_control_plane_audit_event` | §1.2 — the deferred admin path is not half-built here |
| `a_bearer_only_caller_with_no_oidc_identity_is_refused_not_downgraded_to_an_actor` | §1.2 — the `actor_from_client` fallback (`control_plane.rs:496-512`) is never reached from revoke |
| `an_end_user_oidc_credential_accepted_at_mcp_also_reaches_the_revoke_route` | §1.2 — reachability; the surface is not operator-only |

These last two follow the surface. If review selects option B, both are replaced
by the meta-tool equivalents and §2's tests carry over unchanged.

---

## §7. Out of scope — the deferred wider-revoke ticket

Explicitly NOT designed here, and a review finding if it appears in the
implementation:

1. **Admin revoke of another principal's grant.** No operator, admin or
   support-role path that revokes a grant the caller does not hold. §2.3 is the
   rule; a second code path that takes a principal id as input is the thing the
   operator deferred.
2. **Revoking by principal id, subject, email or any caller-supplied identity
   field.** The request body carries `descriptor_id` and nothing else (§1.3).
3. **A revoke audit surface.** No audit event type, no audit endpoint, no
   revoke entries in the control-plane audit log, no `ControlPlaneActor`
   construction. Existing refusal/release audit on other paths is untouched
   (§5.4).
4. **Bulk or cascading revoke.** No "revoke all my accounts", no revoke-by-
   descriptor across principals, no revoke-on-user-deletion hook.
5. **The connect / consent half.** `commit_grant_if` and
   `commit_grant_if_unchanged` keep their annotations (§4.2). Self-revoke does
   not need them and must not opportunistically wire them.
6. **Adding `invalidate` to the `AccountCustody` trait.** §1.1 — the trait's
   two-method shape is an asserted invariant; the concrete handle is carried
   instead.
7. **A meta-MCP tool for accounts.** §1.2 option B, with its README /
   `benchmarks/public_claims.json` / badge obligations, is deferred with the
   connect surface it would properly accompany.
8. **Listing a caller's connected accounts.** A read surface is a separate
   decision with its own disclosure questions; §5.2 deliberately avoids
   disclosing grant existence through revoke.

---

## Review checklist

* §2 is the section to review hardest. A revoke endpoint that mis-identifies the
  caller lets one user disconnect another; the claim that this is impossible
  rests on `identity.rs:76-96` and on the request carrying no principal field.
* §1.1's constraint — `AccountCustody` has no `invalidate` — is what decides the
  call site. An implementation that widens the trait has not followed this
  design.
* §4.1 lists four annotations, not the two in the brief, and asks one open
  question (the fifth, `identity.rs:62-65`) that review should settle.
* The second open question is the surface itself (§1.2). Option A is reachable
  by the right caller and is the smaller diff; option B puts the control where
  the user already is, at the cost of a documented drift update. §2, §3 and §5
  are identical under either. §4 is not: §4.4 ties route placement to annotation
  treatment, so whoever settles the surface settles that too.
* §4.4 is the one claim in §4 that a build would falsify rather than confirm.
  It says removing the four annotations while the only caller sits behind
  `webui` turns `cargo clippy --no-default-features -- -D warnings` red. Cheap
  falsifier, available to the implementer on day one: make the change, run that
  one command.
* §0 corrects two briefed premises. Both change what the doc can claim; neither
  changes the operator's scope.



