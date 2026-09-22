# MIK-6744.STORE.1 — 3.x credential migration path

**Status**: design, pre-implementation, **revised after a second review round
(two live seats) on 2026-09-21** — see §12.3 for what changed and why.
**Date**: 2026-09-21.
**Source ref for every citation**: `origin/docs/ranking-1-release-line` @ `1d8b5668`.
The shared checkout is behind that ref and carries a peer's uncommitted edits to
`crash_tests.rs` and `service_release_tests.rs`; nothing below was read from the
working tree.

**Evidence tags**: **V** verified by reading source at the ref · **I** inferred
from verified facts · **A** assumption needing confirmation.

---

## 1. The ruling this designs under

Operator ruling 2026-09-20: **build the migration path.** The criterion requires
3.x credential data to be readable *and* migrated; the shipped product says the
opposite in two places (`mod.rs:779`, `upgrade.rs:243`); the operator ruled the
product wrong and the criterion stands. Migrate-versus-rewrite is closed and is
not reopened here.

The overruled concern is carried forward as a constraint, not an objection: a
migration decrypts 3.x credentials and re-seals them into the per-principal
store, and that is a credential-handling path that exists only to run once.
Once-only paths get the least production exposure per line of risk they carry.
Re-authenticating would have bought fresh grants and left no stale 3.x refresh
tokens crossing a major version. The release owner weighed that and chose
migration. Everything in §7 (fail-closed), §10 (security) and §9 (falsifiers)
exists to buy down that specific cost.

## 1.1 HARD DEPENDENCY: the `sole` identity tier, and what this row delivers without it

**Escalated 2026-09-21 as its own decision. Stated here because it determines
whether STORE.1 can satisfy the operator's second ruling at all, and a reader
who reaches §5 without knowing it will design against the wrong target.**

The operator's words: *"and there needs to be a solo upgrade path. all our
current users are solo users."* A migrated credential is reachable only when
its declared principal authenticates: `AccountKey.principal_authority` and
`principal_subject` come from `VerifiedIdentity::issuer` and `::subject`
(`identity.rs:85-86`), and a `VerifiedIdentity` has exactly **two** production
producers — `key_server/oidc.rs:446` (a verified OIDC token) and
`gateway/openwebui_adapter.rs:421` (OpenWebUI's forwarded identity). Every
other construction in the tree is a test or a fixture (V, all 58 occurrences
classified by `cfg(test)` context on 2026-09-21, not inherited from a prior
count).

A solo 3.x install has neither producer. So today, on this row alone:

| | What a solo install gets |
|---|---|
| **Without the `sole` tier** | The migration runs, refuses nothing, and commits a grant that validates and is durable. The declared principal never authenticates, so no lease ever matches that `AccountKey`. The criterion's MIGRATED conjunct is satisfied on disk and **every current user gets nothing usable.** This is the same inertness §5.2(a) rejects the sentinel principal for — reached by a different route. |
| **With the `sole` tier** | The operator declares the solo principal, migration commits under it, and a request on a single-user gateway resolves to that same principal and leases the migrated grant. This is the only configuration in which STORE.1 delivers the ruling. |

**The tier is not in this row and must not be scoped into it.** It lives on
`origin/design/proof-tiered-principals` (@ `7325697b`) as 431 lines of design
plus a 15-line test-comment fix — **no implementation** (V). Its `sole` tier
would mint `principal_authority = "local"` and a fixed subject from
`auth.single_user: true`, which `upgrade.rs:144` already tells personal
gateways to set.

**Two binding consequences for this design:**

1. **The declaration is not free-text for the solo case.** §5.3 takes
   `principal_authority` and `principal_subject` from the operator verbatim.
   Where the deployment is solo, those two values MUST equal what the `sole`
   tier mints, or the migration recreates the inert-key failure with an
   operator's typo instead of a designed sentinel. Migration must therefore
   validate the declared pair against the tier's producer once that producer
   exists, and refuse a solo declaration that does not match. Until it exists,
   there is nothing to validate against.
2. **No falsifier in §9 proves the solo case, and none can be written yet.**
   F1 proves `lookup(key)` returns `Connected` — that the record is in the
   store, not that anyone can reach it. The solo acceptance test is
   *migrate, then authenticate as the solo principal, then lease* — and its
   middle step has no API. It is recorded as **F21** and is expected to fail
   to compile, not to fail an assertion, which is a different kind of red and
   is not counted as coverage.

**Until the `sole` tier decision lands, STORE.1's honest status is: the
mechanism is buildable and reviewable, and its user-visible value is zero for
the population the ruling names.** That is the decision being escalated, and it
is recorded here rather than resolved.

---

## 2. Citation corrections to the brief

The brief's anchors were approximate in four places. Implementation builds from
§8, so the corrected anchors are here rather than in a footnote.

| Brief said | Actual (V) |
|---|---|
| `credential_key()` at `client/mod.rs:114` | `:114` is the free fn `storage_key(backend_name, issuer)`. The method `credential_key` is declared at `client/mod.rs:382` and returns at `:386`. |
| count asserted at `upgrade.rs:1158` | `:1158` is a doc-comment line. The assert is `upgrade.rs:1161`, inside `notice_4_0_0_carries_all_five_items` at `:1160`. |
| notice text at `upgrade.rs:243` | `NOTICE_4_0_0_ITEMS` starts at `:242`; item 1's string literal spans `:243`–`:248`. |
| `legacy_migration` "written but never read" | **Wrong, and it changes input 3.** It *is* read: `commit.rs:285-288` reads it off the prior entry and `:299` writes it back into the replacement. It is a pure carry-forward with **no producer anywhere** — no site in the tree ever sets it to `Some`. `repair_tests.rs:179` seeds `None`. |

Unchanged and confirmed: `drop_credentials_from_other_issuer` at
`client/mod.rs:408` (V); storage load at `client/mod.rs:356` (V); `AccountKey` at
`personal_accounts/mod.rs:49` (V); `GrantRecord` at `:137` (V);
`legacy_migration` field at `:207` (V); `mod.rs:779` (V); `commit_grant_if` at
`service.rs:342` and `worker.rs:254` (V).

## 3. The read side is already covered — say so plainly

The row's own history frames the read side as hard. It is not, and the design
should not inherit that framing.

- The 3.x record is **plaintext JSON at mode 0600**. `TokenStorage::save` writes
  `serde_json::to_string_pretty` through an owner-only scratch file and renames
  it into place (`oauth/storage.rs:231-255`, comment at `:237-244`) (V).
  `seal_bytes`-style encryption belongs to the **new** per-principal store only.
- 4.0.0's `TokenInfo` parses a 3.x payload because `token_endpoint` (`:41-42`),
  `client_id` (`:45-46`) and `client_secret` (`:49-50`) are all
  `#[serde(default)]` (V).

  **Correction to a premise the brief and the existing test comment both
  carry**: these are **not** fields 4.0.0 added. `v3.5.1:src/oauth/storage.rs`
  declares the identical nine-field `TokenInfo`, `token_endpoint` /
  `client_id` / `client_secret` included, with the same `serde` attributes (V,
  read at tag `v3.5.1`). The old file parses because a v3.5.1 record that never
  populated those optional fields omits them, and `serde(default)` absorbs the
  omission — not because the schema grew. The inaccurate line is
  `upgrade_path_tests.rs:49-50` ("the exact field set v3.5.1 serialized, with
  none of the fields 4.0.0 later added"); `:76-78` is phrased correctly and
  needs no change, and every assertion in both tests is still right.

  This matters beyond pedantry: because `token_endpoint` is a **3.x** field, a
  real 3.x record may carry the endpoint its credential was actually issued
  against. §5.3a uses that as the issuer contradiction check.
- So migration is a **filename re-key, not unwritten decryption.** An earlier
  note in this row claimed otherwise and was corrected on 2026-09-14.

The barrier is the key, and only the key:

- v3.5.1 called `storage.load(backend_name, http_url)`. 4.0.0 calls
  `storage.load(&self.credential_key()?, &self.resource_url)`
  (`client/mod.rs:354-357`), where `credential_key` returns
  `storage_key(&self.backend_name, &meta.issuer)` = `backend_name + NUL + issuer`
  (`client/mod.rs:382-387`, `:114-116`) (V).
- `TokenStorage::storage_key` hashes `backend_name + ":" + resource_url` and
  takes the first 8 bytes (`oauth/storage.rs:178-185`) (V). A different first
  argument is a different SHA-256 is a different filename, so the 3.x file is
  never opened.
- `drop_credentials_from_other_issuer` (`client/mod.rs:408-423`) additionally
  clears in-memory token and registered client id across an issuer change (V).

**READABLE is already covered** as of 2026-09-18 by
`src/oauth/upgrade_path_tests.rs:80-107`
(`legacy_single_user_record_written_by_3_x_still_opens_on_4_0_0`), with its
sibling at `:118-149`
(`legacy_single_user_record_is_not_reachable_under_the_4_0_0_issuer_key`)
pinning the gap (V). **MIGRATED is the one remaining uncovered conjunct, and it
is all this design targets.**

## 4. The fact that reframes the whole write side

`start_custody` is **live in production**: called from
`src/gateway/server/mod.rs:855`, `:867` and `:876` (V). It builds the refresh
provider, then opens the store and claims both exclusive file locks
(`personal_accounts/mod.rs:697-720`) (V). The production *reader* path is
`VaultStrategy` → `AccountCustody::refresh_if_expired` / `release`
(`vault.rs:46-55`) (V).

But every durable **writer** into that store is dead code today. All of these
carry `expect(dead_code, reason = "per-user OAuth scaffolding, deferred to
post-4.0.0 backlog MIK-6744/6745/6746")` (V):

| Writer | Site | After this row |
|---|---|---|
| `PersonalAccountStore::commit_grant_if_unchanged` | `consent.rs:71-74` | **becomes live** — this row's caller |
| `PersonalAccountStore::commit_grant` | `mod.rs:486-492` | stays dead |
| `AccountService::commit_grant_if` | `service.rs:335-341` | stays dead (§7.1a) |
| `CustodyHandle::commit_grant_if` | `worker.rs:247-253` | stays dead (§7.1a) |
| `AccountService::invalidate` / `PersonalAccountStore::mark_reconnect_required` | `service.rs:319-325`, `mod.rs:547-553` | stay dead |

**Therefore: this migration is the first production writer into the
per-principal store, and `commit_grant_if_unchanged` (`consent.rs:75`) is the
single entry point through which it arrives.** (I, from the V above.) That is
the most consequential sentence in this document. It sets the top of the blast
radius (§8) and the top of the security section (§10): this is the first code
that can corrupt that store in the field, which is why §9.3's crash falsifier
uses the existing nine-boundary harness rather than trusting the new path.

The service and worker wrappers staying dead is deliberate, not an oversight —
§7.1a explains why an offline migration must not route through them, and §8.1
records that removing their attributes without adding a caller would itself
fail the build.

---

## 5. THE ATTRIBUTION DECISION

### 5.1 Why this is the hard problem

The destination `AccountKey` (`personal_accounts/mod.rs:49-55`) is keyed on five
fields: `principal_authority`, `principal_subject`, `backend_id`, `resource`,
`oauth_issuer` (V). A `GrantRecord` (`:137-149`) additionally requires
`generation`, `token_revision`, `authorization_epoch`, `descriptor_revision`,
`client_id` (V).

A 3.x `TokenInfo` (`oauth/storage.rs:20-51`) carries **none** of the principal
fields and **none** of the generation fields, and its file is keyed on
`backend_name` and `resource_url` alone (`:178-185`) (V). Migration must
therefore produce an attribution it has no source for.

The rule it must produce it under is not a convention, it is written doctrine.
`identity.rs` is the module that says what may become an account key:

> `account_key(identity: Option<&VerifiedIdentity>, descriptor: &AccountDescriptor)`
> — "No verified principal, no account. Nothing is inferred from the request,
> and there is no anonymous or operator-token fallback for personal mode."
> (`identity.rs:76-95`, header at `:8-24`) (V)

`principal_authority` ← `VerifiedIdentity::issuer`, `principal_subject` ←
`VerifiedIdentity::subject` (`identity.rs:85-86`), and a `VerifiedIdentity` is
produced in production only by OIDC token verification
(`key_server/oidc.rs:446-452`) and the OpenWebUI adapter
(`gateway/openwebui_adapter.rs:421`) (V). There is no synthetic or single-user
identity producer anywhere in the tree (V).

So the test every candidate must pass is one question: **is the principal
verified, or is it inferred by the gateway?**

### 5.2 Candidates, each with its failure mode

**(a) Sentinel principal.** Mint `principal_authority =
"urn:mcp-gateway:legacy-3x"`, `principal_subject = "single-user"`.
*Failure mode*: fatal, twice over. It is exactly the inference `identity.rs:8-24`
forbids — an invented authority inside the isolation boundary. And it is inert:
a real user's key carries `principal_authority = VerifiedIdentity::issuer`, so
the sentinel key is one no lease can ever match (I, from `identity.rs:85-86` +
`vault.rs:46-55`). It would satisfy MIGRATED on paper and deliver nothing.
**Rejected.**

**(b) Lazy first-presenter binding.** Stage the 3.x credential unattributed and
bind it to the first principal that presents a verified identity for that
backend/resource/issuer. *Failure mode*: fatal. In any multi-user 4.0.0
deployment the first person through the door captures the operator's 3.x refresh
token. That is precisely the cross-principal credential handover the module
exists to prevent. **Rejected.**

**(c) Derive the principal from 3.x config.** Read the old `gateway.yaml` and
synthesize a principal from whatever it named. *Failure mode*: 3.x
single-user mode records no OIDC issuer or subject for the operator — there is
nothing in a 3.x config to derive `VerifiedIdentity::issuer` / `.subject` from
(V: `config/features/auth.rs:44` is a bare `single_user: bool`). The derivation
would have to invent at least one of the two fields, which collapses into (a).
**Rejected.**

**(d) Operator-declared principal, no declaration no migration. — CHOSEN.**

### 5.3 The decision

**Migration runs only from an explicit operator declaration, and takes the
principal from it verbatim.**

The operator writes, per legacy backend being migrated, a block naming:

| Declared field | Consumes | Why it must be declared |
|---|---|---|
| `principal_authority` | → `AccountKey.principal_authority` | The gateway has no verified source. A human asserts it. |
| `principal_subject` | → `AccountKey.principal_subject` | Same. |
| `descriptor_id` | → `AccountKey.backend_id` | `backend_id` is the `accounts.descriptors` **map key** (`identity.rs:38-39`), not the backend registry name (V). |
| `legacy_backend_name` | → the 3.x filename hash | The 3.x file is hashed over the **registry** name (`oauth/storage.rs:178-185`); `config::AccountDescriptor` (`config.rs:255-292`, the whole struct) carries `mode`, `provider`, `resource`, `issuer`, the four endpoints, `client_id`, `client_secret_ref`, `redirect_uri`, `scopes`, `send_resource_parameter` and `external_strategy` — and **no legacy name** (V, verified across the full field list, not just the first three). Without this, migration cannot even find the file. |

`resource` and `oauth_issuer` are **not** declared as free text — they are read
from the already-configured descriptor the `descriptor_id` names
(`config.rs:261`, `:263`; bound the same way at `identity.rs:88-89`) (V). But
taking the issuer from the destination descriptor is **not** by itself safe, and
§5.3a is the part of this decision that earns the "sound" verdict.

### 5.3a The issuer binding must be attested and contradiction-checked

**The defect this closes** (raised by design review 2026-09-21, confirmed at
source): a 3.x record carries no issuer. If the operator re-pointed that backend
to a different authorization server between 3.x and 4.0.0, silently adopting the
destination descriptor's issuer would migrate a refresh token issued by server A
into an account key that names server B — and the gateway would then present it
to B. That is precisely what `client/mod.rs:105-107` records as an MCP
2026-07-28 **MUST NOT** ("a client MUST NOT reuse persisted credentials with a
different authorization server") (V), and what
`drop_credentials_from_other_issuer` (`:408-423`) exists to prevent in memory.
A migration that re-introduced it would undo the very property this release
shipped.

Three requirements, all cheap:

1. **Attestation.** The declaration must carry an explicit
   `legacy_issuer` the operator asserts the 3.x credential was issued by.
   It is not defaulted from the descriptor. Migration refuses if it is absent.
2. **Contradiction check against the record.** If the 3.x `TokenInfo` carries a
   `token_endpoint` (a genuine 3.x field, §3), and that endpoint's origin does
   not match the attested issuer's origin, **refuse this backend**. This is
   evidence the record itself supplies, and it costs one comparison (V that the
   field exists at `oauth/storage.rs:41-42` in both v3.5.1 and 4.0.0; I that
   origin comparison is the right granularity — see O5).
3. **Equality with the destination.** Refuse unless `legacy_issuer` equals the
   destination descriptor's `issuer`. If they differ, the correct outcome is
   re-authentication, not migration — the credential genuinely belongs to a
   different authorization server, and no attestation can make it portable.

Requirement 3 makes the migration *conservative by construction*: it only ever
migrates a credential into the same authorization server it came from. This is
also what makes a migrated grant refreshable at all — `provider.rs:300-301`
refuses any refresh where `account.oauth_issuer != descriptor.issuer`, with the
comment "a descriptor that has since been pointed elsewhere is a different
authorization, not this one" (V). The provider already enforces this rule at
refresh time; migration must not create records that trip it.

### 5.4 What makes the pick safe

1. **It does not violate the doctrine, it respects its shape.** `identity.rs`
   forbids the *gateway* inferring a principal, and every prohibition it writes
   is framed on the **request** path: "Nothing is inferred from the request",
   "No request body, query, header or state possession contributes", "A caller
   with no verified principal gets a refusal" (`identity.rs:8-24`, `:80-81`)
   (V). An offline operator declaration is not a request. It is an operator act
   with a name on it, the same category as `initialize` being offline and
   explicit (`mod.rs:786-790`) — not a runtime inference. (I)

2. **But it bypasses the constructor, and that cost is named here rather than
   argued away.** `account_key` (`identity.rs:76-95`) is the single site that
   builds an `AccountKey`, and its doc states the design intent plainly:

   > "Five fields, five sources, nothing else. `email`, `name` and `groups` are
   > never read — not by omission but by construction: they are not mentioned
   > below, so no future edit can quietly admit one without appearing in a
   > diff." (`identity.rs:73-75`) (V)

   The guard that sentence describes is **one auditable diff site**: any future
   attempt to admit a sixth source has to edit `account_key` and show up in
   review. Migration admits a sixth source — an operator declaration — and it
   does so by **not going through `account_key` at all**, because that function
   requires a `VerifiedIdentity` migration does not have.

   So this design gives up the single-diff-site property for this one path.
   That is a real cost, not a technicality, and it carries two obligations:

   - The migration must construct its `AccountKey` at **exactly one** site,
     inside `personal_accounts`, so the bypass has its own single auditable
     location rather than being scattered.
   - That site must carry a comment pointing at `identity.rs:73-75` and stating
     why it is not using `account_key` — so the next auditor finds the
     exception where they look for it, instead of concluding the constructor is
     still the only way an `AccountKey` comes into being.

   Listed in §8.3 as a construct with this constraint attached.

3. **No declaration, no migration.** This is also the complete answer to
   "can an attacker induce migration?" (§10.5). Nothing scans the credential
   directory; migration only ever resolves the one filename the declaration's
   `legacy_backend_name` plus the descriptor's `resource` hash to. One
   mechanism, two requirements satisfied.
4. **It cannot overwrite anyone.** The commit is guarded on
   `ConsentExpectation::Absent` (§7). A principal who has already authorized
   normally is `Connected`; a revoked one is `Revoked`; both fence the migration
   without writing (V: `consent.rs:96-100`).
5. **The blast radius is bounded by what 3.x already exposed.** The credential
   being migrated was a shared single-user operator token in 3.x. A misdeclared
   subject hands it to one named principal instead of to every caller of that
   gateway — strictly narrower than the status quo ante. (I)

### 5.5 The risk it carries, stated plainly

**A wrong `principal_subject` in the declaration silently attributes a live
refresh token to the wrong person, and nothing in the system can detect it.**
There is no verification step available — that is the whole reason the field is
declared rather than derived. The mitigations are that the declaration is
explicit, auditable, and provenance-marked in the store (§6), and that the
migrated grant lands `Absent`-guarded so it can never displace a real one. The
residual risk is the operator's own typo, and it is accepted here rather than
engineered away, because engineering it away requires a verified principal that
by construction does not exist at migration time.

---

## 6. INPUT 3 — `legacy_migration` becomes the real path. It is not deleted.

This is a decision, and it goes **use it**, with a correction to the premise.

The brief calls the field dead. It is not dead, it is **producerless**: it has a
reader that carries it forward across every replacement
(`commit.rs:285-288` reads it off the prior entry, `:299` writes it back), and
no site in the tree ever produces a `Some` (V, §2). That distinction decides the
call, because the carry-forward semantics already in place are *exactly* the
semantics a migration provenance marker needs.

**Decision**: migration sets `legacy_migration` to `Some` of the 3.x source
file's basename on the grant it commits — **and this requires provenance
plumbing that does not exist today.** §6.1 is that cost, stated up front rather
than discovered in implementation.

### 6.1 The plumbing the decision requires — confirmed gap

Design review 2026-09-21 caught this and it is **certain**, verified at source:
**the guarded commit cannot set `legacy_migration` today.**

`commit_grant_if_unchanged` calls
`storage::commit::commit_grant(&config, &mut authority, account, record)`
(`consent.rs:102`), whose signature takes no provenance argument
(`commit.rs:390`). Inside, `stage_publication` derives the field **only** by
copying it off the entry that already exists (`commit.rs:285-288`) and writing
it back (`:299`) (V). On a first migration there is no prior entry, so the copy
yields `None`. **Every first migration would land with the marker absent** —
exactly the grant the marker exists to label.

So §6's decision is not free. It costs:

- a provenance parameter threaded through `commit_grant` (`commit.rs:390`) into
  `stage_publication` (`commit.rs:250-256`), replacing the carry-forward at
  `:285-288` with "use the supplied value, else carry forward";
- the same parameter on `commit_grant_if_unchanged` (`consent.rs:75-80`) and on
  the non-unix arms (`consent.rs:81-87`, `commit.rs:593`);
- **both** call sites of `commit::commit_grant` — `consent.rs:102` (passes the
  migration's provenance) and `mod.rs:501` (passes `None`). Those two are the
  only callers in the tree (V). Full table in §8.3.

These are listed in §8.3 as new constructs, not hidden here.

**The decision stands despite the cost**, because the alternative is worse in a
specific way: committing migrated grants *indistinguishable* from user-consented
ones, on a path whose acknowledged residual risk (§5.5) is misattribution. A
misattributed grant that cannot be identified as migrated is a misattribution
nobody can later audit or unwind. The plumbing is four signatures; the
alternative is an unauditable credential provenance gap.

**If the owner rejects the plumbing**, the honest fallback is to delete the
field (four sites, §6.2) rather than ship it set to `None` forever — a marker
that is always absent is worse than no marker, for exactly the reason input 3
gives.

### 6.2 Why this and not deletion

1. **The carry-forward is already correct for the refresh case.** Once the
   marker is set, a migrated grant that later refreshes stays labelled:
   `commit.rs:285-299` preserves it with no new code (V). The plumbing in §6.1
   is needed only for the *initial* set, not for every subsequent write.
2. **It answers an audit question nothing else can.** With it, an auditor can
   tell a grant the user consented to from a grant the operator asserted on the
   user's behalf (§5.5's residual risk). Without it, those are indistinguishable
   on disk, which is a poor place to be given §5.5.
3. **The brief's own warning cuts this way.** "Leaving a dead field named for the
   feature is how the next audit concludes the feature exists." The fix for that
   is to make the feature exist, which is what the operator ruled.

**Deletion, if the owner rejects §6.1's plumbing**, is four sites, not one:
`mod.rs:207` (the field), `commit.rs:285-288` (the read), `commit.rs:299` (the
write-back), `repair_tests.rs:179` (the `None` seed). Costed so the choice is
informed, not so migrate-versus-rewrite is reopened.

`AuthorityEntry` is `#[serde(deny_unknown_fields)]` (`mod.rs:198`) and the
field is already `Option<String>`, so setting it produces no manifest schema
change and no compatibility break for a manifest written before this ships (V).

---

## 7. MECHANISM

### 7.1 Shape

One offline command, in the existing `commands/upgrade.rs` family, reached only
from an explicit operator declaration (§5.3). It is **not** reached by daemon
startup — `serve` opens an existing authority or fails (`mod.rs:786-790`), and
that property is preserved.

Per declared backend, in order:

1. **Read** the 3.x record via the existing
   `TokenStorage::load(legacy_backend_name, resource)`
   (`oauth/storage.rs:194-224`). No new reader, no new parser (V).
2. **Recover `client_id` from three sources, in precedence order** — and note
   §7.1b, because recovering it is *not* what makes the grant refreshable:
   a. the 3.x backend's **operator-configured** `client_id`, if the 3.x config
      set one. This source was missing from the first draft and its absence
      would have **certainly** refused every preconfigured-client install:
      `restore_persisted_client_id` is a no-op when a `client_id` is already
      set, and its comment states that only happens when
      `OAuthClientConfig.client_id` was supplied, i.e. operator config
      (comment at `client/mod.rs:389-398`, guard at `:425-428`) (V). Such an
      install has **no**
      `_client.json` and **no** `client_id` in the token file, so the other two
      sources both miss.
   b. `TokenStorage::load_client_id(legacy_backend_name, resource)`
      (`oauth/storage.rs:295-313`) — a prior Dynamic Client Registration.
   c. `TokenInfo.client_id` (`oauth/storage.rs:45-46`).

   Refuse the backend if all three miss. **Disagreement is resolved by
   precedence, not by blanket refusal — corrected 2026-09-21 second review
   round.** An install that used Dynamic Client Registration in 3.x and was
   later given an operator `client_id` legitimately holds both, and they
   legitimately differ: `restore_persisted_client_id` is a no-op once a
   configured id is set (`client/mod.rs:425-428`), and
   `drop_credentials_from_other_issuer` deliberately keeps a configured id
   because "a configured client id belongs to the operator rather than to
   an issuer" (`client/mod.rs:408-423`) (V). A blanket refusal would refuse
   that install and force a re-authentication the row exists to avoid. So:
   **(a) wins over (b) and (c)**, and a disagreement between (a) and either
   of the others is reported, not refused. A disagreement between (b) and
   (c) — two disk records that should agree — IS a refusal, because neither
   has authority over the other.
   `GrantRecord.client_id` is a non-`Option` `String` (`mod.rs:148`) (V).

### 7.1b `client_id` recovery does not make the grant refreshable — a precondition does

**Confirmed at source, and it corrects a natural assumption.** The production
refresh provider does **not** use `GrantRecord.client_id`. It reads
`descriptor.client_id` (`provider.rs:303`) and refuses with `Unavailable` if it
is absent (V). It likewise takes the token endpoint from the *pinned* bootstrap
snapshot, never from the record (`provider.rs:314-319`) (V).

So recovering the record's `client_id` gives a complete, validating
`GrantRecord` — nothing more. **A migrated grant is refreshable only if the
destination descriptor independently carries the same client registration (and
whatever secret reference it needs).**

**Requirement**: migration must refuse a backend whose destination descriptor
has no `client_id`, and must refuse when the descriptor's `client_id` differs
from the recovered legacy one. Migrating into a descriptor that will fail its
first refresh produces an account that looks connected and cannot work — the
worst of both outcomes, because the user is not prompted to re-authenticate
either. F13 (§9.5) is the falsifier.
3. **Build** the `AccountKey` (§5.3) and the `GrantRecord` (§7.2).
4. **Commit** the guarded write with `ConsentExpectation::Absent` — see §7.1a for
   which of the two entry points, because the brief's assumption does not hold.
5. **Never** touch the 3.x file. Not read-and-delete, not truncate, not re-key.

### 7.1a Which commit entry point — a correction to the brief

The brief states the migration "must land through `commit_grant_if`
(`service.rs:342`, `worker.rs:254`)". Taken literally that is achievable but
wrong for an offline command, and it changes the blast radius, so it is resolved
here rather than assumed.

`AccountService::new` requires `P: RefreshProvider` and
`O: CredentialReleaseObserver` (`service.rs:223-231`, struct at `:207-221`) (V).
`CustodyHandle::start` requires the same plus a capacity (`worker.rs:109-114`)
(V). The only production `RefreshProvider` is `GatewayRefreshProvider`
(`mod.rs:608-612`), and building it goes through
`PersonalOAuthRefresh::bootstrap`, which is `async` and **fetches, validates and
pins every managed descriptor's issuer metadata over HTTP before the store is
touched** (`mod.rs:697-711`, contract stated at `:572-575`) (V).

So routing an offline migration through `commit_grant_if` would give a
credential-migration command a network dependency it has no use for: it never
refreshes anything, and a run would fail if the issuer were unreachable even
though the migration is pure local filesystem work.

**Decision: commit through `PersonalAccountStore::commit_grant_if_unchanged`
(`consent.rs:75-105`) directly.** It needs only an open store — no provider, no
observer, no tokio worker, no HTTP — and it is the primitive that actually
carries the guarantee this design depends on: comparison and publication under
one authority-lock acquisition (`consent.rs:16-19`, `:96-100`) (V).
`commit_grant_if` at `service.rs:342` is a thin delegation to exactly that call
(`service.rs:348-358`) (V), so nothing is lost but the provider requirement.

**Blast-radius consequence**: `service.rs:335-341` and `worker.rs:247-253` keep
their `expect(dead_code)` and stay dead until the MIK-6745/6746 consent journey
wires them in. Of the dead-code attributes, only `consent.rs:71-74` comes off.

**This is not the whole radius, and §7.1a is not a claim that the row is
cheap.** §6.1's provenance plumbing independently touches `commit_grant` and
its callers. What the direct-store route buys is narrower and specific: two
fewer attribute removals, and no async HTTP bootstrap on an offline path. §8.3
carries the full list.

If the row instead insists on the service/worker route, the cost is explicit:
two more attributes come off **and** an offline command acquires an async HTTP
bootstrap. That is a worse trade and should be an owner decision, not a default.

### 7.2 Field construction, and what each seed is answerable to

`validate_record` (`storage.rs:127-145`) is the binding contract (V). Every seed
below is chosen to satisfy it, and the right-hand column quotes it.

| `GrantRecord` field | Source | Must satisfy (V) |
|---|---|---|
| `access_token` | `TokenInfo.access_token` | non-empty, ≤ 65536 (`storage.rs:128-129`) |
| `refresh_token` | `TokenInfo.refresh_token` | if `Some`, non-empty ≤ 65536 (`:130-133`) |
| `token_type` | `TokenInfo.token_type` (3.x defaults `"Bearer"`, `oauth/storage.rs:25-26`, `:53-55`) | — |
| `expires_at` | **see §7.2a — `unwrap_or(0)` was wrong and is withdrawn** | not validated (`storage.rs`, no rule) |
| `scopes` | `TokenInfo.scope` split on whitespace, sorted, deduped — **but an ABSENT `scope` is not an empty set; see §7.2a** | strictly ascending: `scopes.windows(2).any(pair[0] >= pair[1])` rejects (`:138`) |
| `provider_account_id` | `None` | `Option`, unconstrained |
| `client_id` | §7.1 step 2, else refuse | non-`Option` `String` (`mod.rs:148`) |
| `generation` | `commit::random_hex()` — 16 random bytes, 32 hex chars (`commit.rs:67-73`) | `lower_hex(.., 32)` (`storage.rs:134`) ✓ exactly |
| `token_revision` | `1` | `!= 0` (`:136`) |
| `authorization_epoch` | `1` | `!= 0` (`:137`) |
| `descriptor_revision` | **see §7.3 — open (A)** | `lower_hex(.., 64)` (`:135`) |

### 7.2a Two seeds that can make a working 3.x grant STOP working — designed, not defaulted

**Raised by design review 2026-09-21 (second round), confirmed at source, and
this is the most serious class of defect in the row.** A migration that fails is
recoverable: the 3.x file is untouched (§7.4) and the operator re-runs or
re-authenticates. A migration that *succeeds* and leaves the user with a
credential that worked before the upgrade and does not work after it is worse
than never migrating at all, because it consumes the one outcome the operator
ruled for and delivers the outcome the ruling was meant to avoid. The first
draft of §7.2 shipped two of these, both by taking a default instead of making
a decision.

#### (a) `expires_at` — `unwrap_or(0)` kills an access-only grant

**The mechanism, verified at source.** `AccountService` refreshes anything it
finds expired (`service.rs:272-277`), and the refresh provider refuses outright
when the record carries no refresh token:
`current.refresh_token.as_deref().ok_or(ProviderRefreshError::Unavailable)?`
(`provider.rs:307-311`) (V). So for a 3.x record with **no `expires_at` and no
`refresh_token`**, seeding `expires_at = 0` produces a grant that is
permanently expired and permanently unrefreshable. That same access token was
usable in 3.x until its real expiry.

The first draft called `0` "fail-closed by choice". It is fail-closed only for
a record that *has* a refresh token; for one that does not, it is fail-dead.
The rule was written against the refreshable case and never tested against the
other.

**Designed behaviour**, replacing `unwrap_or(0)`:

| 3.x record | `expires_at` seed | Why |
|---|---|---|
| `expires_at` present | that value, verbatim | The record carries the real lifetime. Nothing is invented and nothing is discarded. |
| absent, `refresh_token` present | `0` | The original intent, and correct here: expired-on-arrival forces one refresh before first use rather than handing out a token whose remaining life the record never stated. The refresh can succeed, so nothing is lost. |
| absent, `refresh_token` absent | **refuse this backend** | There is no honest seed. `0` kills it; any positive value is a lifetime the gateway invented for a live credential. Refusal leaves the 3.x file in place and the operator re-authenticates once — the 4.0.0 behaviour they were already promised (`upgrade.rs:243-248`). |

Refusal, not migration-with-a-warning: a grant that looks `Connected` and
cannot work is the failure mode §7.1b already refuses for a descriptor with no
`client_id`, and it is refused here for the same reason. The user is not
prompted to re-authenticate, so nothing recovers them.

#### (b) `scopes` — an absent `scope` becomes an empty set that refuses its own refresh

**The mechanism, verified at source.** `AccountService::apply` weighs a refresh
response's scope list against the stored one:

```
let mut scopes = rotated.scopes.unwrap_or_else(|| current.scopes.clone());
...
if scopes.iter().any(|scope| !current.scopes.contains(scope)) {
    return Err(AccountServiceError::ScopeBroadeningRefused);
}
```

(`service.rs:393-400`) (V). If `current.scopes` is **empty**, then every scope
the authorization server names in its refresh response is a scope the stored
grant does not contain, so the first refresh that reports any scope at all is
rejected as broadening — a consent the user never gave. `TokenInfo.scope` is
`Option<String>`, and a 3.x record that never recorded a scope is ordinary, so
"split the scope string" silently produces the empty set for a real and common
input.

**Designed behaviour:**

| 3.x record | `scopes` seed | Why |
|---|---|---|
| `scope` present | split, sorted, deduped as before | Unchanged; this was always right. |
| `scope` absent, destination descriptor declares `scopes` | the descriptor's `scopes`, sorted and deduped | The operator has already declared what this backend is authorized for, and a refresh response matching that declaration is then not a broadening. This attributes scopes the record did not carry, so it is recorded as an attribution, not a recovery. |
| `scope` absent, descriptor declares none | **refuse this backend** | Nothing names the grant's scopes, so any seed is invented and the empty set is actively harmful. |

The middle row is the only place in this design that fills a `GrantRecord`
field from the destination rather than the source, and it is doing so because
the alternative is a grant that breaks on first refresh. It is narrower than
it looks: §5.3a already requires the legacy and destination issuers to be
equal, so the descriptor's scopes describe the same authorization server the
credential came from.

**Both refusals are per-backend**, in the same shape as §7.1 step 2's
`client_id` refusal: the run continues, other declared backends still migrate,
and the refused one reports why. §7.5's fail-closed property is unchanged,
because a refused backend never reaches the commit.

**Falsifiers** (join §9.5): F18 — a 3.x record with no `expires_at` and no
`refresh_token` is refused, and `lookup` is `Absent`; F19 — a record with no
`expires_at` but WITH a refresh token migrates and seeds `0`; F20 — a record
with no `scope` against a descriptor declaring scopes migrates with the
descriptor's scopes, and the same record against a descriptor declaring none
is refused. Each pair is two-directional on purpose: F19 and F20's first leg
are the positive controls that stop F18 and F20's second leg passing for a
migration that refuses everything.

### 7.3 `descriptor_revision` has no producer — RULED, and the first spec was wrong

**OPERATOR RULING 2026-09-21:** *"if we don't calculate the fingerprint, it is
another development gap we need to fix."* Option (ii) is declined. STORE.1
defines the producer. The binding condition in the recommendation below stands.

Grepped across the whole tree at the ref: every non-test occurrence of
`descriptor_revision` is a field copy (`service.rs:128`, `:183`, `:193`;
`commit.rs:295`), a comparison (`commit.rs:433`, `:450`, `:564`;
`storage.rs:622`) or a validator (`storage.rs:135`, `:481`). **No production
site computes one.** Every fixture uses `"0".repeat(64)` (V).

#### The originally proposed field set is redundant with the key

The first version of this section proposed SHA-256 over the descriptor's
`provider`, `resource` and `issuer`. **Two of those three are already in
`AccountKey`** (V, `src/personal_accounts/mod.rs:49-53`):

```
AccountKey = principal_authority, principal_subject, backend_id, resource, oauth_issuer
```

If `resource` or `issuer` changes, the **key** changes, the old record is never
found, and no fence is needed. Hashing them into the revision therefore adds
nothing the key does not already do — and leaves the revision blind to every
change that keeps the key intact.

**The concrete defect that spec would have shipped (I, mechanism verified — but see the correction below: the remedy does not work either):** an
operator widens `scopes` on an existing descriptor, read-only to read-write. The
key is unchanged, so every stored grant still resolves. The revision is
unchanged, so `commit.rs:433` never fences. Every user keeps a token carrying
the **old, narrower** scopes while the gateway's configuration asserts the new
ones, and nothing anywhere reports the mismatch.

#### The revision must cover what the key cannot see

The field exists to detect a descriptor change the key is blind to. That is
exactly the set of fields that can change while the key stays byte-identical
(V, `src/personal_accounts/config.rs:255-292`):

| Field | Why a change must fence |
|---|---|
| `scopes` | **The security-critical one.** A widened scope leaves a narrower token in place while config claims otherwise |
| `client_id` | Tokens minted by a different registered application would keep being used |
| `client_secret_ref` | The credential backing the client changed |
| `token_endpoint` | Refresh would target an endpoint the grant did not come from |
| `authorization_endpoint` | The grant was obtained somewhere else |
| `revocation_endpoint` | Revocation would be sent where the grant does not live |
| `redirect_uri` | Part of the registered client contract |
| `mode` | `personal_managed` / `shared` / `external` change the custody model outright |
| `send_resource_parameter` | Alters the token request; `Option<bool>` because "declared false" and "not declared" are distinct |
| `external_strategy` | Carries the endpoint, audience and session rules for `external` mode |

**Excluded, because `AccountKey` already discriminates them:** `resource`,
`issuer`. Including `provider` is harmless and nearly free, but on its own it is
not a fingerprint.

**`client_secret_ref` is a reference (`env:VARIABLE`), never the secret** —
`config.rs:272-274` states the reference deliberately stays a reference so no
secret is materialised into a serialized or `Debug`-rendered configuration.
Hash the reference string. **Never resolve it and never hash a resolved value.**

#### Construction

Unchanged in shape, corrected in inputs: SHA-256 over the existing versioned
length-prefixed encoding — `encode_fields` (`storage.rs:51-58`) under a fresh
domain tag — over the field set above, hex-encoded. 64 lowercase hex by
construction, which is what the validator at `storage.rs:135` and `:481`
demands.

This still satisfies both fence tests, and satisfies them for the right reason:
`o4_an_unchanged_descriptor_revision_does_not_fence` (`fence_tests.rs:184`
onward) holds because the encoding is deterministic over unchanged inputs, and
`o4_a_changed_descriptor_revision_fences_the_grant_durably`
(`fence_tests.rs:162-182`) now holds for the changes that actually matter rather
than only for a change that would have moved the key anyway.

#### THE FENCE THIS SECTION WAS WRITTEN FOR DOES NOT EXIST — corrected 2026-09-21, second review round

**This correction is load-bearing and it invalidates the argument above, not
just its field set.** The section justified its corrected field set with a
worked example: an operator widens `scopes`, the `AccountKey` is unchanged so
every stored grant still resolves, "the revision is unchanged, so
`commit.rs:433` never fences". The remedy proposed was a better fingerprint.
That remedy does not work, because **no site in the tree compares a live
descriptor's fingerprint to a stored `descriptor_revision`** (V, every
occurrence re-read):

| Site | What it actually does |
|---|---|
| `commit.rs:295` | copies the field onto the replacement entry |
| `commit.rs:433` | `record.descriptor_revision != expected.descriptor_revision` — **both supplied by the caller**; a caller-consistency check, not a config check |
| `commit.rs:450-455` | compares the STORED entry to the version the caller captured — optimistic concurrency |
| `commit.rs:514`, `:522`, `:564`, `:627` | the same shape for revoke / reconnect / repair |
| `service.rs:79`, `:128`, `:183`, `:193` | field copies into `GrantVersion` / `CredentialLease` |
| `storage.rs:135`, `:481` | format validators (`lower_hex(.., 64)`) |
| `vault.rs:226-227` | renders the value into a propagation string |

Every one is a copy, a validator, or a comparison of two values that both
originate from stored records. The live `AccountDescriptor` is never
fingerprinted and never compared. So a widened `scopes` is not fenced today,
and **computing a perfect fingerprint at migration time does not fence it
either** — the value would be correct and nothing would ever read it against
the configuration it describes.

**What the fence would actually require**, and it is not in this row: a
comparison site on the read path — `AccountService` before release, or
`GatewayRefreshProvider` before refresh — that computes the current
descriptor's fingerprint and refuses, or marks reconnect-required, when it
differs from the stored one. That is a new production behaviour with its own
user-visible consequence (every affected user is asked to reconnect after a
config edit), and it belongs to the consent journey that owns the read path,
not to a one-time offline migration.

#### What STORE.1 therefore does about `descriptor_revision`

**RULED 2026-09-21: compute it.** That ruling stands and is implemented as
specified above — the versioned length-prefixed encoding over the field set in
the table, hex-encoded, 64 lowercase hex by construction. What changes is only
the claim made for it:

- **What it buys now**: a `GrantRecord` that validates (`storage.rs:135`), and
  a value that is *ready* for a fence when one is built. Nothing else.
- **What it does NOT buy**: any detection of a descriptor change. This section
  previously implied otherwise, and a reader who believed it would conclude a
  widened `scopes` is now caught. It is not.
- **The coupling condition is unchanged and still loud**: whatever MIK-6745/6746
  computes for `descriptor_revision` must be the **same function**, not a
  reimplementation. If it computes a different value, `commit.rs:433` rejects
  every migrated grant whose caller captured the other one, and every migrated
  user is asked to reconnect — the outcome this row exists to prevent (I).

**This does not block implementation.** It blocks only on MIK-6745/6746 being
bound to reuse the function rather than writing their own. The pre-ruling
paragraph that said the opposite — "this is the one item that should block
implementation until settled" — was left behind when the ruling was folded in
on 2026-09-21 and is **deleted**, not annotated: a design carrying both
readings has no reading.

**The missing comparison site is recorded as O7**, so the gap is owned rather
than implied away.

### 7.4 Input 1 — NON-DESTRUCTIVE

`mod.rs:779`'s "existing state is never replaced, and nothing is migrated into a
store this command creates" is a safety property about **`initialize`**, and it
stays true: this migration does not run through `initialize`, it runs against an
already-initialized store.

The non-destructive property this design owes is narrower and absolute: the 3.x
source is opened read-only and never mutated, truncated, renamed or deleted. A
failed migration leaves the user exactly where they started, which is the state
`upgrade.rs:243-248` already describes to them.

**Explicit design constraint, not an incidental property: migration must never
write through `TokenStorage::save` under the 4.0.0 key.** The destination is
`PersonalAccountStore` and nothing else. Re-keying the file would be a tempting
convenience, and it would make the shipped notice false in the field the moment
it landed, ahead of the retraction sequencing in §11.

### 7.4a Are existing grants preserved or invalidated? — stated explicitly

**Question 3 of the review mandate, and the first draft never answered it.**
Both answers are here because "preserved" is true in one sense and false in
another, and shipping only the flattering half is how an operator gets
surprised.

**Preserved, at the authorization server.** Migration performs no token
request. It does not refresh, does not revoke, and does not present the
credential anywhere. §5.3a requirement 3 refuses any migration whose legacy
issuer differs from the destination descriptor's, so a migrated grant is only
ever re-homed into the same authorization server that issued it. Nothing about
the migration invalidates a live grant.

**Preserved, on disk.** The 3.x file is opened read-only and never mutated
(§7.4). After a successful migration the operator holds two references to one
grant: the untouched 3.x file, and the sealed record in the per-principal
store.

**NOT preserved for rollback, once the migrated grant is used.** This is the
part the first draft implied away. Many authorization servers rotate refresh
tokens: the first refresh returns a new refresh token and retires the one
presented. Because §7.2a(a) seeds `expires_at = 0` whenever the 3.x record
carried no expiry, the *first use* of such a migrated grant triggers exactly
that refresh. From then on the 3.x file is byte-identical and its refresh token
is dead at the server. An operator who rolls back to 3.x after any migrated use
finds a file that looks intact and a grant that no longer works.

**Therefore:**

- The retracted notice text (§11) must say that the 3.x files remain as a
  record, **not** that they remain usable after migration. `upgrade.rs:243-248`
  currently tells operators the stranded files "still hold usable refresh
  tokens" — true today, and it stops being true for a migrated backend the
  first time it refreshes. Commit 2's rewrite carries this or it ships a lie.
- Rollback to 3.x is supported **before** first use of a migrated grant and is
  not guaranteed after it. Stated, not engineered around: guaranteeing it would
  mean never refreshing a migrated grant, which is the opposite of the row.

### 7.5 Input 2 — FAIL-CLOSED AND RESUMABLE

Both properties come from existing primitives. Nothing new is invented.

**Fail-closed on partial completion.** Each backend is one independent
`commit_grant_if` call. `commit_grant_if_unchanged` does the comparison and the
durable publication under **one** acquisition of the authority lock
(`consent.rs:75-105`, contract at `:16-19`) and a mismatch returns `Fenced`
having written nothing (`:96-100`) (V). So there is no half-populated account:
an account is either committed whole or absent. A run that dies after three of
five backends leaves three complete grants and two untouched 3.x files — not a
store that is half-populated and believed complete.

**Resumable, for free.** The guard is `ConsentExpectation::Absent`
(`service.rs:112-117`). Re-running after a partial run finds the three completed
accounts `Connected`, which is not `Absent`, so those three fence without
writing and the remaining two commit (V + I). Idempotency is a property of the
guard, not of a bookkeeping file this design would otherwise have had to invent.
The same guard is what makes a revoked account stay revoked
(`AccountLookup::Revoked` is not `Absent`) — migration can never resurrect a
credential a user has deliberately killed.

**Crash durability** is the existing nine-boundary commit sequence
(`faults.rs:17-29`), exercised through the existing `CommitCheckpoint` harness.
§9.3 says how.

---

## 8. BLAST RADIUS

**Lead fact (§4): this migration is the first production writer into the
per-principal store.** Everything below follows from that.

### 8.0 A structural constraint the brief did not name

`personal_accounts` is `pub(crate) mod` (`lib.rs:63`) (V), but the commit
machinery is deeper: `pub(super) mod commit` lives inside `storage.rs:29`, so it
is `personal_accounts::storage::commit` and is **not reachable from
`src/commands/`** (V). `random_hex` is additionally private to `commit.rs:67` —
no `pub(super)`, and its only callers are `commit.rs:63` and `:274` (V).

**Therefore the migration entry point must live inside `personal_accounts` and
expose exactly one `pub(crate)` function**, the way `start_custody`
(`mod.rs:675`) already does, with `src/commands/` calling only that. A migration
written directly in `src/commands/` cannot compile.

This also **removes** an item the brief's framing implies: `ConsentExpectation`
does **not** need to leave its `#[cfg(test)]` re-export gate (`mod.rs:592-596`),
because an entry point inside the module names `service::ConsentExpectation`
through the private `mod service` (`mod.rs:31`). Had the entry point gone in
`src/commands/`, that gate would have had to come off. Recorded because it is
exactly the kind of item an implementer discovers at compile time and then
"fixes" by widening the wrong thing.

### 8.1 Attribute removals — mandatory, not cleanup

Every one of these is `expect`, not `allow`. A production caller makes the
expectation unfulfilled, and `unfulfilled_lint_expectations` under the repo's
`cargo clippy --all-targets -- -D warnings` gate is a hard error. These are not
optional tidying; the build fails without them.

**Scoped by §7.1a**: the migration commits through
`PersonalAccountStore::commit_grant_if_unchanged` directly, so the service and
worker wrappers stay dead. One removal, not three.

- [ ] `src/personal_accounts/consent.rs:71-74` — `expect(dead_code, reason = "MIK-6744.STORE.1")`
      on `commit_grant_if_unchanged` (`:75`). **Remove.** Its reason string
      names this very row, and its comment (`:63-70`) says it is written to
      self-delete the moment production wiring adds a real caller. This design
      is that caller.
- [ ] `src/personal_accounts/consent.rs:45-51` — `expect(dead_code)` on
      `GuardedCommitError::RuntimeNotImplemented`. **Verify, likely stays.**
      Predicate is `all(not(test), unix)`; the only producer is the
      `#[cfg(not(unix))]` arm at `:81-87`, which a unix production caller never
      reaches. Listed so the implementer checks rather than assumes (A).

**Explicitly NOT removed, and they must stay:**

- `src/personal_accounts/service.rs:335-341` — `expect(dead_code)` on
  `commit_grant_if` (`:342`). Stays dead; MIK-6745/6746 removes it.
- `src/personal_accounts/worker.rs:247-253` — same on `commit_grant_if`
  (`:254`). Stays dead.

Removing either of these *without* adding a caller would itself fail the build
for the opposite reason. An implementer who reads only the brief will try.

### 8.2 Visibility widenings — each needs approval before it lands

- [ ] `src/personal_accounts/commit.rs:67` — `fn random_hex` →
      `pub(in crate::personal_accounts) fn`, so the migration can mint a
      `generation` that satisfies `lower_hex(.., 32)` (`storage.rs:134`) without
      a second RNG helper.

      **`pub(super)` would NOT be enough, and this is the trap.** `commit` is
      declared `pub(super) mod commit;` inside `storage.rs:29`, so `pub(super)`
      on an item in `commit.rs` reaches only `storage` — not `mod.rs` and not a
      sibling migration module. The module's own convention for exactly this is
      `pub(in crate::personal_accounts)`, used by every item other modules call:
      `commit_grant` (`commit.rs:390`), `refresh_tokens` (`:417`), `revoke`
      (`:479`), `mark_reconnect_required` (`:510`), `fence_expected_version`
      (`:549`) (V).

      **This is an API visibility widening and needs an explicit yes** per the
      repo's standing rule. The alternative — a private 16-byte RNG call in the
      migration module — duplicates `commit.rs:67-73` and is the worse answer.

### 8.3 New constructs

- [ ] **The operator declaration** (§5.3, §5.3a): `principal_authority`,
      `principal_subject`, `descriptor_id`, `legacy_backend_name`,
      `legacy_issuer`. Lands beside `AccountsConfig`
      (`src/personal_accounts/config.rs:192`) and `AccountDescriptor`
      (`:255-263`), validated by the existing `validate_descriptors` family
      (`config.rs:574`).
- [ ] **Provenance plumbing for `legacy_migration`** (§6.1). **Without it the
      marker is never set** — F17 pins that. Signatures **and their call
      sites**, because an implementer building from this list must not discover
      a caller at compile time:

      | Site | Change |
      |---|---|
      | `commit.rs:390` `commit_grant` (unix) | add the provenance parameter |
      | `commit.rs:593` `commit_grant` (`cfg(not(unix))` shim, verified at source) | signature parity; body still returns `InvalidConfiguration` |
      | `commit.rs:250-256` `stage_publication` | accept it; replace the carry-forward at `:285-288` with "use the supplied value, else carry forward" |
      | **`commit.rs:343`** — caller, inside `fn publish` (`commit.rs:336`) | **ADDED 2026-09-21 second review round.** `stage_publication` has TWO callers, not one; this is the second (V). Pass `None`. |
      | `consent.rs:75-80` `commit_grant_if_unchanged` | accept it and pass it through |
      | `consent.rs:81-87` (`cfg(not(unix))` arm) | signature parity |
      | **`consent.rs:102`** — caller | pass the migration's provenance |
      | **`mod.rs:501`** — caller, inside `PersonalAccountStore::commit_grant` (`mod.rs:493`, itself `expect(dead_code)` at `:486-492`) | pass `None`; stays dead |

      `consent.rs:102` and `mod.rs:501` are the only callers of
      `commit::commit_grant` (V — every other hit is
      `PersonalAccountStore::commit_grant` or a test). **But the parameter does
      not stop at `commit_grant`, and the first draft of this table said it
      did.** `stage_publication` is reached from two directions:
      `commit_grant` at `commit.rs:410`, and `publish` at `commit.rs:343`.
      `publish` is itself called from `refresh_tokens` at `commit.rs:457` (V).

      **Correction, and it matters because this table promised no compile-time
      surprises:** the first draft stated that `refresh_tokens`
      (`commit.rs:417`) is "**not** touched". That is false. Threading the
      parameter through `stage_publication` breaks `publish`, and `publish` is
      `refresh_tokens`'s durable write. `refresh_tokens` needs no new argument
      of its own — a refresh must carry the marker forward, never set it, which
      is exactly `None` plus the existing carry-forward (§6.2 claim 1) — but
      `publish` must accept and pass the parameter, so the edit reaches it.
      An implementer building from the first draft's list would have discovered
      this from the compiler, which is the failure this table exists to prevent.

      `revoke` (`:479`) and `mark_reconnect_required` (`:510`) write no record
      and do not reach `stage_publication`; those two are genuinely untouched
      (V).

- [ ] **Source-path validation** before reading (§10.5): regular file, not a
      symlink, owned by the running user, mode `0600`.
- [ ] **Parse-diagnostic sanitization** (§10.2): either a position-only wrapper
      for the migration's own reads, or a fix at `oauth/storage.rs:215` and
      `:304`. Pick one and put it in the diff; F14 pins it.
- [ ] **Issuer contradiction check** (§5.3a) against `TokenInfo.token_endpoint`.
- [ ] **Descriptor refreshability precondition** (§7.1b): refuse when the
      destination descriptor has no `client_id` or disagrees with the recovered
      legacy one.
- [ ] **A `descriptor_revision` producer** (§7.3) — **RULED 2026-09-21: build it.** Field set corrected; the only residual is binding MIK-6745/6746 to reuse the function.
- [ ] **The migration entry point**, `pub(crate)`, inside `personal_accounts`
      per §8.0. **It must build its `AccountKey` at exactly one site**, carrying
      a comment that points at `identity.rs:73-75` and states why it does not
      use `account_key` — see §5.4 item 2. The bypass gets its own single
      auditable location or it gets scattered.
- [ ] **The `src/commands/` caller**, one call, offline, never on the
      `serve` path (`mod.rs:786-790`).

### 8.4 Reached read-only, no edit required

- `TokenStorage::load` (`oauth/storage.rs:194`) (V)
- `TokenStorage::load_client_id` (`oauth/storage.rs:295`) (V)
- `ConsentExpectation::Absent` (`service.rs:112-117`) (V)
- `commit::commit_grant` and its nine boundaries (`faults.rs:17-29`) (V)
- `AuthorityEntry.legacy_migration` carry-forward (`commit.rs:285-299`) (V)

### 8.5 Sites that must NOT change — regression surface

- `src/oauth/storage.rs:231-255` (`save`) — migration never calls it (§7.4).
- `src/oauth/client/mod.rs:354-357`, `:382-387`, `:408-423` — the 4.0.0 keying
  is correct and is not what this row fixes.
- `src/personal_accounts/mod.rs:779` — the `initialize` safety property is
  unrelated and stays as written (§7.4).

---

## 9. TEST PLAN AS FALSIFIERS

Each row names the claim, the cheapest test that goes **RED** if the mechanism is
absent or broken, and which existing file it joins.

### 9.1 Placement — the peer collision, resolved

`crash_tests.rs` is held uncommitted by a peer, and its child entrypoint
`account_child` (`crash_tests.rs:27-64`) dispatches on an action string, so a new
crash case would ordinarily mean editing that exact function.

**Decision: a new sibling `src/personal_accounts/migration_crash_tests.rs`**,
with its own `CHILD` const and its own child entrypoint, declared in `tests.rs`
next to the existing `#[cfg(unix)] #[path = "crash_tests.rs"] mod crash;`
(`tests.rs:551-553`). It reaches `super::probe` (declared `tests.rs:539-541`)
and `super::faults::Boundary` (`mod.rs:38-39`) without touching the peer's file
(V for every anchor; I for the conclusion that this compiles as a sibling).

### 9.2 Falsifiers — attribution and commit

| # | Claim | Falsifier (RED if broken) | Joins |
|---|---|---|---|
| F1 | Migration commits a grant the declared principal can look up | Declare a principal, run migration against a seeded 3.x file, assert `lookup(key)` is `Connected` with the 3.x access token | new `migration_tests.rs` |
| F2 | **No declaration, no migration** | Run with no declaration against the same seeded file; assert `lookup` is `Absent` and the 3.x file is byte-identical | same |
| F3 | Migration never overwrites an existing grant | Commit a grant normally, then migrate the same key; assert the stored record is still the original (the `Absent` guard fenced it) | same |
| F4 | A revoked account is never resurrected | `revoke`, then migrate; assert `lookup` stays `Revoked` | same |
| F5 | Re-running is idempotent | Migrate twice; assert one `Connected` record and the same `generation` both times | same |
| F6 | `client_id` is not recoverable → the backend is refused, not committed with an empty one | Seed a 3.x file with no `client_id` and no `_client.json`; assert refusal and `lookup` is `Absent` | same |
| F7 | `legacy_migration` provenance is set and survives a refresh | Migrate, assert the entry's `legacy_migration` is `Some`; refresh, assert it is still `Some` | same |
| F8 | Scopes land strictly ascending | Seed `scope: "write read read"`; assert the record validates and scopes are `["read","write"]` | same |

### 9.3 Falsifier — crash and resume (input 2, existing harness)

| # | Claim | Falsifier | Joins |
|---|---|---|---|
| F9 | A crash mid-migration leaves the account absent, never half-populated | Drive the child with `abort_at = Boundary::CommitCheckpoint.name()` (`faults.rs:57`); assert it dies **at** the named checkpoint, that a candidate file appeared, and that a restart reports `absent` or an explicit failure — never a partial grant | new `migration_crash_tests.rs` (§9.1) |
| F10 | Resume after that crash completes the migration | Re-run migration after F9's crash; assert `Connected` | same |

F9 mirrors `s10_a_crash_between_candidate_sync_and_manifest_replacement_keeps_the_prior_grant`
(`crash_tests.rs:144-179`) and reuses its `explicit_failure` discipline
(`:105-116`) — the existing harness, per input 2, not a second one.

### 9.4 Falsifiers — the read side and the notice

| # | Claim | Falsifier | Joins |
|---|---|---|---|
| F11 | The existing 4.0.0 compatibility pin still holds | `legacy_single_user_record_is_not_reachable_under_the_4_0_0_issuer_key` (`upgrade_path_tests.rs:118-149`) passes **unchanged** | existing, unmodified |
| F11b | **Migration itself never re-keys the 3.x file** | Seed a 3.x record, **run migration to success**, then assert `store.load(&storage_key(BACKEND, ISSUER), RESOURCE)` is still `None` | `migration_tests.rs` |
| F12 | The 3.x file survives migration byte-for-byte | Assert on the source path after a successful migration | `migration_tests.rs` |

**F11 alone is not a falsifier for the re-keying claim, and the first draft said
it was.** Design review 2026-09-21 caught it and the objection is correct:
`upgrade_path_tests.rs:118-149` seeds a store and calls `store.load` directly —
**it never invokes migration** (V). It therefore cannot go red no matter what
migration does, which makes it a check that cannot fail for the property it was
credited with. It remains valuable as a compatibility pin; F11b is the actual
falsifier, and it must run migration to completion first.

### 9.5 Falsifiers — the refusals the review findings added

| # | Claim | Falsifier | Joins |
|---|---|---|---|
| F13 | A descriptor that cannot refresh the migrated grant is refused, not committed | Declare a descriptor with no `client_id` (and separately, one whose `client_id` differs from the recovered legacy id); assert refusal and `lookup` is `Absent` (§7.1b) | `migration_tests.rs` |
| F14 | A malformed 3.x record leaks nothing to logs | Seed a record with a sentinel secret in a wrong-typed field; capture `tracing` output; assert the sentinel appears nowhere (§10.2) | `migration_tests.rs` |
| F15 | A substituted source is refused | Replace the source path with a symlink, and separately with a mode-0644 file; assert refusal in both cases and `lookup` is `Absent` (§10.5) | `migration_tests.rs` |
| F16 | An issuer mismatch is refused, not migrated | Seed a record whose `token_endpoint` origin differs from the attested `legacy_issuer`; assert refusal. Separately assert refusal when `legacy_issuer` differs from the descriptor's `issuer` (§5.3a) | `migration_tests.rs` |
| F17 | The provenance marker is actually set on a first migration | After a first successful migration, assert the authority entry's `legacy_migration` is `Some` — this goes RED against today's carry-forward-only code and stays red until §6.1's plumbing lands | `migration_tests.rs` |

F17 is deliberately listed as a falsifier that **fails today**. It is the
cheapest proof that §6.1's gap is real rather than theoretical, and the cheapest
guard that the plumbing actually landed.

---

### 9.6 Falsifiers added by the second review round (2026-09-21)

| # | Claim | Falsifier | Joins |
|---|---|---|---|
| F18 | A 3.x record with no `expires_at` AND no `refresh_token` is refused, never committed permanently-dead | Seed such a record; assert refusal and `lookup` is `Absent` (§7.2a(a)) | `migration_tests.rs` |
| F19 | A record with no `expires_at` but WITH a refresh token still migrates, seeding `0` | Seed such a record; assert `Connected` and `expires_at == 0`. **This is F18's positive control** — without it F18 passes for a migration that refuses everything | same |
| F20 | An absent `scope` never becomes an empty scope set | Two legs: against a descriptor declaring `scopes`, assert `Connected` with the descriptor's scopes; against one declaring none, assert refusal and `Absent` (§7.2a(b)) | same |
| F21 | **A solo install can actually USE a migrated credential** | Declare the solo principal, migrate, authenticate as that principal on a single-user gateway, assert the lease carries the migrated grant. **Expected to fail to COMPILE, not to fail an assertion**, until O8's `sole` tier exists (§1.1) — recorded so the gap is visible in the suite rather than only in prose, and explicitly not counted as coverage | blocked on O8 |

### 9.7 The vacuity rule every negative falsifier above is now subject to

**Both review seats raised this independently and it is accepted.** A falsifier
that asserts only that something did NOT happen passes for a migration that
does nothing at all, which is precisely the defect class this repo has caught
twice in one week. Against a tree with no migration, **F2, F3, F4, F12 and F14
as first drafted are vacuous**: "assert `lookup` is `Absent` and the 3.x file
is byte-identical" is true of an empty function.

**Rule, binding on the implementation of §9:** every negative falsifier must
run a *proven-successful* migration first, in the same test, and assert that
success — then assert the negative about a second backend, a second key, or a
second run. Specifically:

- **F2** (no declaration, no migration): migrate backend A successfully and
  assert `Connected`, then assert backend B — seeded identically, declared
  nowhere — is `Absent` and its file byte-identical. Without leg one, F2 proves
  nothing, and §10.5's security argument rests on it.
- **F3, F4** (never overwrite, never resurrect): assert the *positive* commit
  or revoke landed first, then that migration left it alone.
- **F12, F11b** (source untouched, never re-keyed): §9.4 already requires F11b
  to run migration to completion; F12 must do the same.
- **F14** (no secret in logs): asserting only that the sentinel is absent
  passes when the parse was never attempted. It must additionally assert the
  position-only refusal *appears* in the captured output, so the test fails if
  the record was never read.

F9's crash falsifier is **not** in this class: the existing harness already
requires `Outcome::Died { checkpoint: Some(..) }` — the child announces the
named boundary before dying — and a candidate-count delta proving the window
was entered (`crash_tests.rs:144-179`) (V). A child that merely exited fails
those assertions. The fault cannot fail to bite unnoticed.

---

## 10. SECURITY (input 5 — not optional on this path)

This is a live-credential path, and per input 5 the delivery process's
design-before-code gate applies with no discretion. It is also, per §4, the
**first production writer into the per-principal store**, so it is the first
code that can corrupt that store in the field.

### 10.1 What touches plaintext credential material, and for how long

**Corrected after design review 2026-09-21** — the first draft ended the window
at sealing, which is wrong.

Plaintext 3.x credential bytes enter the process at
`TokenStorage::load` (`oauth/storage.rs:202` `read_to_string`) and exist in at
least three buffers: the file contents `String`, the `TokenInfo` fields it
deserializes into, and the `GrantRecord` `String`s built from them.

**Sealing does not end the exposure.** `seal_token(key_id, key, &aad, record)`
borrows the record (`commit.rs:269`) — it produces ciphertext beside the
plaintext, it does not consume or erase it. The plaintext lives until each owner
is dropped at the end of the migration's per-backend scope, and neither
`TokenInfo` nor `GrantRecord` implements zeroize-on-drop (V: no `Drop` impl on
either, `oauth/storage.rs:20-51`, `mod.rs:137-149`).

What the design *can* honestly claim:

- The window is **synchronous and await-free** on the chosen route (§7.1a): no
  provider, no worker, no `await`, so no buffer is cloned across a task boundary
  or parked in a future. The rejected service/worker route would have added
  exactly that — `worker.rs:260-262` clones the record into the closure it
  offloads (V).
- It is **one backend at a time**; no collection of decrypted credentials
  accumulates.
- No buffer is written anywhere except sealed (§10.3, §10.4).

Zeroization is **not** claimed and is not in scope for this row; it would be a
change to `TokenInfo`/`GrantRecord` affecting every existing holder. Recorded as
O6 rather than silently implied.

### 10.2 Logs, errors, panics

The first draft claimed "nothing lands". **That claim was too strong and is
corrected here** — there is one real leak path, found by design review
2026-09-21 and confirmed at source.

**The leak**: `TokenStorage::load` logs the raw `serde_json` error on a parse
failure — `warn!(backend = %backend_name, error = %e, "Failed to parse stored
token")` (`oauth/storage.rs:215`) (V). `serde_json`'s `Display` embeds offending
input in several error shapes (for example `invalid type: string "…", expected
u64 at line N column M`), so a **malformed** 3.x record can put fragments of its
own contents — including a token value landing in a field of the wrong type —
into an operator's log at `warn` level. The same pattern repeats at
`oauth/storage.rs:304` for `load_client_id` (V).

This is pre-existing and not introduced here, but migration is the path that
deliberately feeds old, possibly hand-edited records to that reader, so it is
this design's problem to handle:

- **Requirement**: the migration must not rely on `TokenStorage::load`'s
  diagnostics. Either parse through a wrapper that reports position-only
  errors, or accept the existing reader and add a sanitization fix to
  `oauth/storage.rs:215` and `:304` within this row's blast radius (§8.3).
- **Falsifier**: F14 (§9.5) — a malformed record carrying a sentinel secret,
  asserting the sentinel appears in no captured log output.

**What genuinely does not leak**, three independent guards already in place:

- `TokenInfo`'s `Debug` is hand-written and redacts `access_token`,
  `refresh_token` and `client_secret` (`oauth/storage.rs:62-76`) (V); the
  comment at `:57-61` says a derived `Debug` would have printed all three.
- `GrantRecord`'s `Debug` is `finish_non_exhaustive()` — no fields at all
  (`mod.rs:151-155`) (V).
- `AccountError` is secret-free by construction (`mod.rs:83-103`) (V).

**Constraint on the new code**: report per-backend outcomes using the existing
error vocabulary only. No `format!` interpolating a `TokenInfo` field, and no
logging the declared `principal_subject` beside a backend id at info level.
The safe precedent is `AccountReleaseAudit` (`mod.rs:628-643`), which logs
backend, resource and a non-secret `token_revision` behind an explicit
`ci-allow-secret-log` justification (V).

**Panics**: `unwrap_or(0)` on `expires_at` (§7.2) and explicit refusal on a
missing `client_id` (§7.1) are chosen partly so no `unwrap`/`expect` sits on a
path holding plaintext.

### 10.3 File modes on anything created

The migration creates nothing itself. Every file it causes to exist is created
by the existing commit path: `open_private` uses
`create_new(true).mode(0o600)` (`commit.rs:76-84`), scratch names are private
and in-directory so the rename is atomic (`:60-64`), and `persist_record`
(`:89`) runs the full create/write/sync/rename/parent-sync sequence (V). The
3.x source keeps its own 0600 (`oauth/storage.rs:237-244`) because it is never
written (§7.4).

### 10.4 What a crash mid-migration leaves on disk

**A sealed orphan candidate, never plaintext.** The record is sealed at
`commit.rs:269` *before* `persist_record` at `:306` writes anything, so the only
bytes that can reach the disk are ciphertext. A crash at `CommitCheckpoint`
leaves that candidate durable and unreferenced by any manifest
(`faults.rs:21`), and the commit path removes unreferenced candidates on any
failure before the rename (`commit.rs:313-319`) (V).

An unreferenced sealed candidate is inert: `lookup` resolves through the
authority manifest, and `s13_restored_pre_revoke_ciphertext_stays_refused_across_restart`
(`crash_tests.rs:181-203`) already proves that ciphertext the manifest does not
name is refused even when replanted deliberately (V).

So the worst on-disk residue of a crashed migration is a sealed file nothing
points at, plus the untouched 3.x original. F9 (§9.3) is the falsifier.

### 10.5 Can migration be induced by an attacker-controlled path?

**Induced: no. Substituted: yes, if the source directory is writable by a
hostile party — and the first draft's "never opened" was too strong.** Design
review 2026-09-21 caught the overclaim; it is corrected here.

**What holds.** Migration is reached only from an explicit operator declaration
(§5.3) and never enumerates `~/.mcp-gateway/oauth/`. A random file dropped into
that directory is not picked up, because nothing scans for it. Writing the
declaration requires the privilege to change gateway configuration, which is
above the bar this defends against. The path is offline and never on the `serve`
path (`mod.rs:786-790`), so request traffic cannot trigger it at all (V).

**What does not hold.** The filename is *predictable*: it is
`SHA-256(legacy_backend_name + ":" + resource)[..8] + "_tokens.json"`
(`oauth/storage.rs:178-185`), computed from values in the declaration and the
descriptor, both readable by anyone who can read the config (V). And
`fs::read_to_string` (`:202`) **follows symlinks** and performs no ownership or
mode check (V). So a party who can write into the source directory can plant or
symlink that exact path and have migration seal *their* chosen token into the
declared principal's account.

**Therefore the source directory is a trust boundary, and the design states it
rather than assuming it:**

1. **Stated precondition**: `~/.mcp-gateway/oauth/` must be owned by, and
   writable only by, the identity running the migration. This is the same trust
   the 3.x credentials already required — those files *are* the credentials —
   so it is a documented boundary, not a new requirement.
2. **Requirement**: before reading, verify the resolved source is a regular
   file, not a symlink, owned by the running user, and mode `0600`. This is
   cheap, it matches what `TokenStorage::save` already guarantees on write
   (`oauth/storage.rs:237-244`), and it turns a silent substitution into a
   refusal. F15 (§9.5) is the falsifier.

**Bounded regardless.** Even a successful substitution is `Absent`-guarded
(`consent.rs:96-100`): it can create a grant at a key that had none, never
displace or read an existing one.

The residual risk remains §5.5's: an operator who declares the wrong subject.
That is an authorization mistake, not an injection.

---

## 11. `NOTICE_4_0_0_ITEMS` SEQUENCING (input 4 — retract last)

`upgrade.rs:243-248` currently tells operators "Stored tokens from 3.x are not
migrated: each OAuth backend re-authenticates once", plus where the stranded
files are, their mode, and to delete them. **That text is true today and must
stay true until migration actually ships.** Retracting it early makes the
product lie in the other direction.

### 11.1 Commit order

**Commit 1 — mechanism, notice untouched.** Everything in §7, §8 and §9 lands.
`NOTICE_4_0_0_ITEMS` is not edited. Both notice tests stay green unmodified. The
migration exists but the notice does not yet claim it, which is the safe
asymmetry: a notice that under-promises is not a lie.

**Commit 2 — notice retraction, once commit 1 is merged and green.** Item 1 is
rewritten to describe the migration that now exists, and the two tests below
change in the same commit.

The ordering is not stylistic. Between the two commits the notice says "not
migrated" while a migration command exists but has not been run by anyone — still
true, because nothing migrates without a declaration (§5.3). There is no window
in which either version of the text is false.

### 11.2 The tests that change at commit 2 — there are two, not one

- `notice_4_0_0_discloses_the_stranded_3_x_token_files` (`upgrade.rs:1187-1196`)
  asserts item 1 contains `"~/.mcp-gateway/oauth/"`, `"0600"` and
  `"delete them"` (`:1190`). **Obvious.** It must be rewritten to pin whatever
  the new text promises. Note its doc comment (`:1180-1186`) cites
  `legacy_single_user_record_is_not_reachable_under_the_4_0_0_issuer_key` as the
  at-source proof; that citation stays accurate (§9.4 F11).
- `notice_4_0_0_carries_all_five_items` (`upgrade.rs:1159-1175`) asserts the
  joined text contains `"re-authenticate"` (`:1164`). **Not obvious, and it is
  the one an implementer misses.** If the rewritten item 1 drops that word, this
  test goes red too. Either keep a form of the word in the new text or update
  `:1164` in the same commit.
- The count assert `NOTICE_4_0_0_ITEMS.len() == 5` (`:1161`) **does not
  change**: item 1 is rewritten, not removed, and the surface stays five items.
  Adding a sixth item would be the wrong shape — this is one item becoming
  accurate, not a new disclosure.

### 11.3 The other retraction target

`src/personal_accounts/mod.rs:779` ("nothing is migrated into a store this
command creates") **is not retracted at all**, in either commit. It documents
`OfflineInitError::Refused` for `initialize`, and it stays true (§7.4). Listed
because it is the second of the two sites the ruling quotes, and an implementer
sweeping for "migration is not supported" prose will find it and be tempted.

---

## 12. OPEN ITEMS

| # | Item | Tag | What settles it |
|---|---|---|---|
| O1 | ~~**`descriptor_revision` has no producer** (§7.3). Blocks implementation.~~ **RULED 2026-09-21: it is a development gap to fix; STORE.1 defines the producer.** The proposed field set was ALSO wrong and is corrected in §7.3 — it hashed `provider`/`resource`/`issuer`, but `resource` and `oauth_issuer` are already in `AccountKey` (`mod.rs:49-53`), so it duplicated the key and was blind to a widened `scopes`. | V | Residual: MIK-6745/6746 must be bound to reuse the same function, not reimplement it. |
| O2 | `random_hex` visibility widening (§8.2) | A | An explicit yes on `commit.rs:67` → **`pub(in crate::personal_accounts)`**, per the standing rule on API visibility widening. **Corrected 2026-09-21 second review round:** this row previously said `pub(super)`, which §8.2 states in bold is NOT enough — the open-items table was re-introducing the exact trap §8.2 warns about. |
| O3 | Whether a migrated grant is ever leasable in the deployment that receives it | V | **RULED 2026-09-21: there must be a solo upgrade path — "all our current users are solo users."** So this is not a precondition to check but a gap to close, and it is the one that decides whether this row delivers anything at all. A migrated grant is leased only when its declared principal authenticates, and `VerifiedIdentity` has exactly two production producers (`key_server/oidc.rs:446-452`, `gateway/openwebui_adapter.rs:421`) — `handlers.rs:2218` looks like a third and sits inside `#[cfg(test)]` opened at `:2177`. A solo 3.x install has neither, so today migration would satisfy MIGRATED and deliver nothing to **every existing user**. The answer is the single-user principal in `design/proof-tiered-principals`, which must land for this row to be worth building. |
| O4 | `consent.rs:45-51` `expect` — stays or goes (§8.1) | A | Compile check during implementation; listed so it is checked rather than assumed. |
| O5 | Issuer contradiction check granularity (§5.3a) — is comparing the `token_endpoint`'s **origin** to the attested issuer's origin the right test? Some providers host the token endpoint off the issuer origin. | A | A decision on whether to compare origins, require an exact operator-supplied endpoint, or treat a mismatch as a warning that requires a second attestation flag. Conservative default: refuse and make the operator override explicitly. |
| O6 | Zeroization of `TokenInfo` / `GrantRecord` plaintext buffers (§10.1) | A | Out of scope for this row as scoped; it changes types every existing holder shares. Named so the security section's claim stays honest rather than implying erasure this design does not perform. |
| O7 | **The `descriptor_revision` fence has no comparison site** (§7.3). Every occurrence in the tree is a copy, a validator, or a comparison of two stored-origin values; the live `AccountDescriptor` is never fingerprinted and never compared (V). Computing the value correctly at migration time therefore detects no descriptor change at all. | V | A decision on whether the read path (`AccountService` before release, or `GatewayRefreshProvider` before refresh) gains a live-fingerprint comparison, and which row owns it. It is **not** in STORE.1: it is a new production behaviour whose consequence is that every affected user is asked to reconnect after a config edit. |
| O8 | **The `sole` identity tier** (§1.1). STORE.1 delivers zero user-visible value to a solo install without it, and that is the population the operator's ruling names. | V | Escalated 2026-09-21 as its own decision. `origin/design/proof-tiered-principals` @ `7325697b` is design-only, no implementation. §1.1 records both outcomes. |

**Gating, consolidated — this is the single authoritative list, and §7.3 no
longer carries a competing one.**

| Item | Gates | Owner |
|---|---|---|
| O8 (`sole` tier) | whether the row delivers anything to current users; and the solo falsifier F21 | escalated, owner decision |
| O5 (issuer-check granularity) | F16's refusal assertion — a falsifier cannot be written against an undecided rule | owner decision; conservative default is refuse-with-explicit-override |
| O2 (`random_hex` visibility) | one line of implementation | explicit yes, per the standing rule |
| O7 (fence comparison site) | nothing in STORE.1 — recorded so the gap is owned, not implied away | a later row |
| O4 (`consent.rs:45-51` `expect`) | nothing — a compile check during implementation | implementer |
| O6 (zeroization) | nothing — out of scope, named so §10.1 stays honest | a later row |

O1 is RULED and no longer gates. **O3 is superseded by §1.1 and O8**, which
state both outcomes rather than leaving the question open.

### 12.1 Review findings accepted and folded in (2026-09-21)

Every item below was raised by design review, **verified independently at
source**, and confirmed. Listed so the next reader sees what changed and why,
rather than trusting the reviewer or this author.

| Finding | Verified at | Where fixed |
|---|---|---|
| Issuer adopted from the destination descriptor with no evidence it issued the legacy credential — reintroduces the MCP "MUST NOT reuse across authorization servers" rule | `client/mod.rs:105-107`, `provider.rs:300-301` | §5.3a (attest + contradiction-check + equality) |
| `client_id` recovery omitted 3.x operator-config, certainly refusing preconfigured-client installs | `client/mod.rs:389-398` | §7.1 step 2a |
| Recovering `GrantRecord.client_id` does not make a grant refreshable; the provider uses `descriptor.client_id` | `provider.rs:303`, `:314-319` | §7.1b (new precondition), F13 |
| The guarded commit **cannot** set `legacy_migration`; every first migration would lack the marker | `consent.rs:102`, `commit.rs:390`, `:285-288` | §6.1 (plumbing costed), §8.3, F17 |
| Plaintext lifetime does not end at sealing; `seal_token` borrows the record | `commit.rs:269`; no `Drop` on either type | §10.1 (rewritten), O6 |
| `TokenStorage::load` logs raw `serde_json` errors, which can embed input | `oauth/storage.rs:215`, `:304` | §10.2 (rewritten), §8.3, F14 |
| "Never opened" overclaimed: the filename is predictable and the reader follows symlinks | `oauth/storage.rs:178-185`, `:202` | §10.5 (rewritten), §8.3, F15 |
| F11 cannot detect re-keying because it never invokes migration | `upgrade_path_tests.rs:118-149` | §9.4 (F11b added) |
| `v3.5.1` already carries `token_endpoint`/`client_id`/`client_secret`; they are not fields 4.0.0 added | `v3.5.1:src/oauth/storage.rs:20-51` | §3 (premise corrected) |
| `AccountsConfig` is at `config.rs:192` | `config.rs:192` | §8.3 |

One reviewer claim was **not** adopted as stated: the suggestion to call the
synchronous guarded store operation directly was already this design's §7.1a,
reached independently before the review ran.

---

## 13. SUMMARY OF DECISIONS TAKEN

1. **Attribution**: operator-declared principal, no declaration no migration
   (§5.3), **plus an attested and contradiction-checked issuer binding** that
   refuses any migration across authorization servers (§5.3a). Rejected:
   sentinel principal, lazy first-presenter binding, derivation from 3.x config
   — each fails `identity.rs`'s "verified, never inferred" test (§5.2).
2. **`legacy_migration`**: kept and made real as the provenance marker; it is
   producerless rather than dead. **This requires provenance plumbing through
   four signatures that does not exist today** (§6.1) — costed, not assumed.
3. **Non-destructive**: 3.x source is read-only, and migration never writes
   through `TokenStorage::save` under the 4.0.0 key — a stated constraint, not an
   incidental property (§7.4).
4. **Fail-closed and resumable**: both fall out of `ConsentExpectation::Absent`
   plus the existing single-acquisition guarded commit; no new bookkeeping
   (§7.5). Crash property uses the existing `CommitCheckpoint` harness in a new
   sibling file, so the peer's `crash_tests.rs` is untouched (§9.1).
5. **Commit route corrected**: directly through
   `PersonalAccountStore::commit_grant_if_unchanged`, not through
   `AccountService`/`CustodyHandle` as the brief assumed — those require a
   `RefreshProvider` whose bootstrap does HTTP, which an offline migration must
   not need. This shrinks the blast radius to one attribute removal (§7.1a,
   §8.1).
7. **Two seeds that could kill a working grant are designed, not defaulted**
   (§7.2a). `expires_at` is preserved when present, seeded `0` only when a
   refresh token exists to redeem it, and the backend is REFUSED when neither
   is available. An absent `scope` takes the destination descriptor's scopes,
   or the backend is refused — never the empty set, which refuses its own
   first refresh. A successful migration that leaves a credential dead is
   worse than no migration, and the first draft shipped two routes to it.
8. **The `descriptor_revision` fence is not built, and the design now says so**
   (§7.3, O7). The value is computed per the ruling; the claim that it detects
   a descriptor change is withdrawn, because no site compares it to live
   configuration. Ninety lines specifying a fence with no comparison site was
   worse than an honest gap.
9. **The `sole` identity tier is a named hard dependency** (§1.1, O8), with
   both outcomes written down: without it the row satisfies MIGRATED on disk
   and delivers nothing to any current user; with it, it delivers the ruling.
   Escalated as its own decision rather than designed around here.
10. **Grant preservation is stated in both directions** (§7.4a): nothing is
    invalidated by the migration, and rollback to 3.x is not guaranteed after
    a migrated grant's first refresh on a rotating server.
6. **Notice retracted last**, in a second commit, with two tests changing rather
   than the one that is obvious (§11).

### 12.2 Second review pass — independent citation verifier (2026-09-21)

A second verifier was run because `grok-review` is unavailable in this
environment (0-byte output, authentication failure; prior runs in the review
directory are also 0B, so it is broken rather than transient). **The
two-reviewer gate the row specifies was therefore not met**: one reviewer ran,
one is unavailable, and this pass is a labelled substitute, not grok.

Verdict: **SOUND WITH FIXES**. Its findings, each re-verified at source before
being applied:

| Finding | Verified at | Resolution |
|---|---|---|
| §5.3 cited `config.rs:255-263`, but the "no legacy name" claim needs the whole struct, which runs to `:292` | `config.rs:255-292` — full field list confirmed | Widened, with the field list spelled out |
| §7.3 cited `fence_tests.rs:163-191`, which starts one line into one test and stops mid-second | `:162-182` fences on change; `:184` onward is the no-fence case | Split into the two tests by name |
| §8.3 cited `config.rs:213` as `AccountsConfig` | `:192` is the struct, `:213` the field | **Already fixed** before this pass ran; verifier read a pre-fix snapshot |
| §5.4 argued the request/offline distinction but never named the constructor bypass | `identity.rs:73-75` | **Substantive — accepted.** §5.4 item 2 added, plus a constraint in §8.3 |

It independently confirmed as exact: all four §2 corrections; every
`validate_record` anchor in §7.2; all ten `descriptor_revision` sites and the
"no production producer" claim in §7.3; the §10.3/§10.4 commit and crash
anchors; the §9 test anchors and the sibling-module reachability claim
(`crash_tests.rs:13` already reaches `super::faults::Boundary`); every §11
notice anchor; and that all five mandatory inputs are answered in their own
sections.

It also independently verified §5.2's inertness argument for the rejected
sentinel principal: a tree-wide search for `VerifiedIdentity {` returns
production producers only at `key_server/oidc.rs:446-452` and
`gateway/openwebui_adapter.rs:421` — every other construction sits in a
`#[cfg(test)]` module or fixture, including `gateway/router/handlers.rs:2218`,
which is inside the `#[cfg(test)]` block opened at `:2177`.

---

### 12.3 Second review round — two live seats, 2026-09-21

Both seats ran on the full document with a scope line on stdin. **Neither was
dark**, which corrects a standing expectation: `gpt-review` has returned 0-byte
output repeatedly in this environment, and did not here — it wrote 6.1 KB and
its evidence line records read-only Git inspection against `1d8b5668` and tag
`v3.5.1`. `kimi-review` wrote 9.1 KB and was explicit that it could **not**
reach the repository, so every `V`-tagged citation it accepted on this
document's own word; its findings are therefore document-internal by
construction. Both returned **SHIP-WITH-FIXES**. Note this is a different pair
from §12.2, where grok was dark and a substitute verifier stood in.

Every finding below was re-verified at source before being applied. Findings
are listed with which seat raised them, because a claim both seats reach
independently and a claim one seat reaches are not the same evidence.

| Finding | Raised by | Verified at | Where fixed |
|---|---|---|---|
| **The `descriptor_revision` fence has no comparison site anywhere**; computing the value detects no descriptor change | gpt | all 20 occurrences re-read: `commit.rs:295`, `:433`, `:450-455`, `:514`, `:522`, `:564`, `:627`; `service.rs:79`, `:128`, `:183`, `:193`; `storage.rs:135`, `:481`; `vault.rs:226-227` | §7.3 rewritten; O7 |
| **`expires_at → unwrap_or(0)` kills an access-only grant** | gpt | `service.rs:272-277`, `provider.rs:307-311` | §7.2a(a); F18/F19 |
| **An absent `scope` becomes an empty set that refuses its own refresh** | gpt | `service.rs:393-400` | §7.2a(b); F20 |
| **§8.3's provenance list omits `stage_publication`'s second caller**, and its "`refresh_tokens` is not touched" is false | gpt | `commit.rs:250` (def), `:343` (in `publish`), `:410` (in `commit_grant`), `:457` (`refresh_tokens` → `publish`) | §8.3 table + correction |
| **The solo path is unbound**: nothing ties the declared principal to the only identity that could lease the grant | both | `identity.rs:85-86`; two production `VerifiedIdentity` producers only (`key_server/oidc.rs:446`, `gateway/openwebui_adapter.rs:421`), all 58 occurrences classified by `cfg(test)` context | §1.1; O8; F21 |
| **§7.3 contradicted itself** in adjacent paragraphs on whether the row is blocked | both | the document itself | §7.3 — the pre-ruling paragraph **deleted**, survivor named |
| **O2 asked for `pub(super)`**, the exact visibility §8.2 states in bold is insufficient | both | §8.2 vs O2 | O2 corrected |
| **Negative falsifiers are vacuous** without a positive control (F2, F3, F4, F12, F14) | both | the no-op hypothesis applied to each | §9.7, binding rule |
| **O5 is open while §5.3a req 2 is mandatory and F16 pins it** | kimi | §5.3a vs O5 | O5 moved into the consolidated gating table |
| **Grant preservation across the migration is never stated** (Q3), and a rotating server voids the 3.x token on first migrated refresh | kimi | §7.4 scopes its claim to a *failed* migration | §7.4a |
| **§7.1 step 2's "refuse if two sources disagree" can refuse a legitimate install** — DCR first, operator `client_id` later, both present and legitimately different | kimi | `client/mod.rs:389-398`, `:425-428`; `drop_credentials_from_other_issuer` keeps a configured id across an issuer change | §7.1 precedence note |

**Claims trimmed rather than adopted as stated:**

- kimi framed the rotation point as contradicting §7.4's "leaves the user
  exactly where they started". It does not: §7.4 scopes that sentence to a
  **failed** migration. The real gap is that Q3 is unanswered, which is what
  §7.4a fixes.
- gpt's `expires_at` finding was stated as affecting access-only grants
  generally. It affects only records with **no `expires_at`**; a present value
  is preserved verbatim. The narrower statement is what §7.2a(a) encodes.

**One finding was raised by this round's own author and withdrawn**: that
`oauth::storage` being a private module (`oauth/mod.rs:18`) made `TokenStorage`
unreachable from `personal_accounts`, requiring a fourth visibility widening
§8.2 had missed. It is re-exported at `oauth/mod.rs:24`
(`pub use storage::{TokenInfo, TokenStorage}`) and `personal_accounts/provider.rs`
already uses it. §8.2 stands at one widening. Recorded because a withdrawn
finding is evidence the others were checked.

