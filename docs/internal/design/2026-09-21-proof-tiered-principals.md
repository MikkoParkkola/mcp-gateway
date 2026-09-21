# Proof-tiered principals: one identity model from a laptop to an enterprise

**Status:** proposal, written 2026-09-21 in response to an operator question.
**Problem it answers:** `MIK-6744.STORE.1` open item O3.
**Evidence tags:** **V** verified by reading source at
`origin/docs/ranking-1-release-line`, **I** inferred, **A** assumption.

---

## 1. The problem, stated exactly

**V** A per-user credential is only reachable when its declared principal
authenticates. `AccountKey.principal_authority` and `principal_subject` come
from `VerifiedIdentity::issuer` and `::subject` (`identity.rs:85-86`).

**V** `VerifiedIdentity` has exactly **two** production producers:

| Site | What it needs |
|---|---|
| `src/key_server/oidc.rs:446-452` | a verified OIDC token |
| `src/gateway/openwebui_adapter.rs:421` | OpenWebUI's forwarded identity |

Everything else that constructs one is a test or a fixture.
`src/gateway/router/handlers.rs:2218` looks like a third and is not: it sits
inside `#[cfg(test)] mod caller_identity_tests`, opened at `:2177`.

**V** So a deployment with **no supported end-user identity producer** can
never produce a principal, can never match an `AccountKey`, and therefore
cannot use the per-user credential store at all.

That wording is deliberate and was corrected in review. "No OIDC" is too broad:
the OpenWebUI adapter is configured independently of any OIDC provider, so a
deployment running it *does* have a producer. The population that has neither
is the one O3 is about — and a 3.x single-user install upgrading to 4.0.0 is
squarely in it, so the STORE.1 migration would be correct on disk and deliver
nothing to the very population whose tokens it migrates.

### 1.1 The precedent this proposal builds on

**V** The OpenWebUI adapter is not a second OIDC path. It validates claim
coherence — expiry after issuance, lifetime within a configured maximum, no
future-dated issuance beyond configured skew — and then constructs a
`VerifiedIdentity` at `:421` with a comment that states its own epistemic
status plainly:

> Not carried: an adapter **asserts** a subject, and an email or group list
> taken from it would flow into role mapping as if an IdP had verified it.

So the product **already ships, and has already reviewed, an assertion-based
identity producer** that deliberately carries less than a verified one. This
proposal is an extension of an existing accepted pattern, not the introduction
of a new one — and the adapter's discipline of refusing to carry unverified
attributes is the model the `sole` tier should copy.

## 2. The reframe

The defect is not "migration needs a special case". It is that the product
currently equates **identity** with **OIDC-verified identity**, which is an
enterprise assumption compiled into a single function.

Identity is not binary. It has *tiers of proof*, and a deployment should be
able to use the strongest tier it can actually operate.

**The load-bearing discovery: every tier already ships.** Nothing below
invents an identity mechanism. Each one already exists, is already
operator-configured, and is simply not wired to `account_key()`.

| Tier | Authority | Subject | Already in the product |
|---|---|---|---|
| `sole` | `"local"` | a fixed constant | **V** `auth.single_user: true`, read at `upgrade.rs:184`; `upgrade.rs:144` actively tells personal gateways to set it |
| `key` | `"apikey"` | `api_keys[].name` | **V** `ApiKeyConfig` at `config/features/auth.rs:136`, `name` at `:141` — "Human-readable name for this client" |
| `mtls` | `"mtls"` | SAN-URI else CN | **V** `CertIdentity` at `src/mtls/identity.rs:30` |
| `oidc` | issuer URL | `sub` | **V** `key_server/oidc.rs:446-452` |

## 3. Why this is a small change, not a rewrite

**V** `principal_authority` is **not** constrained to be an OIDC issuer. It is
a `String`. The only validation is `key.digest()?`, which refuses an empty or
oversized field (`identity.rs:96-98`). Nothing anywhere requires it to be a
URL, and nothing parses it.

**V** The constraint lives entirely in one producer — `account_key()` at
`identity.rs:71-98` — which takes `Option<&VerifiedIdentity>` and refuses
`None` with `MissingVerifiedPrincipal`.

So the change is to widen *who may mint a principal*, not to change the store,
the key, the digest, or the schema.

### 3.1 The guard that must survive

**V** `identity.rs:73-75` carries a deliberate property:

> Five fields, five sources, nothing else. `email`, `name` and `groups` are
> never read — not by omission but by construction: they are not mentioned
> below, so no future edit can quietly admit one without appearing in a diff.

That property is *single-diff-site auditability*, and it is worth keeping. This
proposal therefore does **not** add call sites that bypass `account_key()`. It
changes `account_key()`'s input from "a verified OIDC identity" to "a proven
principal", keeping exactly one construction site.

## 4. The safety argument, and why it needs no new comparison logic

The tempting design is a rank comparison: a grant proven at tier N may be
leased by a principal proven at tier ≥ N. **That is unnecessary and it is the
part that would be dangerous**, because it invites a weak local proof to open
a strong enterprise grant.

The existing key equality already does the work. The authority string
**namespaces the tier**:

```
("local",  "single-user")        # sole tier
("apikey", "alice")              # key tier
("mtls",   "alice@corp.example") # mtls tier
("https://accounts.google.com", "10769150350006150715")   # oidc tier
```

`"local"` can never equal an OIDC issuer URL. Two principals from different
tiers are simply **different keys** and never collide. No ordering, no
comparison, no bypass surface — the mechanism that prevents cross-tier
escalation is the one already under test.

The tier is therefore recorded for **audit and policy**, never for matching.

### 4.0 Two claims, and only one of them is currently true

Review separated these, correctly. They are not the same claim:

1. **Exact-key matching is sound.** A grant is reachable only by a principal
   whose `(authority, subject)` pair is byte-equal. **V** This holds today:
   `AccountKey::digest` hashes the fields and equality is over the digest.
2. **Authority strings occupy disjoint namespaces.** This is an **assumption,
   not an enforced invariant** — and it is the one §3 makes possible by
   celebrating that `principal_authority` is unvalidated. Nothing stops an
   operator configuring an identity provider whose issuer is the literal string
   `local`, which would collide with the `sole` tier exactly.

**So the invariant must be enforced, not assumed.** Reserve the tier labels
`local`, `apikey` and `mtls` as authority values, and refuse at config load any
identity provider whose issuer equals a reserved label. Fail closed, name both
the reserved word and the setting that used it.

Without that guard the design in §4 is a convention, and a convention is not a
security boundary. With it, the no-rank-comparison property is real.

### 4.1 The one real hazard, and its guard

An enterprise deployment that *also* sets `auth.single_user: true` would mint
`("local", "single-user")` for every caller, collapsing all users into one
principal — a genuine credential-sharing defect.

**Guard, fail-closed at config load:** `auth.single_user: true` is mutually
exclusive with any configured identity provider. Refuse to start and name both
settings. **I** This fits existing practice: `upgrade.rs` already treats
`single_user` as a *declared posture* rather than a runtime inference, and the
`MIK-6746.IDENTITY.1` design already refuses contradictory identity
configuration at load.

**A** Assumption needing confirmation: that no shipped deployment currently
sets both. Cheap to check before the guard lands, and the guard should name the
remedy rather than simply exiting.

## 5. What each deployment gets

**1. Single user, local laptop.** Sets `auth.single_user: true` — already the
documented advice at `upgrade.rs:144`. Principal is `("local", "single-user")`.
The 3.x migration lands there and **works**: they upgrade and keep their
grants, which is the value STORE.1 was funded to deliver and currently cannot.

**2. Family or small team, 2–10 people.** Each person gets a named API key.
Principals are `("apikey", "alice")`, `("apikey", "bob")`. Real per-user
credential isolation with no identity provider, no SSO subscription, no
Keycloak to operate. **I** This is the tier the category generally ignores:
competing gateways tend to offer single-user or full SSO with nothing between.

**3. Small team wanting cryptographic proof.** mTLS client certificates, which
already ship. Principal is `("mtls", <SAN-URI else CN>)`.

**4. Enterprise.** OIDC, unchanged. Everything above is additive.

## 6. Scope

Deliberately staged. The full ladder is not 4.0.0 work.

| Stage | Content | Why here |
|---|---|---|
| **4.0.0** | `sole` tier only, gated on `auth.single_user: true`; the §4.1 mutual-exclusion guard; the §4.0 reserved-label guard; **and carrying a `sole` principal through `VaultStrategy::prepare` (`vault.rs:133`)** | The smallest change that makes STORE.1 deliver to its actual population. Widening `account_key()` alone is not enough — the lease path is where a grant becomes usable |
| **4.1** | `key` tier — API-key-named principals | The family/small-team story; needs its own threat model, since a bearer secret is weaker than a certificate |
| **behind IDENTITY.1** | `mtls` tier | `MIK-6746.IDENTITY.1` is already building a proof ranking (`ProofSource: Ord`). This slots in behind it rather than inventing a second ranking |

### 6.1 Obligations that gate the deferred tiers

Both were raised as CRITICAL in review, and both are real. Neither blocks
4.0.0, because neither tier ships in it — but each must be closed **before its
own tier reaches production**, and recording them here is what stops a later
stage treating the tier as pre-approved.

- **`key` tier — an API key name is not a stable owner identifier.** Keys get
  rotated, renamed and reassigned. If `api_keys[].name` is the subject and a
  key is reassigned to a different person while grants are bound to that name,
  the new holder inherits the previous holder's credentials. Before shipping
  this tier: require a non-empty owner identifier that is unique, stable across
  key rotation, and refuses reassignment while any grant remains bound to it.

- **`mtls` tier — SAN-URI-or-CN is not globally unique.** If more than one
  trusted issuer can mint certificates, two independent authorities can issue
  the same subject string and their holders collapse into one principal.
  Before shipping this tier: qualify the subject by trust domain, so the
  authority half of the key distinguishes issuers rather than flattening them.

### 6.2 Vocabulary, not semantics, is what IDENTITY.1 shares

The `sole` tier is an **operator assertion**, and `MIK-6746.IDENTITY.1`'s
ranking is about **proof**. Reusing its vocabulary must not quietly add an
assertion to a proof-only enumeration, or a declared label inherits
proof-grade semantics by nothing more than sharing a type.

Whatever mechanism carries assertion-based tiers must be visibly distinct from
the proven rung at the type level. That is a question for the IDENTITY.1
design, not for this one to settle unilaterally.

**The integration rule, and it is not optional:** `MIK-6746.IDENTITY.1` already
defines a proof ladder. This proposal must **reuse** that ranking and its
vocabulary, never define a parallel one. Two independently-authored identity
rankings in one gateway is a defect waiting to happen, and the two rows are in
design simultaneously right now.

## 7. What this changes elsewhere

**It interacts with the `MIK-7334.CATALOGUE.1` descope, but only from 4.1.**
That descope rests on 4.0.0 shipping no multi-user mode, so the isolation
clause has nothing to range over.

The staging in §6 matters here, and the first version of this section
overstated the conflict. **4.0.0 ships the `sole` tier only, which is
single-user by construction and therefore does not create a multi-user mode.**
The descope premise survives 4.0.0 intact.

It is the **`key` tier in 4.1** that makes small-team deployments real, and at
that point multi-caller isolation starts to matter and the premise erodes. So
the honest statement is not "these contradict" but: ratifying the descope is
consistent with 4.0.0, and whoever ratifies it should know the premise has a
known expiry date rather than discovering it during 4.1 planning.

**It does not reopen the STORE.1 attribution decision.** Migration still runs
only from an explicit operator declaration. This proposal changes what a
declared principal may *be*, not how it is authorised.

**It does not resolve O1.** `descriptor_revision` still has no producer and
still blocks implementation independently.

## 8. What would falsify this

Two of the three were checkable immediately and were run.

1. **A shipped deployment that sets both `auth.single_user: true` and an
   identity provider.** Would make §4.1's guard a breaking change rather than a
   safety net. **A** — still open; check before implementing.

2. **A constraint on `principal_authority` that this review missed.**
   **CHECKED — survives. V** Every non-test occurrence in the tree is:
   `identity.rs:10` (a doc comment), `identity.rs:85` (the assignment),
   `mod.rs:50` (the field declaration) and `mod.rs:67` (passed to the digest as
   `.as_str()`). Nothing parses it, nothing validates its shape, nothing treats
   it as a URL. The namespacing argument in §4 holds.

3. **`account_key()` having a second caller that assumes OIDC semantics.**
   **CHECKED AND FAILED — the first version of this section was wrong.**

   **V** `src/personal_accounts/vault.rs:133` calls
   `account_key(Some(identity), &self.descriptor)` inside `VaultStrategy`, and
   the result goes straight to `custody.refresh_if_expired(&account)` at `:137`.
   That is a **production caller**, and it sits on precisely the lease path a
   migrated grant has to travel.

   The original claim — "no production caller anywhere" — came from a grep
   piped through `head -12`. An alphabetically earlier test file produced more
   than twelve hits and filled the window, so `src/personal_accounts/` was cut
   off before it was ever displayed. A truncated listing was read as a census.
   Recorded here rather than silently fixed, because the false version made the
   proposal look cheaper than it is.

   **Consequences, both real:**
   - §6's 4.0.0 stage must include carrying a `sole` principal through
     `VaultStrategy::prepare`. Widening `account_key()` alone does not deliver
     a usable grant.
   - §3.1's single-construction-site claim **survives** and should not be
     confused with this: `vault.rs` *calls* `account_key()`, it does not build
     an `AccountKey` itself. There is still exactly one construction site.

## 9. The honest cost

A single-user principal is an **operator assertion**, not a proof. If the
machine has more than one human on it, `auth.single_user: true` is a false
declaration and they share credentials. That is already true of the existing
`single_user` posture and this proposal does not worsen it — but it does extend
that assertion's blast radius from *request authorisation* to *stored OAuth
grants*, and the documentation must say so plainly rather than implying the
`local` tier is equivalent to the others.

The `sole` tier is therefore correctly the **weakest** rung, and the reason it
is safe here is §4: it cannot reach any other tier's grants, because it cannot
produce any other tier's key.
