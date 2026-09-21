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

## 4. Mutually exclusive modes, and why that is the right shape

**Operator steer, 2026-09-21:** the authentication methods should be *mutually
exclusive operating modes* that the admin chooses — single-user local, API key,
mTLS, OIDC — enforced for everybody, rather than several active at once for
different users.

That is a better design than the tiered one this document opened with, and it
is adopted. The reason is not simplicity for its own sake: it removes a hole
that review found in the original.

The first version argued that no rank comparison was needed because `"local"`
can never equal an OIDC issuer URL, so tiers could not collide. Review was
right that **nothing enforces that** — §3 celebrates `principal_authority`
being an unvalidated string, which is exactly what would let an operator
configure an issuer literally named `local`. The disjointness was a convention
presented as a security boundary.

**With one mode per deployment there is no second namespace to collide with.**
The property stops being a rule that must be written, tested and kept true, and
becomes a consequence of the configuration. The guard disappears rather than
being implemented.

### 4.1 The mode discrimination already exists

**V** `AuthConfig::implies_multi_user()` at
`src/config/features/auth.rs:94-100`:

```rust
if !self.enabled {
    return false;
}
let hard_multi_user = self.api_keys.len() > 1 || has_oidc;
hard_multi_user || !self.single_user
```

**V** And the field's own doc comment at `:33-42` already reasons exactly the
way the steer does, as ADR-008 INV-2 (MIK-6752):

> Default `false` is deliberately fail-closed: a single shared API key or
> bearer token can be handed to a whole team, and the gateway cannot prove
> from credential count alone that only one human is behind the auth. […] More
> than one API key or any OIDC issuer is a hard multi-user signal that
> overrides this hint.

So the product **already computes the mode**, already fail-closed, already
tested, already tied to a ratified ADR. It returns "single user" only when auth
is enabled, there is at most one API key, there is no OIDC issuer, **and** the
operator has explicitly asserted it.

### 4.2 What this reduces the 4.0.0 change to

The whole of it: **when `implies_multi_user()` is false, mint one fixed
principal**, and carry it through the lease path.

| Originally proposed | Now |
|---|---|
| A new `sole` tier and vocabulary | Reuse the existing single-user determination |
| A new config key | None — `auth.single_user` already exists |
| A mutual-exclusion guard between `single_user` and OIDC | None — `implies_multi_user` **is** that guard |
| Reserved authority labels, enforced at config load | None — one mode means one authority |
| A rank comparison across tiers | None |

What remains is genuinely small: one producer behind an existing condition,
wired into `account_key()` (`identity.rs:71-98`) and carried through
`VaultStrategy::prepare` (`vault.rs:133`), plus tests.

### 4.3 The generalisation, for later

The steer's full shape is `implies_multi_user` widening from a boolean to an
enumerated mode — `SingleUser | ApiKey | Mtls | Oidc` — chosen by the admin and
enforced for every caller. That is the 4.1 direction and it subsumes §6's
staging. It should be designed once, against `MIK-6746.IDENTITY.1`, rather than
grown a mode at a time.

**One caution worth recording before that design starts:** mTLS is frequently
deployed as a *transport* requirement underneath an application-level identity,
not as an alternative to it — a deployment may reasonably want client
certificates required at the connection AND OIDC deciding who the user is.
Making those two mutually exclusive would forbid a real and sensible
configuration. The exclusivity that is clearly right is over *who the user is*;
whether it should also cover transport-level requirements is an open question
for that design, not a settled one.

## 4A. Superseded: the original tiered argument

Kept because the reason it was wrong is the reason §4 is right, and a reader
who only sees the conclusion cannot check it.

The first draft argued that no rank comparison was needed because the authority
string namespaces the tier — `("local", "single-user")` versus
`("https://accounts.google.com", "10769150350006150715")` — so principals from
different tiers are different keys and never collide.

Half of that survives and half does not:

- **Exact-key matching is sound. V** A grant is reachable only by a principal
  whose `(authority, subject)` pair is byte-equal, because `AccountKey::digest`
  hashes the fields and equality is over the digest.
- **Namespace disjointness was never enforced.** Nothing stops an operator
  configuring an identity provider whose issuer is the literal string `local`.
  §3 is what makes that possible, by establishing that `principal_authority` is
  an unvalidated string. So the disjointness was a convention presented as a
  security boundary — the precise failure mode this document warns about
  elsewhere.

The original fix was to reserve the tier labels and refuse them at config load.
The operator's mutually-exclusive-modes steer removes the need for that guard
entirely, which is why §4 supersedes this rather than patching it. **A guard
that does not have to exist cannot rot.**

### 4A.1 The hazard it worried about was already handled

The original §4.1 raised this: an enterprise deployment that *also* sets
`auth.single_user: true` would mint one principal for every caller, collapsing
all users together — a real credential-sharing defect. It proposed a new
fail-closed guard refusing that combination at config load.

**V That guard already exists and is already the shipped behaviour.**
`implies_multi_user()` (`auth.rs:94-100`) treats `has_oidc` as a *hard*
multi-user signal that overrides the `single_user` hint, and the field's doc
comment at `:33-42` states the reasoning as ADR-008 INV-2. An enterprise that
sets both is already resolved to multi-user, so the collapse cannot happen.

Two lessons worth keeping, since this document nearly shipped both mistakes:

- A proposed guard should be checked against existing behaviour before it is
  designed. This one was written from the field's *name* rather than from the
  function that consumes it, and the function was ten lines away.
- The `**A**` assumption attached to it — "no shipped deployment currently sets
  both" — was never load-bearing, because the code never let the combination
  mean what the guard feared. An assumption about deployments was standing in
  for a fact about code.

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
| **4.0.0** | Single-user mode only: mint one fixed principal when `implies_multi_user()` is false, and **carry it through `VaultStrategy::prepare` (`vault.rs:133`)** | The smallest change that makes STORE.1 deliver to its actual population. No new config key and no new guard — the condition already exists and is tested. Widening `account_key()` alone is not enough: the lease path is where a grant becomes usable |
| **4.1** | API-key mode — per-key named principals | The family/small-team story; needs its own threat model, since a bearer secret is weaker than a certificate |
| **behind IDENTITY.1** | mTLS mode | `MIK-6746.IDENTITY.1` is already building a proof ranking (`ProofSource: Ord`). This slots in behind it rather than inventing a second ranking |

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
