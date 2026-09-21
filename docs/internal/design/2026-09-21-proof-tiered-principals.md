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

**V** So a deployment with no OIDC identity provider can never produce a
principal, can never match an `AccountKey`, and therefore cannot use the
per-user credential store at all.

That is the whole of O3. A 3.x single-user install upgrading to 4.0.0 is
*exactly* such a deployment, so the STORE.1 migration would be correct on disk
and deliver nothing to the population whose tokens it migrates.

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
| **4.0.0** | `sole` tier only, gated on `auth.single_user: true`, plus the §4.1 mutual-exclusion guard | The smallest change that makes STORE.1 deliver to its actual population. One producer, one guard, tests |
| **4.1** | `key` tier — API-key-named principals | The family/small-team story; needs its own threat model, since a bearer secret is weaker than a certificate |
| **behind IDENTITY.1** | `mtls` tier | `MIK-6746.IDENTITY.1` is already building a proof ranking (`ProofSource: Ord`). This slots in behind it rather than inventing a second ranking |

**The integration rule, and it is not optional:** `MIK-6746.IDENTITY.1` already
defines a proof ladder. This proposal must **reuse** that ranking and its
vocabulary, never define a parallel one. Two independently-authored identity
rankings in one gateway is a defect waiting to happen, and the two rows are in
design simultaneously right now.

## 7. What this changes elsewhere

**It weakens the `MIK-7334.CATALOGUE.1` descope argument.** That descope rests
on 4.0.0 shipping no multi-user mode, so the isolation clause has nothing to
range over. If principals become producible at several tiers, small-team
deployments become real, multi-caller isolation starts to matter, and the
premise erodes.

These two decisions should therefore be taken **together**, not separately.
Ratifying the CATALOGUE.1 descope and adopting this proposal in the same
release would be close to contradictory.

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
   **CHECKED — survives, and more strongly than expected. V** Outside its own
   definition, `account_key(` appears only in `account_resolver_fixture.rs:185`
   and in `account_resolver_tests.rs`, where the two-argument `account_key(...)`
   is a *different local test helper* entirely. There is **no production caller
   of `account_key()` anywhere**, which matches its
   `expect(dead_code, reason = "per-user OAuth scaffolding, deferred to
   post-4.0.0 backlog MIK-6744/6745/6746")` annotation.

   That last result materially lowers the cost: widening this function's input
   changes **no production call site**, because it currently has none. The
   change is confined to the function, its tests, and whatever new producer
   calls it.

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
