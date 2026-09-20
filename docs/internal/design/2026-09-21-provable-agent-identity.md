# Provable agent identity — design

- **Work item**: `MIK-6746.IDENTITY.PROVABLE` (`docs/requirements/RELEASE-4.0.0-scope-status.json`, top-level `funded_work[0]`)
- **Source**: operator ruling 2026-09-20, recorded verbatim in the `MIK-6746.CONTRACT.1` note
- **Release**: 4.0.0 · **Stage**: design · **Date**: 2026-09-21
- **Prior context**: `docs/design/2026-09-17-mik-6746-c1-mandatory-agent-audience.md`
- **Status**: DESIGN ONLY. The ruling requires design review before any code. No Rust is written by this document.

## Sections

1. The ruling, verbatim
2. Root defect, verified at source
3. The decisive finding: the verified rung does not exist
4. The new type shape
5. Call-site inventory
6. Precedence as a total function
7. What "contradicts" means
8. `known_agents` and `require_id` under the split
9. The declared label as telemetry
10. Backward compatibility and the config matrix
11. Test plan
12. Out of scope, and the stages remaining
13. Falsifier
14. Design review round 1 — findings and disposition

## 1. The ruling, verbatim

Quoted from the `MIK-6746.CONTRACT.1` note. This is the specification; nothing below weakens it.

> ROOT DEFECT: AgentIdentity carries ONE field for two different things -- who a caller PROVED they are, and what they SAY they are. The authorization check at src/security/agent_identity.rs:161 cannot tell them apart, so every downstream control over it is unsound. The precedence inversion is the symptom, not the defect.
>
> 1. SPLIT THE CONCEPT. Proven principal (mTLS subject, verified JWT claim) and declared label (X-Agent-ID header, query param) become separate fields. Everything else is cosmetic until this lands.
>
> 2. RANK BY PROOF, NOT POSITION. mTLS > verified JWT claim > declared label. A declared label CONTRADICTING a proven one is a REFUSAL, not a silent override. Verified at source before the ruling: extract_agent_identity at :104 checks X-Agent-ID first and returns immediately, so an unverified header currently beats a cryptographically verified claim -- the order is exactly inverted. The type documents its own weakness at :61: 'not authenticated -- treat as a label, not a security principal'.
>
> 3. known_agents APPLIES TO PROVEN IDENTITIES ONLY. A declared-only label can never satisfy it, and never satisfies require_id. An allowlist admitting self-declared membership is worse than absent, because the name makes operators believe a control exists.
>
> 4. KEEP THE DECLARED LABEL AS TELEMETRY. Multi-agent tracing and cost attribution need a caller-supplied tag; the feature is not wrong, its privilege is. Audit records BOTH, and a proved-A-claimed-B mismatch becomes an alertable signal -- turning the vulnerability into detection.
>
> MIGRATION: change 2 is breaking for anyone overriding identity by header. Legacy behaviour stays reachable behind an explicit allow_unverified_agent_identity opt-in that warns at startup. Concern raised and accepted by the release owner: this is a breaking default plus a new config surface on a release already carrying the identity-keyed catalogue and the 3.x credential migration.
>
> WHY IT IS WORTH IT, product rationale on record: the README sells an OWASP Agentic AI posture and self-asserted agent identity sits inside that threat model.

## 2. Root defect, verified at source

Re-verified independently on 2026-09-21 against the working tree, not taken from the ruling.

| Claim | Evidence |
|---|---|
| One field carries both meanings | `src/security/agent_identity.rs:60-66` — `AgentIdentity { id: String, source: IdentitySource }`. The doc comment at `:61-62` says the value is "not authenticated — treat as a label, not a security principal, unless combined with mTLS or JWT verification". |
| The header wins, and wins first | `src/security/agent_identity.rs:105-111`. The comment at `:105` reads "X-Agent-ID header (highest precedence)"; the branch returns before the JWT branch at `:114` is reached. The module header repeats the order at `:10-15`. |
| `source` is never consulted in an authorization decision | `src/security/agent_identity.rs:161` — `!config.known_agents.contains(&identity.id)`. `identity.source` appears nowhere in `validate_agent_identity` (`:142-169`). `IdentitySource` is constructed at `:109`, `:117`, `:125` and read only by its `Display` impl at `:79-87`. |
| Consequence | Anyone able to set an HTTP header presents as any allowlisted agent, on both dispatch routes. |

Both production call sites run extract-then-validate before the body is read: `src/gateway/router/handlers.rs:603` and `:613` for `/mcp`, `src/gateway/router/backend_handlers.rs:517` and `:522` for `/mcp/{name}` and `/mcp/{name}/{*path}`. The route parity established by d7a59a95 means the defect is symmetric across both, and so is the fix.

## 3. The decisive finding: the verified rung does not exist

**The `agent_id` reaching this code is merely parsed. It is never verified, by anything, anywhere.** Stating it loudly because it changes change 2 from a reordering into a build.

Three facts, each checked at source:

1. `extract_jwt_agent_id` (`src/security/agent_identity.rs:187-196`) splits the bearer string on `.`, base64-decodes segment 1, and reads `agent_id` out of the JSON. No signature check. The doc comment at `:182-186` states this outright — "Decode a JWT payload without verifying the signature" — and defends it with "Cryptographic verification is left to the JWT middleware layer (key server / OAuth) which runs before this code."
2. That defence does not hold for this claim — but the reason needs stating precisely, because the loose version misdescribes what a signature covers. `agent_id` occurs **zero times** in `src/gateway/oauth/jwt.rs`. The verified claim set `AgentClaims` (`jwt.rs:50-67`) is `sub`, `iss`, `aud`, `exp`, `iat`, `scope`. A JWT signature covers the **whole payload**, so an `agent_id` sitting in a token that `validate_agent_token` accepted *is* authenticated by that signature; being absent from `AgentClaims` means it is not deserialized or semantically validated, not that it is outside the signed bytes. The defect is narrower and still fatal: `extract_jwt_agent_id` never consults `validate_agent_token` at all. It reads the field out of an **unverified** base64 decode of an arbitrary bearer string, on a path that runs whether or not agent auth is enabled (`oauth/mod.rs:105-107` returns early when it is off). So the value that reaches the allowlist is unauthenticated in fact, regardless of what a signature elsewhere would have covered. This also lowers the cost of route (a) below: adding `agent_id` to `AgentClaims` makes it verified by deserializing it from an already-signature-checked payload, not by adding a new verification step.
3. The bearer string is not even required to be a validated token. `extract_jwt_agent_id` parses whatever sits after `Bearer `, so a caller can mint an arbitrary unsigned three-segment string and have its `agent_id` accepted.

So the ruling's middle rung — "verified JWT claim" — has no implementation to reorder. It has to be built.

### There is, however, an already-verified agent principal

`crate::gateway::oauth::AgentIdentity` (aliased `OAuthAgentIdentity` at every call site) is constructed at `src/gateway/oauth/mod.rs:137-143` **only** on the `Ok` arm of `validate_agent_token` (`:127`). Its `client_id` is the verified JWT `sub` (`:138`), and the comment at `:134-135` records the intent: "Authority follows the registration, not the token bytes or the operator-chosen display name."

It reaches both call sites. `agent_auth_middleware` is layered on `routes` at `src/gateway/router/mod.rs:281-284`, and `/mcp/{name}` is registered into `routes` at `:256`, before that layer is applied. The comment at `:286-291` records the wrapping order: a layer added later runs earlier, so agent auth is innermost — after authentication, before the handler. Both handlers already pull it out of extensions: `handlers.rs:584-587` and `backend_handlers.rs:490`. mTLS `CertIdentity` (`src/mtls/identity.rs:30`) is likewise already in scope at `handlers.rs:583` and `backend_handlers.rs:489`.

**The proven principals are already sitting at both call sites. `extract_agent_identity` simply is not given them.**

### DECISION 3.1 — source the verified rung from `OAuthAgentIdentity`, not from a new claim

Two routes were considered.

- **(a)** Add `agent_id` to `AgentClaims` and plumb it out of `ValidatedToken`. Literal fidelity to the ruling's words.
- **(b)** Use `OAuthAgentIdentity.client_id` as the proven principal and delete `extract_jwt_agent_id` outright.

**Chosen: (b).** Reasons, in order of weight:

1. It removes the unsigned parser rather than leaving it beside a verified sibling. Leaving `extract_jwt_agent_id` in the tree after this work is the single most likely way for the defect to come back.
2. `client_id` is already bound to a registry entry, so a proven principal is by construction a name the operator configured. A new `agent_id` claim would be self-chosen by the token holder and would need its own registry binding to mean anything — that is route (a)'s hidden cost.
3. It is not weaker than the ruling. The ruling asks for a cryptographically verified claim to outrank a header; `sub`, verified against registered key material, is that claim under its standard name.

Migration cost of (b) checked, not assumed: no shipped configuration sets `known_agents`. The only occurrences outside the module are test fixtures (`src/gateway/router/tests.rs:3823`, `:3856`, `:3878`, `:3896`, and `src/security/agent_identity.rs:447`, `:464`), holding short labels such as `known-agent` and `agent-allowed`. Operators who set their own allowlist will be listing agent labels; under (b) those entries must become registered `client_id` values. That is a real migration step and belongs in the upgrade notes — see section 10.

Route (a) is **not** discarded, it is deferred: if operators need an agent identifier distinct from `client_id`, add `agent_id` to `AgentClaims` and populate the proven principal from `ValidatedToken`. That is an additive change on top of this design and needs no rework of the type shape below.

## 4. The new type shape

Change 1 of the ruling: "Proven principal (mTLS subject, verified JWT claim) and declared label (X-Agent-ID header, query param) become separate fields."

```rust
/// Resolved identity for the calling agent.
///
/// Two independent facts, never merged: who the caller PROVED they are, and
/// what they merely SAY they are. Authorization reads `proven` only.
pub struct AgentIdentity {
    /// Cryptographically established principal. `None` when the caller
    /// presented no proof. NEVER populated from a caller-supplied header,
    /// query parameter, or unverified token payload.
    pub proven: Option<ProvenPrincipal>,
    /// A weaker proof presented alongside `proven` and outranked by it
    /// (rows 7 and 8: a verified JWT behind an mTLS certificate). Audited,
    /// never authorized on, never compared against `declared`. Without this
    /// field the row-7 promise to audit the JWT `sub` is unimplementable —
    /// the stronger proof would simply overwrite it.
    pub secondary_proof: Option<ProvenPrincipal>,
    /// Caller-supplied tag. Telemetry and attribution only; carries no
    /// privilege and can never satisfy an authorization control.
    pub declared: Option<DeclaredLabel>,
}

pub struct ProvenPrincipal {
    /// The principal's identifier: the mTLS subject, or the verified JWT `sub`.
    /// For mTLS the selection is fixed and total, never best-effort: first SAN
    /// URI, else CN, else **no principal is constructed at all**. A certificate
    /// carrying neither is not an identity; the existing `display_name`
    /// fallback (`handlers.rs:93-103`) synthesises a human string and must not
    /// be reachable from this field, or an unnameable certificate silently
    /// becomes an allowlist key. Such a handshake is treated as "no proof":
    /// row 1 of the section 6 table, refused under `require_id` or a
    /// non-empty `known_agents`.
    pub id: String,
    pub proof: ProofSource,
}

/// Ordered by strength. Ranking is the discriminant order, not a call order.
#[derive(PartialOrd, Ord)]
pub enum ProofSource {
    /// Verified JWT `sub`, from `validate_agent_token`.
    VerifiedJwtSubject,
    /// mTLS client-certificate subject, from the TLS handshake.
    MutualTls,
}

pub struct DeclaredLabel {
    pub id: String,
    pub source: DeclaredSource,
}

pub enum DeclaredSource {
    Header,
    QueryParam,
}
```

Notes on the shape:

- `IdentitySource` is replaced by two enums. The split is the point: there is no longer a single enum whose variants mix proof levels, so no future call site can pattern-match a proven and a declared case into one arm by accident.
- `ProofSource` derives `Ord` with `MutualTls` last, so "rank by proof" is a comparison on the type rather than a hand-written chain that a later edit can reorder. This is the structural guard against the defect recurring: the current bug is precisely a precedence encoded as statement order.
- `JwtClaim` as a variant disappears. Under DECISION 3.1 the unsigned decode is deleted, so there is no source that is JWT-shaped and unproven.
- Both fields are `Option`, and `AgentIdentity` is now always constructed — never `Option<AgentIdentity>`. "No identity at all" is `AgentIdentity { proven: None, declared: None }`. This removes the `Option<Option<..>>` awkwardness at the call sites and makes the refusal logic a single total match. See section 5 for what that does to the two production callers.

### Extraction signature

`extract_agent_identity` must be given the proven inputs it currently cannot see:

```rust
pub fn extract_agent_identity(
    headers: &HeaderMap,
    query: Option<&str>,
    cert_identity: Option<&CertIdentity>,
    oauth_agent_identity: Option<&OAuthAgentIdentity>,
) -> AgentIdentity
```

The `bearer_token: Option<&str>` parameter is removed. Dropping it is what makes the unsigned decode unreachable, and it deletes the bearer-extraction block duplicated at `handlers.rs:594-601` and `backend_handlers.rs:510-516`.

### Prior art in this repo

`caller_grant_subject` (`src/gateway/router/handlers.rs:51-67`) already resolves a caller identity by ranked source — verified OIDC identity, then operator-trusted headers, then `CertIdentity`, then `OAuthAgentIdentity` — into `GrantSubject { authority, subject, label }`. This design deliberately mirrors its ordering discipline and its authority-plus-label shape rather than inventing a third vocabulary.

One difference is intentional and must not be copied: `caller_grant_subject` ranks trusted headers **above** mTLS, gated on `state.meta_mcp.trust_caller_identity_headers()` (`handlers.rs:61-64`, `:1452`). That is an operator explicitly delegating identity to a front proxy. `X-Agent-ID` has no such gate and no such operator intent, so it does not inherit that standing.

## 5. Call-site inventory

Every construction and read of `security::AgentIdentity`, enumerated with `rg` and cited. A type split that misses a construction is a compile error at best and a silent bypass at worst.

### Headline: zero external construction sites

`security::AgentIdentity` is constructed **only inside its own module**. All three `AgentIdentity { .. }` literals in `src/gateway/router/tests.rs` (`:1798`, `:3116`, `:3248`) are the **OAuth** `AgentIdentity` from `src/gateway/oauth/mod.rs:59`, identifiable by their `quota_principal` and `client_id` fields. The two types share a bare name and are distinguished only by import path and by the `OAuthAgentIdentity` alias at the router call sites.

Closed by import sweep, not only by literal search: the sole importers of the type across `src/` are `src/gateway/router/handlers.rs:39` (`extract_agent_identity`, `validate_agent_identity`) and the re-export at `src/security/mod.rs:35-37`; `backend_handlers.rs` calls both fully qualified at `:517` and `:522` without importing. `src/config/features/security.rs:8` imports `AgentIdentityConfig` only. No other module in the tree references the type, so the sixteen production sites below are the complete blast radius.

**Name collision is the main hazard in this work.** Any reviewer or implementer skimming for `AgentIdentity` will hit the OAuth type more often than the one being changed. Recommendation carried into implementation: rename nothing in this change, but require every reviewer diff-comment on an `AgentIdentity` literal to state which of the two it is.

### Production sites — these are the whole blast radius

| # | Site | What it does today | After the split |
|---|---|---|---|
| 1 | `src/security/agent_identity.rs:107-110` | builds `{ id, source: Header }`, returns immediately | becomes a `declared` assignment; no early return |
| 2 | `src/security/agent_identity.rs:115-118` | builds `{ id, source: JwtClaim }` from the unsigned decode | **deleted** with `extract_jwt_agent_id` (DECISION 3.1) |
| 3 | `src/security/agent_identity.rs:123-126` | builds `{ id, source: QueryParam }` | becomes a `declared` assignment, fallback after the header |
| 4 | `src/security/agent_identity.rs:100-130` `extract_agent_identity` | returns `Option<AgentIdentity>` | new signature, returns `AgentIdentity`; gains the two proven inputs |
| 5 | `src/security/agent_identity.rs:142-169` `validate_agent_identity` | allowlist on `identity.id`, `source` unread | total match on `(proven, declared)`; see section 6 |
| 6 | `src/security/agent_identity.rs:161,164` | `known_agents.contains(&identity.id)` and its message | tests `proven.id` only; message names the policy |
| 7 | `src/security/agent_identity.rs:187-196` `extract_jwt_agent_id` | unsigned base64 decode of `agent_id` | **deleted** |
| 8 | `src/security/mod.rs:35-37` | re-exports `AgentIdentity`, `AgentIdentityConfig`, `IdentitySource`, both functions | `IdentitySource` replaced by `ProofSource` and `DeclaredSource` |
| 9 | `src/gateway/router/handlers.rs:603` | `extract_agent_identity(&headers, query_str, bearer_token)` | pass `cert_identity.as_ref()` and `oauth_agent_identity.as_ref()`, both already bound at `:583` and `:584-587` |
| 10 | `src/gateway/router/handlers.rs:613` | `validate_agent_identity(agent_identity.as_ref(), ..)` | drops the `.as_ref()`; refusal shape unchanged |
| 11 | `src/gateway/router/handlers.rs:594-601` | bearer-token extraction feeding site 9 | **deleted**, unused after the signature change |
| 12 | `src/gateway/router/handlers.rs:1448` | `agent_id = agent_identity.as_ref().map(\|a\| a.id.as_str())` into the dispatch audit path | must choose proven vs declared — see section 9 |
| 13 | `src/gateway/router/handlers.rs:1900` | same read into `tasks::RecoveryCaller.agent_id` | same choice |
| 14 | `src/gateway/router/backend_handlers.rs:517-521` | `extract_agent_identity(..)` on the direct route | same change as site 9; `cert_identity` at `:489`, `oauth_agent_identity` at `:490` |
| 15 | `src/gateway/router/backend_handlers.rs:522-527` | `validate_agent_identity(..)`, refuses `-32600` with `StatusCode::FORBIDDEN` | signature change only; refusal shape unchanged |
| 16 | `src/gateway/router/backend_handlers.rs:510-516` | bearer-token extraction feeding site 14 | **deleted** |

Beyond the type itself, this work adds two fields to `AgentIdentityConfig` — `allow_unverified_agent_identity` (section 10) and `principal_labels` (section 7). The config surface is `src/config/features/security.rs:8` (which re-exports `AgentIdentityConfig`), `:583` and `:627`, and `src/config/mod.rs:36`. Both fields are additive under the existing `#[serde(default)]` on the struct (`src/security/agent_identity.rs:35-37`), so no existing configuration fails to parse; the behaviour change is in validation, not deserialization.

Downstream of sites 12 and 13, `agent_id` travels as a plain `Option<&str>` — `tasks.rs:112`, `:171`, `:211`, `:295` — so no type change propagates past the router. That boundary is what keeps the blast radius at sixteen sites.

### Test sites requiring rework

In-module: constructions at `src/security/agent_identity.rs:309`, `:335`, `:379`, `:449`, `:466`, `:485`; `extract_agent_identity` calls at `:305`, `:321`, `:331`, `:348`, `:361`, `:375`, `:394`; `validate_agent_identity` calls at `:410`, `:423`, `:435`, `:455`, `:471`, `:491`. Route-level: the C5 parity block at `src/gateway/router/tests.rs:3742-3900`, whose fixtures at `:3792`, `:3823`, `:3856`, `:3878`, `:3896` set `known_agents` and today pass with a header-only caller.

One of these encodes the defect as expected behaviour and must be **inverted, not ported**: `extract_from_jwt_claim` (`:366-384`) builds a token with `alg: none` at `:372` and asserts it resolves to `IdentitySource::JwtClaim`. A port that keeps it green keeps the bug.

`extract_header_takes_precedence_over_query` (`:342-353`) survives unchanged: header over query is still the right order **within** the declared label, which is where that comparison now lives.

Worth recording for the test review: **the inverted precedence is not pinned by any test today.** There is no header-beats-JWT case in the module — the suite covers header, query, header-over-query, whitespace, JWT-present, and JWT-without-claim, and never the combination that constitutes the vulnerability. The defect survived because nothing asserted the wrong behaviour, not because something asserted it.

## 6. Precedence as a total function

Change 2: "mTLS > verified JWT claim > declared label. A declared label CONTRADICTING a proven one is a REFUSAL, not a silent override."

Three independent inputs, so eight combinations. Every one has a defined outcome; there is no residual case.

Inputs: **M** = mTLS `CertIdentity` present (`handlers.rs:583`, `backend_handlers.rs:489`). **J** = verified `OAuthAgentIdentity` present (`handlers.rs:584-587`, `backend_handlers.rs:490`; only ever constructed on the `Ok` arm of `validate_agent_token`, `oauth/mod.rs:127-143`). **D** = declared label present (`X-Agent-ID` header, else `agent_id` query param).

Table assumes `security.agent_identity.enabled = true`. When it is `false`, `validate_agent_identity` returns `Ok(())` at `:146-148` and every row is "accept, no enforcement" — unchanged.

| # | M | J | D | Proven principal | Outcome |
|---|---|---|---|---|---|
| 1 | no | no | no | none | **Refuse** if `require_id = true` (no ID at all). **Refuse** if `known_agents` is non-empty: an allowlist that admits an anonymous caller is not an allowlist, and today `:161` skips the check entirely when no identity resolves. Accept only when both controls are off. |
| 2 | no | no | yes | none | **Refuse** if `require_id = true`, and **refuse** if `known_agents` is non-empty — a declared-only label satisfies neither (change 3). Accept as unprivileged if both are off; the label is recorded as telemetry only. **This row is the breaking change.** |
| 3 | no | yes | no | JWT `sub` | Accept. Allowlist checked against `sub`. |
| 4 | no | yes | yes | JWT `sub` | Accept if the label is **consistent** with `sub`; **refuse** on contradiction (section 7). |
| 5 | yes | no | no | mTLS subject | Accept. Allowlist checked against the mTLS subject. |
| 6 | yes | no | yes | mTLS subject | Accept if consistent; **refuse** on contradiction. |
| 7 | yes | yes | no | **mTLS subject** (mTLS outranks JWT) | Accept. The JWT `sub` is recorded in audit as a secondary proof, never as the principal. |
| 8 | yes | yes | yes | **mTLS subject** | Accept if the label is consistent with the mTLS subject; **refuse** on contradiction. The JWT `sub` is audited, not compared against the label — one principal, one comparison. |

Three properties this table has that the current code does not:

1. **The declared label never becomes the principal.** In rows 3 through 8 it cannot override; in row 2 it cannot satisfy a control. There is no path from `X-Agent-ID` to an authorization pass.
2. **Rank is by proof, not by call order.** Rows 7 and 8 resolve to mTLS through `ProofSource: Ord`, not through which branch a function happens to check first. The defect at `:105-111` is a precedence encoded as statement order; this design replaces that encoding.
3. **Contradiction is refusal, never silent preference.** Rows 4, 6 and 8 refuse rather than quietly ignoring the label. Silently preferring the proven value would satisfy "the header cannot escalate" but would lose the detection signal the ruling asks for in change 4.

### Refusal shape

Unchanged from the C5 precedent: JSON-RPC `-32600` with `StatusCode::FORBIDDEN` (`handlers.rs:615`, `backend_handlers.rs:526`), message naming the policy that refused. The C5 review specifically required the policy name in the message so an unrelated 403 cannot mask a missing guard; contradiction refusals inherit that requirement and must name the contradiction, not merely say "forbidden".

## 7. What "contradicts" means

The ruling says a declared label contradicting a proven one is a refusal. "Contradicts" has to be defined operationally here, or the implementer guesses — and the obvious guess breaks every mTLS deployment.

**The trap.** The three identifiers live in different namespaces. An mTLS subject is a SAN URI or a CN (`src/mtls/identity.rs:30`, read via `san_uris` then `common_name` then `display_name` at `handlers.rs:93-103`). A verified JWT `sub` is a registered `client_id`. `X-Agent-ID` is an arbitrary short string chosen by the caller. A naive `proven.id != declared.id` refusal would reject every caller that presents a client certificate **and** sets `X-Agent-ID`, because `spiffe://cluster/ns/agents/sa/runner` never string-equals `runner`. That is a usability outage discovered at integration time, not a security win.

### DECISION 7.1 — contradiction refuses by default; the soft edge is an operator opt-in

A declared label **contradicts** the proven principal when the two are comparable and differ. "Comparable" is established by configuration, never guessed. Every rule below is keyed by the **pair** `(proof source, id)`, never by a bare identifier — see DECISION 7.2.

1. **Exact match.** `declared.id == proven.id` — consistent. The common case under DECISION 3.1, where the proven id is a `client_id`.
2. **Operator mapping.** `agent_identity.principal_labels` maps a `(proof source, proven id)` pair to the set of labels it may declare. A declared label outside that set is a **contradiction** — refuse.
3. **Explicit waiver.** A principal whose entry is the waiver variant declares that its labels are in a namespace the gateway cannot compare. Any label is accepted and the pair is audited. The waiver is a **distinct config shape**, not a reserved string: the value is `{ labels = [...] }` or `{ incomparable = true }`, so no real label can collide with it and a one-element label set cannot be mis-written into a waiver. (An earlier draft used an `unmapped_ok` sentinel value; a sentinel inside the label namespace it governs is a misconfiguration waiting to happen.)

**Coverage is required only where the principal set is enumerable.** When `agent_identity.enabled` is set and declared labels are accepted, `principal_labels` must cover every **enumerable** configured principal — the JWT `client_id` registry, and any mTLS policy that lists explicit subjects. This is enforced at **startup**, alongside the validation section 10 already requires.

### DECISION 7.2 — the census is scoped to what config can enumerate; non-enumerable proof sources take a namespace waiver

An earlier draft required `principal_labels` to cover *every* configured principal, full stop. **mTLS cannot satisfy that**, verified at source: the match modes are `any`, an OU match, and SAN globs (`src/mtls/`, and `support.rs:627-628` already distinguishes handshake-required mTLS from `enabled` alone), so the admissible subject set is defined by a CA trust store and a pattern — it is not a list the gateway can walk at startup. A startup check demanding a total census would either never pass for a glob policy or would have to be quietly skipped, and a gate that is quietly skipped is worse than no gate.

The census therefore has two tiers:

| Proof source | Enumerable? | Startup requirement |
|---|---|---|
| Verified JWT `sub` | yes — the `client_id` registry | every registered client needs a `principal_labels` entry (label set or waiver) |
| mTLS, explicit subject list | yes | every listed subject needs an entry |
| mTLS, `any` / OU / SAN glob | **no** | a single **namespace-level** waiver for the proof source, written explicitly; startup refuses if declared labels are accepted and no namespace entry exists |

The property preserved is the one that mattered: the operator states in configuration that a namespace is incomparable, rather than the gateway inferring it. What is given up is per-principal granularity for glob policies, which was never available to begin with.

### DECISION 7.3 — no cross-namespace credential combining

Keying by bare identifier lets two independent namespaces collide. A caller presenting a valid client certificate for principal **A** and a valid JWT for principal **B** must not combine A's `known_agents` membership with B's scopes. Both `known_agents` and `principal_labels` are therefore keyed by `(proof source, id)`, and the resolved principal is a single `(source, id)` pair chosen by `ProofSource: Ord` — the losing credential is audited (section 9) and grants nothing. String equality between an mTLS CN and a JWT `sub` is a coincidence, never an identity.

That closes the namespace trap without weakening change 2:

- Contradiction-is-refusal is the **default**, matching the ruling literally. It fires on every mismatch in a mapped namespace.
- The mTLS case still works: an operator whose SAN URI cannot be compared to a short label sets the waiver. The operator states the namespace is incomparable; the design does not assume it.
- The difference from a guessed soft edge is where the burden sits. Under a default-accept rule the gateway silently decides two identifiers are incomparable and the operator never learns. Under the waiver the operator writes it down, which is also what makes the audit signal meaningful — a mismatch under a waiver is expected, a mismatch under a mapping is an incident.

**The naive alternative, rejected:** `proven.id != declared.id` refuses unconditionally. This looks like the most literal reading of change 2 but rejects every caller presenting a client certificate and an `X-Agent-ID`, because `spiffe://cluster/ns/agents/sa/runner` never string-equals `runner`. It refuses on namespace difference rather than on contradiction, which is a different property than the one the ruling asks for, and it makes mTLS plus a declared label unusable.

**Cost, stated plainly:** requiring `principal_labels` adds a mandatory config step for any deployment combining enforcement with declared labels. That is a second new config surface on top of `allow_unverified_agent_identity`, on a release the ruling already notes is carrying the identity-keyed catalogue and the 3.x credential migration. It is the price of not having the gateway guess about identity, and it is flagged here for the design reviewer rather than absorbed quietly.

## 8. `known_agents` and `require_id` under the split

Change 3: "known_agents APPLIES TO PROVEN IDENTITIES ONLY. A declared-only label can never satisfy it, and never satisfies require_id."

New behaviour of `validate_agent_identity`:

| Config | Today (`:142-169`) | After |
|---|---|---|
| `enabled = false` | `Ok(())` at `:146-148` | unchanged |
| `require_id = true`, nothing present | refuse (`:151-157`) | unchanged |
| `require_id = true`, declared label only | **accept** — `:150` sees `Some`, `:161` allowlist skipped when empty | **refuse**: a label is not an ID |
| `require_id = true`, proven present | accept | unchanged |
| `known_agents` non-empty, declared label only | **accept if the label is listed** (`:161`) | **refuse**: the allowlist is not satisfiable by self-declaration |
| `known_agents` non-empty, proven present | accept if `identity.id` listed | accept if the `(proof source, proven.id)` pair is listed (DECISION 7.3); the label is not consulted |
| `known_agents` non-empty, **nothing** present | **accept** — `:161` is skipped when no identity resolves | **refuse**: an allowlist cannot admit an anonymous caller |

Three rows flip from accept to refuse. They are the vulnerability.

The module documentation has to change with them. `src/security/agent_identity.rs:24` currently describes `known_agents` as an "optional allowlist of accepted agent IDs", and `:27-28` states the allowlist applies only "when `known_agents` is non-empty and `require_id` is true" — which the C5 review already found wrong at source, since `:161` runs whenever an identity resolves. Both must be rewritten to say the allowlist is a **proven-principal** allowlist. The C5 review recorded the reason plainly and it still holds: `known_agents` is a declared-label policy, not a cryptographic allowlist, and the name implies otherwise. This change makes the name true rather than continuing to document around it.

## 9. The declared label as telemetry

Change 4: "Multi-agent tracing and cost attribution need a caller-supplied tag; the feature is not wrong, its privilege is. Audit records BOTH."

Sites 12 and 13 in the inventory (`handlers.rs:1448`, `:1900`) currently flatten the identity to one `Option<&str>`. Under the split they must choose, and the choice differs by purpose:

- **Audit** records both, always, as distinct fields: `agent_proven`, `agent_proof` (the `ProofSource`), `agent_declared`, `agent_declared_source`. A record that collapses them cannot distinguish "agent-a proved it" from "someone said agent-a", which is the property the whole change exists to create.
- **Authorization** reads `proven` only. Already covered by section 6; named again here so no later reader takes "audit records both" as licence to authorize on the declared value.
- **Attribution and tracing** (`tasks::RecoveryCaller.agent_id`, `tasks.rs:112`, `:211`) keep using the declared label when present, falling back to the proven id. Cost attribution wants the caller's own tag, and a caller that lies about its tag mis-attributes its own costs and no one else's. This is the one place the declared label stays primary — and it is safe **only** because DECISION 9.1 below removes the other consumer of the same flattened value.

### DECISION 9.1 — identity grants authorize on the proven id, not the flattened label

An earlier draft of this section asserted that nothing downstream of the flattened `agent_id` makes an access decision. **That is false, verified at source.** `handlers.rs:1448` builds `agent_id` from the conflated `AgentIdentity.id` — which today is header-first (`agent_identity.rs:100-167`) — and carries it into `MetaMcpCallerContext.agent_id` (`:1597`) and the task-intent request (`:1566`). From there it reaches `IdentityGrantStore` evaluation: `identity_grants.rs:608` passes `request.agent_id` to `Grant::covers`, which calls `self.agent.matches(agent_id)` (`:232`), and `GrantAgent::Exact(expected) => agent_id.is_some_and(|actual| actual == expected)` (`:65-68`) is bare string equality.

**The consequence today:** a grant scoped to `GrantAgent::Exact("agent-a")` is satisfied by any caller that sets `X-Agent-ID: agent-a`. The grant system's agent scoping is an unauthenticated string match. This is the same defect as the header-over-mTLS override, on a second surface, and it is in scope here because the ruling's change 3 — controls apply to proven identities only — cannot hold while it stands.

Under the split, the single `agent_id` field becomes two, and the consumers divide by purpose:

| Consumer | Field | Rationale |
|---|---|---|
| `IdentityGrantRequest.agent_id` → `GrantAgent::matches` | **proven id only** | An access decision. A declared label must never satisfy it. |
| `MetaMcpCallerContext` audit / `agent_declared` | both, distinct | Section 9's audit rule. |
| `tasks::RecoveryCaller.agent_id` | declared, falling back to proven | Attribution, no access decision — the claim holds for this consumer alone. |

`GrantAgent::Exact` keeps its shape; what changes is what is passed to it. Grants minted under 3.x against a declared label stop matching once the caller can no longer prove that label — which is the vulnerability closing, not a regression, and it is listed in section 10's breaking-change set and section 11's Tier 1 rows.
- **Mismatch signal**: when a proven principal and a declared label are both present and differ under a DECISION 7.1 rule 3 waiver, audit emits `declared_label_mismatch` with both values. Under rules 1 and 2 the same situation is a refusal — and **the refusal path emits no audit record today**, verified at source: `handlers.rs:612-618` returns `build_http_error_response(None, -32600, reason, FORBIDDEN)` straight from the `validate_agent_identity` error arm, with no audit call, and `backend_handlers.rs:526` has the same shape. So "the refusal is already its own audit record" is false as written. Emitting an identity audit event on the refusal arm is therefore **new work in this change**, not an existing property being relied on; it is listed in section 12's stages and carries its own Tier 3 test row. Without it, the ruling's detection signal exists only on the waiver path, which is the one path an attacker is least likely to be on.

That last bullet is the ruling's "turning the vulnerability into detection", and it is the part that is cheapest to drop under implementation pressure. It is load-bearing for the ruling and is listed as a distinct test row in section 11.

## 10. Backward compatibility and the config matrix

This change alters who gets refused. That is a decision recorded here, not a side effect.

### DECISION 10.1 — the breaking change is taken, default-on, at 4.0.0

Row 2 of the precedence table is the break. A deployment today that sets `X-Agent-ID` and nothing else, with `agent_identity.enabled = true` and either `require_id = true` or a non-empty `known_agents`, **passes**. After this change it **refuses**. Those deployments do not keep working on the new default, and that is the intent: they are precisely the deployments that believe they have an access control and do not.

Permitted because 4.0.0 is a major release. Recorded because the ruling requires it to be a decision.

The escape hatch is the one the ruling names: `security.agent_identity.allow_unverified_agent_identity`, default `false`. When `true`, a declared-only label may satisfy `require_id` and `known_agents` exactly as today, and the gateway **warns at startup** naming the control that is weakened. Legacy behaviour stays reachable; it stops being the default.

**What the hatch does not restore, stated because its name implies otherwise.** It restores exactly one behaviour: row 2 of the precedence table — declared-only may satisfy `require_id` and `known_agents`. It does **not** restore header-over-proof. With the hatch on, a declared label still never outranks a proven principal (rows 3–8 are unchanged) and a contradiction is still a refusal. The hatch also does not touch DECISION 9.1: identity grants authorize on the proven id whether or not it is set, because a hatch that re-opened grant matching to declared labels would re-open the vulnerability rather than defer it.

**The mis-aimed-hatch trap.** The operator most likely to reach for this flag is the one running mTLS or a JWT *and* sending `X-Agent-ID` — and they will still get a 403, because their failure is a section 7 contradiction, not an unproven identity. Their fix is `principal_labels` (a label set or an incomparable-namespace waiver), which the ruling did not name. The startup warning and the migration note must both say so explicitly, or this flag becomes the first thing tried and the last thing that helps. Renaming it is out of scope — the ruling names the flag — so the documentation carries the correction.

**The hatch exempts obligation 1.** Startup refusal below fires only when the hatch is `false`. With it `true`, a deployment with no proof source configured is coherent — declared labels satisfy the controls — and must start.

### The interaction that makes a gateway unreachable

The more serious compatibility consequence is not the header-only deployment. It is this: **`security.agent_identity` and the sources of proof are independently gated, and an operator can enable enforcement with no proof source available at all.**

- `security.agent_identity.enabled` defaults `false` (`src/security/agent_identity.rs:38-39`).
- `agent_auth.enabled` defaults `false` (`src/config/features/auth.rs:209-211`), and `AgentAuthState` is built from it at `src/gateway/server/mod.rs:1645`. When it is off, `agent_auth_middleware` returns at `oauth/mod.rs:105-107` and no `OAuthAgentIdentity` is ever inserted.
- mTLS is separately configured and optional.

| `agent_identity.enabled` | `require_id` / `known_agents` | agent auth | mTLS | Result |
|---|---|---|---|---|
| false | any | any | any | No enforcement. Unchanged, and this is the shipped default. |
| true | both off | any | any | Extraction and audit only. Works with or without proof. |
| true | either on | on | any | Works. JWT `sub` is the principal. |
| true | either on | off | on | Works. mTLS subject is the principal. |
| true | either on | **off** | **off** | **Every request refuses.** No proof source exists, so no caller can ever satisfy the control. |

That last row is a dead gateway produced by a config that looks reasonable, and it is reachable from today's working configuration by upgrading alone. Three obligations follow:

1. **Startup validation must refuse this combination**, not discover it per request. `agent_identity.enabled` with `require_id` or a non-empty `known_agents`, neither agent auth nor mTLS configured, **and `allow_unverified_agent_identity = false`**, is a configuration error — fail at startup naming both the missing proof sources and the hatch. With the hatch `true` the same combination is legal and starts with the weakening warning. A gateway that starts and then refuses everything is the worst available outcome.
2. **`known_agents` values change meaning.** Under DECISION 3.1 entries must be registered `client_id` values or mTLS subjects, not free labels. No shipped configuration sets `known_agents` — the only occurrences are test fixtures (section 3) — so the repo carries no inventory to migrate, but operator configurations do.
3. **Upgrade notes.** This needs an entry in the 4.0.0 migration material alongside the identity-keyed catalogue and the 3.x credential migration, which the ruling already flags as concurrent load on this release. The migration framework at `src/commands/upgrade.rs` is the existing home for it.

### What does not break

Anything with `agent_identity.enabled = false` — the shipped default — is untouched: `validate_agent_identity` still returns `Ok(())` at its first branch. Deployments already using mTLS or agent JWT auth gain a principal they did not have and keep passing, unless they also send a contradicting `X-Agent-ID` under DECISION 7.1 rules 1 or 2. Those deployments do acquire a new mandatory config step, `principal_labels`, which section 7 records as a stated cost. Cost attribution and tracing keep receiving the declared label (section 9). The refusal shape on both routes is unchanged, so anything asserting `-32600` plus 403 stays valid.

## 11. Test plan

Test design is a separate reviewed stage; this is the plan that stage reviews, not the final suite.

**The governing rule: a test that passes against today's code proves nothing here.** Every happy path in section 6 already passes at `HEAD`. The suite's value is entirely in the refusal rows, so those are listed first and each one states what it would catch.

### Tier 1 — must fail against today's code

These are the falsifiers. If any of them passes before the implementation lands, the test is wrong, not the code.

| # | Scenario | Assert | Catches | Today |
|---|---|---|---|---|
| T1 | Declared header label listed in `known_agents`, no mTLS, no verified JWT | refuse, `-32600` plus 403, message names the proven-principal policy | change 3 — the allowlist admitting self-declaration | **accepts** (`:161`) |
| T2 | `require_id = true`, declared header label only | refuse | change 3 — a label satisfying `require_id` | **accepts** (`:150`) |
| T3 | **Contradiction.** Verified principal `agent-a`, `X-Agent-ID: agent-b`, both mapped or equal-namespace per DECISION 7.1 | refuse, message names the contradiction and both values | change 2 — the case the whole ruling exists for | **accepts, header wins** (`:105-111`) |
| T4 | Same as T3 with mTLS as the proven source | refuse | row 6; proves the rule is on `ProofSource`, not on one branch | **accepts, header wins** |
| T5 | Unsigned three-segment bearer carrying `agent_id`, `alg: none` | **not proven**; cannot satisfy `known_agents` or `require_id` | that the verified rung was really built rather than faked by keeping the unsigned decode | **accepts as `JwtClaim`** (`:366-384` asserts exactly this) |
| T6 | mTLS subject `A` and verified JWT `sub` `B`, no declared label | accept, principal is the **mTLS subject**, JWT audited as secondary | row 7 — rank by proof, not by call order | no such ranking exists |

T3 is the row that matters most. T5 is the row most likely to be quietly dropped, because deleting `extract_jwt_agent_id` makes it feel redundant — it is not: it pins that the deletion happened.

### Tier 2 — regression, must keep passing

| # | Scenario | Assert |
|---|---|---|
| T7 | `agent_identity.enabled = false`, any combination of inputs | accept, no enforcement, unchanged |
| T8 | `require_id = true`, nothing present at all | refuse (row 1, unchanged today) |
| T9 | Verified principal listed in `known_agents`, no declared label | accept (rows 3 and 5) |
| T10 | Header and query both set, no proof | header wins **within** the declared label; both rejected as principal |
| T11 | Whitespace-only `X-Agent-ID` | treated as absent, as today (`:356-363`) |

### Tier 3 — the new surfaces

| # | Scenario | Assert |
|---|---|---|
| T12 | `allow_unverified_agent_identity = true`, declared-only label listed in `known_agents` | accept — legacy path reachable — **and** a startup warning was emitted |
| T13 | `agent_identity.enabled = true`, `require_id = true`, agent auth off, mTLS off | **startup fails** with a message naming both missing proof sources and the opt-in (section 10 obligation 1) |
| T14 | Waivered proven principal, unequal declared label | accept, and `declared_label_mismatch` is emitted with both values (DECISION 7.1 rule 3, change 4) |
| T14b | Mapped proven principal, declared label outside its set | **refuse** (DECISION 7.1 rule 2) |
| T14c | `agent_identity.enabled`, proven source configured, declared labels accepted, a principal absent from `principal_labels` | **startup fails** — the no-fourth-case invariant |
| T15 | Audit record for any accepted request carrying both | `agent_proven`, `agent_proof`, `agent_declared` present as distinct fields |

### Route parity

T1 through T6 run against **both** `/mcp` and `/mcp/{name}`. The C5 work (d7a59a95) established that parity is a property worth testing, and the existing parity block at `src/gateway/router/tests.rs:3742-3900` is the pattern to extend. A refusal implemented at only one call site reproduces exactly the bypass C5 closed — the fix touches `handlers.rs:603/613` and `backend_handlers.rs:517/522` symmetrically, so the tests must too.

### The three routes this design deliberately leaves alone

The call-site inventory lists a sixteen-site blast radius, which reads as a decision about every identity-bearing route. It is not. Three routes are ruled **out** here explicitly, because C5 left them unruled and silence would be read as a ruling:

| Route | Source | Ruling |
|---|---|---|
| `GET /mcp` (SSE stream open) | `handlers.rs:305` | **Out.** Opening a stream mints no task and reaches no backend; enforcement belongs at dispatch, which is the POST path this design covers. Revisit if server-initiated delivery ever carries agent-scoped payloads. |
| `DELETE /mcp` (session close) | `handlers.rs:402` | **Out.** Session ownership is already checked by session id; adding `require_id` here can strand a session an operator can no longer close. |
| `GET /api/costs` | `backend_handlers.rs:1214` | **Out.** Already admin-gated, so agent identity adds no control it does not already have. |

If a later change makes any of these three mint work or return agent-scoped data, this ruling expires with it.

### Positive authorization rows, not only refusals

Tier 1 is entirely refusals — necessary, and not sufficient. A change that refuses everything passes every refusal test. Each Tier 1 refusal therefore pairs with a positive row proving the legitimate caller still gets through: a verified JWT `sub` on the allowlist accepted (against T1's declared-only refusal), an mTLS subject accepted with a consistent declared label (against T3's contradiction refusal), a waived incomparable namespace accepted with the mismatch audited (against T5), and a grant scoped to a proven agent still matching for that agent (against DECISION 9.1's new refusal). Existing happy-path tests do not supply this: they were written against the conflated `id`, so several of them pass *because* a declared label satisfies the control, which is the behaviour being removed. They are listed in section 5 as test sites requiring rework for exactly that reason, and a reworked test is not independent evidence of the behaviour it was rewritten to accommodate.

### Falsifier ordering

Per the C5 precedent, Tier 1 runs **red before green**: each is demonstrated failing against `HEAD` before implementation begins, and the failure output is recorded. A falsifier that was never seen to fail is not evidence. T1, T2, T3 and T5 are the four that must be shown red, because each corresponds to a behaviour the current code actively asserts as correct.

## 12. Out of scope, and the stages remaining

### This design does not cover

- **Full IAM.** The module's own boundary at `src/security/agent_identity.rs:7-8` — "This module provides identity *plumbing*: extraction, optional enforcement, and structured audit logging. Full IAM is out of scope." Unchanged.
- **Per-agent authorization policy.** What a proven agent may *do* stays with scopes (`gateway/oauth/scopes.rs`) and the mTLS policy engine (`authorization.rs:186`). This work establishes who the caller is, not what they may reach.
- **`caller_grant_subject` and `GrantSubject`.** The end-user identity path (`handlers.rs:51-67`, MIK-6704) is a neighbouring resolver with its own ranking. It is cited as prior art in section 4 and deliberately not merged with this one; unifying them is a separate design.
- **Adding `agent_id` to `AgentClaims`.** Deferred route (a) from DECISION 3.1. Additive later, no rework.
- **The `issuer` sibling defect** deferred by the 2026-09-17 C1 design, which remains deferred.
- **Renaming either `AgentIdentity`.** The collision noted in section 5 is handled by review discipline, not by a rename in this change.
- **A2A transport identity.** Whether the A2A adapter carries agent identity through the same rules is unexamined here and should be checked before the final review.

### Stages remaining after this document

Per the ruling, design review comes before any code. Order, from `funded_work[0]`:

1. **Design review** — this document. **Round 1 is complete** (section 14). DECISION 3.1, 7.1, 7.2, 7.3, 9.1 and 10.1 need explicit sign-off. 7.1 adds a mandatory operator config step, 9.1 narrows an existing grant behaviour, and 10.1 breaks existing deployments; all three are reasonable places for a reviewer to rule differently.
2. **Test review** — section 11 reviewed as a plan, including the red-before-green ordering and the positive rows added in round 1.
3. **Failing tests** — Tier 1 written and demonstrated red against `HEAD`.
4. **Implementation** — sixteen production sites from section 5, **plus two surfaces round 1 added**: the identity-grant request path (DECISION 9.1, `handlers.rs:1448/1566/1597` → `identity_grants.rs:608`) and an identity audit event on the refusal arm (`handlers.rs:612-618`, `backend_handlers.rs:526`), which does not exist today. The repo gate fires here: `gitnexus_impact` on `extract_agent_identity` and `validate_agent_identity` before editing either, and `gitnexus_detect_changes` before committing.
5. **Final review** — including a re-run of the OWASP Agentic AI checklist at `docs/OWASP_AGENTIC_AI_COMPLIANCE.md`, since ASI03 is the control this module claims.
6. **Docs and housekeeping** — module docs at `:10-15` and `:24-28`, the upgrade notes from section 10, and `funded_work[0]` moved off `stage: design`.

## 13. Falsifier

The cheapest check that this design is wrong, with a pass/fail threshold, runnable before implementation:

**Claim under test:** the proven principal is available at both call sites, so the precedence table is implementable without new plumbing.

**Check:** at `handlers.rs:603` and `backend_handlers.rs:517`, assert in a route-level test that `CertIdentity` and `OAuthAgentIdentity` are present in request extensions for a caller that presented each, on both routes.

**Threshold:** all four combinations present. **Fail:** any absent on either route means the middleware ordering analysis in section 3 is wrong, the design needs a plumbing stage it does not currently have, and section 6 rows 3 through 8 are unimplementable as written.

**Current expectation, from source rather than execution:** passes. `/mcp/{name}` is registered at `router/mod.rs:256` into `routes`, and the agent-auth layer is applied to `routes` at `:279-284`, so it covers both routes; the wrapping-order comment at `:286-291` places agent auth after authentication and before the handler. `cert_identity` and `oauth_agent_identity` are already bound at `handlers.rs:583-587` and `backend_handlers.rs:489-490`. The routes merged after the layer at `:309-331` are jwks, metrics, key-server and UI — none of them dispatch routes.

This was verified by reading, not by running. Running it is the first task of the implementation stage.

## 14. Design review round 1 — findings and disposition

Two independent non-Claude reviewers read this document at the design stage, before any
code existed. Both returned **SHIP-WITH-FIXES**. Run records:
`~/.claude/data/reviews/runs/gpt-20260920T234342Z-73753.md` and
`~/.claude/data/reviews/runs/grok-20260920T234342Z-73879.md`.

They converged independently on four of the six blockers, which is the signal worth
recording: the overlap is not two readings of one prose slip but two readings of the same
structural gap. Every finding below was re-verified at source in this repository before
being applied — a reviewer's claim is not evidence until the file says so.

| # | Finding | Raised by | Verified at | Disposition |
|---|---|---|---|---|
| B1 | The declared label reaches agent-scoped **grant authorization**, so section 9's "telemetry only" was false | both | `handlers.rs:1448/1566/1597` → `identity_grants.rs:608, 232, 65-68` | **DECISION 9.1** added; grants authorize on the proven id |
| B2 | Section 6 row 1 admitted an anonymous caller against a non-empty `known_agents` | gpt | `agent_identity.rs:161` skips the check when no identity resolves | row 1 and the section 8 table now refuse; two flips became three |
| B3 | Authorization config keyed by bare id lets a cert for A combine with a JWT for B | both | mTLS and JWT namespaces are independent; `ProofSource` ranking alone does not separate them | **DECISION 7.3**: keys are `(proof source, id)` pairs |
| B4 | Section 7 demanded a startup census of principals mTLS cannot enumerate | both | match modes are `any` / OU / SAN glob, defined by a CA trust store and a pattern | **DECISION 7.2**: census scoped to enumerable sources; glob policies take a namespace waiver |
| B5 | `allow_unverified_agent_identity` neither exempted legacy deployments from the startup refusal nor restored what its name implies | both | section 10 obligation 1 as written killed the deployments the hatch exists for | hatch scope stated explicitly; obligation 1 now fires only when the hatch is `false` |
| B6 | Contradiction refusals were assumed to be audited; they are not | gpt | `handlers.rs:612-618` returns the error with no audit call; `backend_handlers.rs:526` matches | audit-on-refusal is now named as new work with its own test row |
| I1 | Certificate identifier selection undefined when a cert carries neither SAN URI nor CN | gpt | `display_name` fallback at `handlers.rs:93-103` would synthesise an allowlist key | selection is now total: SAN URI, else CN, else **no principal** |
| I2 | "No middleware has ever verified `agent_id`" misdescribed what a JWT signature covers | gpt | a signature covers the whole payload; the real defect is the unverified decode | section 3 point 2 rewritten; route (a)'s cost drops with it |
| I3 | A sentinel waiver value can collide with a real label | grok | `unmapped_ok` lived inside the namespace it governed | waiver is a distinct config shape, not a reserved string |
| I4 | Rows 7–8 promise to audit a secondary JWT proof the type cannot hold | grok | the struct carried one `ProvenPrincipal` | `secondary_proof` field added |
| I5 | `GET /mcp`, `DELETE /mcp` and `GET /api/costs` were left unruled | grok | `handlers.rs:305`, `:402`, `backend_handlers.rs:1214` | ruled **out** explicitly, with the condition that expires the ruling |
| I6 | Tier 1 is all refusals; a change that refuses everything passes them | gpt | the reworked happy-path tests pass *because* a label satisfies the control | positive rows added, with why the existing ones do not count |

**What the round did not settle.** Section 13's extension-presence check is still unread by
execution, and A2A inbound identity remains unexamined — both were already stated as out of
scope and neither reviewer disputed that. Neither reviewer ran the gateway or a test, correctly:
there is no implementation yet. That is the point of reviewing at this stage — B1 and B4 would
each have cost a branch to discover after the code was written, and B1 would have shipped a
second unauthenticated string match into the grant system.
