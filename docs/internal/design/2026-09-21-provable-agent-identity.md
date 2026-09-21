# Provable agent identity — design

- **Work item**: `MIK-6746.IDENTITY.1` (`docs/requirements/RELEASE-4.0.0-scope-status.json`, `criteria[19]`, `stage: graded`), tracked as **MIK-7512**. There is no `MIK-6746.IDENTITY.PROVABLE` and no top-level `funded_work` key: the ledger's top-level keys are exactly `schema_version`, `criteria` and `decisions`, which `scripts/release/check_scope_acceptance.py:192-197` requires, and the row's own note records that adding a `funded_work` key would hard-fail that gate. A declared criterion is the only container the gate enumerates, which is why the funded work was transcribed into this row.
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
14. Design review rounds 1 through 6 — findings and disposition

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

**Where this diverges from the ledger row's analysis, and why the ruling text governs.** The `MIK-6746.IDENTITY.1` note contains an analysis paragraph concluding that "Change 2 is therefore not implementable as written until `agent_id` is added to `AgentClaims` and a policy is set for tokens lacking it. That is additional work this row must carry, not a detail of it." This design does not do that, and the divergence is deliberate rather than an oversight. The operator ruling quoted in section 1 is the specification; the row's analysis prose is commentary written while sizing the work. Change 2's own words are "mTLS > **verified JWT claim** > declared label" — it names a verified claim and never names `agent_id`. A `sub` verified by `validate_agent_token` against registered key material is a verified JWT claim under its standard name, so sourcing the proven rung from it satisfies the ruling literally. The analysis paragraph is right about route (a) specifically and wrong to conclude that route (a) is the only route: it assumed the proven rung had to be a *new* claim, when an already-verified one was sitting at both call sites unused. Recorded in section 14 as **RULED (team-lead): DECISION 3.1 STANDS** — the ruling text is the specification, the row's analysis prose is commentary; overturnable in one line by ruling that the proven rung must be an `agent_id` claim, which reopens route (a) and adds the tokens-lacking-it policy as scope.

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
    /// URI, else CN, else **no mTLS principal is constructed at all**. A
    /// certificate carrying neither is not an mTLS identity — the request
    /// falls to the no-mTLS rows of section 6, where a verified JWT still
    /// supplies a principal (rows 3-4). The existing `display_name`
    /// fallback (`handlers.rs:93-103`) synthesises a human string and must not
    /// be reachable from this field, or an unnameable certificate silently
    /// becomes an allowlist key. Such a handshake is treated as "no proof":
    /// row 1 of the section 6 table, refused under `require_id` and
    /// otherwise accepted — a non-empty `known_agents` does not refuse an
    /// unidentified caller, today or after this change (section 8,
    /// `agent_identity.rs:158`).
    pub id: String,
    pub proof: ProofSource,
}

/// Ordered by strength. Ranking is the discriminant order, not a call order.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
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
- `ProofSource` derives `PartialEq, Eq, PartialOrd, Ord` with `MutualTls` last (the full chain, because `Ord` does not compile without `Eq` and `PartialEq`), so "rank by proof" is a comparison on the type rather than a hand-written chain that a later edit can reorder. This is the structural guard against the defect recurring: the current bug is precisely a precedence encoded as statement order.
- `JwtClaim` as a variant disappears. Under DECISION 3.1 the unsigned decode is deleted, so there is no source that is JWT-shaped and unproven.
- Both fields are `Option`, and `AgentIdentity` is now always constructed — never `Option<AgentIdentity>`. "No identity at all" is `AgentIdentity { proven: None, secondary_proof: None, declared: None }`. This removes the `Option<Option<..>>` awkwardness at the call sites and makes the refusal logic a single total match. See section 5 for what that does to the two production callers.

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
| 6 | `src/security/agent_identity.rs:161,164` | `known_agents.contains(&identity.id)` and its message | looks up the **`(proof source, proven.id)` pair** per DECISION 7.3 — never the bare `proven.id`, or an mTLS CN and a JWT `sub` sharing a string satisfy each other's entries; the declared label is not consulted; message names the policy |
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

Beyond the type itself, this work adds three fields to `AgentIdentityConfig` — `allow_unverified_agent_identity` (section 10), `principal_labels` (section 7) and `disable_declared_labels` (DECISION 7.2a). The config surface is `src/config/features/security.rs:8` (which re-exports `AgentIdentityConfig`), `:583` and `:627`, and `src/config/mod.rs:36`. All three are additive under the existing `#[serde(default)]` on the struct (`src/security/agent_identity.rs:35-37`), so none of them makes an existing configuration fail to parse. That compatibility claim covers **those three fields only**. The re-keying of `known_agents` (DECISION 7.3) is a deliberate deserialization break in the other direction: a bare-string entry is a load error, tested at T21. So the honest statement is that this work adds three fields compatibly and changes one existing field incompatibly, not that the whole config surface round-trips unchanged.

Downstream of sites 12 and 13, `agent_id` travels as a plain `Option<&str>` — `tasks.rs:112`, `:171`, `:211`, `:295`.

**Round 2 retracts the conclusion that used to follow this sentence.** It read "so no type change propagates past the router. That boundary is what keeps the blast radius at sixteen sites." That was true of the original scope and stopped being true the moment DECISION 9.1 made grants and task recovery authorize on the proven pair: a downstream consumer that still holds one flattened `Option<&str>` cannot express `(source, id)`, so the split has to reach it. Three sites past the router are therefore in scope and are listed in section 12 stage 4 — `MetaMcpCallerContext` (`src/gateway/meta_mcp/mod.rs:157`), its read at `invoke.rs:1137`, and the ASI03 audit line at `invoke.rs:1893-1915`. Leaving the freeze in place was an invitation to re-flatten at exactly the chokepoint the split exists to open.

**A fourth site, past the request entirely: the durable task worker.** `OwnedCallerContext` (`src/gateway/task_service/execution/context.rs:20`) owns a snapshot of the caller so a worker can rebuild it after the request is gone, and that snapshot holds one flattened `agent_id: Option<String>`, filled from `req.agent_id` at `handlers/tasks.rs:171` and handed back into the rebuilt context at `context.rs:123`. It sits beside `grant_subject` and `verified_identity`, so the rebuilt caller is an authorization context, not an attribution record — the same conflation this design removes at the router would survive inside it, one dispatch later. `TaskIntentRequest` and `OwnedCallerContext` therefore carry **separate proven and declared fields**, and grant authorization is tested *after* worker dispatch, not only at admission: a split that stops at the request boundary leaves the longest-lived copy of the caller flattened.

### Test sites requiring rework

In-module: constructions at `src/security/agent_identity.rs:309`, `:335`, `:379`, `:449`, `:466`, `:485`; `extract_agent_identity` calls at `:305`, `:321`, `:331`, `:348`, `:361`, `:375`, `:394`; `validate_agent_identity` calls at `:410`, `:423`, `:435`, `:455`, `:471`, `:491`. Route-level: the C5 parity block at `src/gateway/router/tests.rs:3742-3900`, whose fixtures at `:3792`, `:3823`, `:3856`, `:3878`, `:3896` set `known_agents` and today pass with a header-only caller.

One of these encodes the defect as expected behaviour and must be **inverted, not ported**: `extract_from_jwt_claim` (`:366-384`) builds a token with `alg: none` at `:372` and asserts it resolves to `IdentitySource::JwtClaim`. A port that keeps it green keeps the bug.

`extract_header_takes_precedence_over_query` (`:342-353`) survives unchanged: header over query is still the right order **within** the declared label, which is where that comparison now lives.

Worth recording for the test review: **the inverted precedence is not pinned by any test today.** There is no header-beats-JWT case in the module — the suite covers header, query, header-over-query, whitespace, JWT-present, and JWT-without-claim, and never the combination that constitutes the vulnerability. The defect survived because nothing asserted the wrong behaviour, not because something asserted it.

## 6. Precedence as a total function

Change 2: "mTLS > verified JWT claim > declared label. A declared label CONTRADICTING a proven one is a REFUSAL, not a silent override."

Three independent inputs, so eight combinations. Every one has a defined outcome; there is no residual case.

Inputs: **M** = an mTLS principal was **successfully resolved** — a `CertIdentity` is present (`handlers.rs:583`, `backend_handlers.rs:489`) **and** it yields a SAN URI or a CN. Certificate presence alone is not M: a certificate carrying neither identifier constructs no `ProvenPrincipal` (section 4), so such a handshake is **M = no** and the row is chosen by J and D alone — a verified JWT alongside it is row 3 or 4, not row 7 or 8. **J** = verified `OAuthAgentIdentity` present (`handlers.rs:584-587`, `backend_handlers.rs:490`; only ever constructed on the `Ok` arm of `validate_agent_token`, `oauth/mod.rs:127-143`). **D** = declared label present (`X-Agent-ID` header, else `agent_id` query param).

Table assumes `security.agent_identity.enabled = true`. When it is `false`, `validate_agent_identity` returns `Ok(())` at `:146-148` and every row is "accept, no enforcement" — unchanged.

| # | M | J | D | Proven principal | Outcome |
|---|---|---|---|---|---|
| 1 | no | no | no | none | **Refuse** if `require_id = true` (no ID at all). Otherwise **accept**, including when `known_agents` is non-empty — unchanged from today, and deliberately so (section 8). |
| 2 | no | no | yes | none | **Refuse** if `require_id = true`, and **refuse** if `known_agents` is non-empty — a declared-only label satisfies neither (change 3). Accept as unprivileged if both are off; the label is recorded as telemetry only. **This row is the breaking change.** |
| 3 | no | yes | no | JWT `sub` | Accept. Allowlist checked against `sub`. |
| 4 | no | yes | yes | JWT `sub` | Accept if the label is **consistent** with `sub`; **refuse** on contradiction (section 7). |
| 5 | yes | no | no | mTLS subject | Accept. Allowlist checked against the mTLS subject. |
| 6 | yes | no | yes | mTLS subject | **Run DECISION 7.1's ordered match**, against the **selected** mTLS proven id — SAN URI else CN, per section 4 — never against the certificate subject generally. DECISION 7.1 states the outcomes and this row does not restate them; for orientation only, mTLS normally carries the namespace waiver, so the usual result is arm 3. |
| 7 | yes | yes | no | **mTLS subject** (mTLS outranks JWT) | Accept. The JWT `sub` is recorded in audit as a secondary proof, never as the principal. |
| 8 | yes | yes | yes | **mTLS subject** | Same rule as row 6 — DECISION 7.1's ordered match, run once against the selected mTLS proven id. The JWT `sub` is audited as secondary proof, never compared against the label: one principal, one comparison. |

Three properties this table has that the current code does not:

1. **The declared label never becomes the principal.** In rows 3 through 8 it cannot override; in row 2 it cannot satisfy a control. There is no path from `X-Agent-ID` to an authorization pass. **The qualifier that keeps this true as stated:** it is a claim about `X-Agent-ID` and the `agent_id` query param, not about every header in the process. `caller_grant_subject` (`handlers.rs:51-67`) ranks operator-trusted headers above `cert_identity`, and those headers are a different, explicitly opted-in set — the `x-gateway-identity-*` and `cf-access-authenticated-user-*` names read by `grant_subject_from_trusted_headers` (`handlers.rs:78-91`) — gated on `trust_caller_identity_headers()`. `X-Agent-ID` is not among them and gains no standing from them. That resolver is ruled out of scope in section 12, so the property above is scoped to this design's surface and must be read that way, not as a claim that no header anywhere can supply an identity.
2. **Rank is by proof, not by call order.** Rows 7 and 8 resolve to mTLS through `ProofSource: Ord`, not through which branch a function happens to check first. The defect at `:105-111` is a precedence encoded as statement order; this design replaces that encoding.
3. **Contradiction is refusal, never silent preference.** Rows 4, 6 and 8 all run DECISION 7.1's ordered match, which refuses a mapped principal whose declared label is outside its set (arm 2) and an unmapped one carrying a label that is not its own name (arm 4), rather than quietly ignoring the label. Under a namespace waiver the same mismatch is accepted and audited — the operator has stated the namespaces are incomparable, so there is no contradiction to refuse, only a signal to record. Silently preferring the proven value in a *mapped* namespace would satisfy "the header cannot escalate" but would lose the detection signal the ruling asks for in change 4.

### Refusal shape

Unchanged from the C5 precedent: JSON-RPC `-32600` with `StatusCode::FORBIDDEN` (`handlers.rs:615`, `backend_handlers.rs:526`), message naming the policy that refused. The C5 review specifically required the policy name in the message so an unrelated 403 cannot mask a missing guard; contradiction refusals inherit that requirement and must name the contradiction, not merely say "forbidden".

## 7. What "contradicts" means

The ruling says a declared label contradicting a proven one is a refusal. "Contradicts" has to be defined operationally here, or the implementer guesses — and the obvious guess breaks every mTLS deployment.

**The trap.** The three identifiers live in different namespaces. An mTLS subject is a SAN URI or a CN (`src/mtls/identity.rs:30`, read via `san_uris` then `common_name` then `display_name` at `handlers.rs:93-103`). A verified JWT `sub` is a registered `client_id`. `X-Agent-ID` is an arbitrary short string chosen by the caller. A naive `proven.id != declared.id` refusal would reject every caller that presents a client certificate **and** sets `X-Agent-ID`, because `spiffe://cluster/ns/agents/sa/runner` never string-equals `runner`. That is a usability outage discovered at integration time, not a security win.

### DECISION 7.1 — contradiction refuses by default; the soft edge is an operator opt-in

A declared label **contradicts** the proven principal when the two are comparable and differ. "Comparable" is established by configuration, never guessed. Every rule below is keyed by the **pair** `(proof source, id)`, never by a bare identifier — see DECISION 7.2.

**One ordered match, evaluated top to bottom; the first arm that fires decides.** Round 6 found these written as three independent paragraphs, which let an implementer reach opposite outcomes for the same request depending on which paragraph they coded first. They are one function with four arms:

1. **Exact match — accept, and stop.** `declared.id == proven.id` is consistent *whatever the mapping says*. A principal is always permitted to declare its own name, so the proven id is a member of its own label set by construction and never has to be listed. This arm is deliberately ahead of arm 2: without it, an operator who maps `(jwt, "svc-a") → {"billing"}` would 403 the caller who honestly sends `X-Agent-ID: svc-a`, which is the one label that cannot be a lie. The common case under DECISION 3.1, where the proven id is a `client_id`.
2. **Operator mapping decides membership.** `agent_identity.principal_labels` maps a `(proof source, proven id)` pair to the set of labels it may declare. Reached only when the declared label differs from the proven id. A declared label outside that set is a **contradiction** — refuse.
3. **Explicit waiver — accept and audit.** A principal whose entry is the waiver variant declares that its labels are in a namespace the gateway cannot compare. Any label is accepted and the pair is audited. The waiver is a **distinct config shape**, not a reserved string: the value is `{ labels = [...] }` or `{ incomparable = true }`, so no real label can collide with it and a one-element label set cannot be mis-written into a waiver. (An earlier draft used an `unmapped_ok` sentinel value; a sentinel inside the label namespace it governs is a misconfiguration waiting to happen.)
4. **No entry at all — refuse.** A proven pair with neither a per-principal entry nor a waiver, carrying a declared label that is not its own id, is the request-time backstop (DECISION 7.2). A missing mapping is never read as "incomparable". With no declared label present this arm is not reached and the caller is accepted (T26b).

This ordering is the whole contradiction function. Section 6's table does not restate it — rows 4, 6 and 8 invoke it.

**Coverage is required only where the principal set is enumerable.** When `agent_identity.enabled` is set and declared labels are accepted, `principal_labels` must cover every **enumerable** configured principal — which, per DECISION 7.2 below, means the JWT `client_id` registry and nothing else. No mTLS policy shape is enumerable, including one that lists literal subjects, so mTLS carries a namespace-level waiver; an operator may still add per-principal mTLS entries for subjects they can name, and those are enforced without ever being required to be complete. This is enforced at **startup**, alongside the validation section 10 already requires.

### DECISION 7.2 — the census is scoped to what config can enumerate; non-enumerable proof sources take a namespace waiver

An earlier draft required `principal_labels` to cover *every* configured principal, full stop. **mTLS cannot satisfy that**, verified at source: the match modes are `any`, an OU match, and SAN globs (`src/mtls/`, and `support.rs:627-628` already distinguishes handshake-required mTLS from `enabled` alone), so the admissible subject set is defined by a CA trust store and a pattern — it is not a list the gateway can walk at startup. A startup check demanding a total census would either never pass for a glob policy or would have to be quietly skipped, and a gate that is quietly skipped is worse than no gate.

The census therefore has two tiers:

| Proof source | Enumerable? | Startup requirement |
|---|---|---|
| Verified JWT `sub` | yes — the `client_id` registry | every registered client needs a `principal_labels` entry (label set or waiver) |
| mTLS, any policy shape | **no** | a **namespace-level** waiver for the proof source, written explicitly; startup refuses if declared labels are accepted and the source carries neither a namespace waiver nor any per-principal entry. Per-principal mTLS entries are permitted and are **not** required to be total |

**Why no mTLS policy is enumerable, against the types as they exist.** Round 2 split this row by configured value — a `cn` or `ou` holding no glob metacharacter was to be enumerable. That is wrong, and the reason is the selection order in section 4: the proven id is **first SAN URI, else CN**. A policy matching a literal `ou`, or a literal `cn` on a certificate that also carries a SAN URI, enumerates a value that is *not* the resolved principal — so the startup census would pass while the request-time id is absent from `principal_labels`, and a match-miss read as "incomparable" silently accepts a contradicting `X-Agent-ID`. That is the vulnerability this decision exists to close, reintroduced through the census. `CertMatchConfig` (`src/mtls/config.rs:122-136`) has five fields and no way to constrain which SANs a signed certificate may also carry, so the gateway cannot know in advance which identifier a policy's admitted certificates will resolve to. The enumerable tier is therefore **JWT only**.

**What that argument does and does not license.** It defeats *totality* — no startup census can demand that mTLS principals be listed, because the list cannot be computed from the config. It does **not** defeat *enumerability by hand*: an operator who knows a certificate subject can write it down. So the waiver is the **default and the normal configuration** for mTLS, not an implicit property of the proof source, and a per-principal mTLS entry remains available to any operator who wants change 2's contradiction refusal for a subject they can name. An earlier draft over-read the argument, made per-principal mTLS entries a load error, and thereby made the ruling's "a declared label contradicting a proven one is a REFUSAL" unreachable for mTLS under *every* configuration — trading a census that could not pass for a rule that could not fire.

**The request-time backstop.** The startup census is not sufficient on its own, because a JWT registry can change under a config reload. So the invariant is also enforced per request, and it is scoped to the situation the rule exists for: **when a declared label is present and differs from the proven id** and the proven `(source, id)` it accompanies is absent from `principal_labels` while its proof source carries no namespace waiver, the request is **refused**, never treated as incomparable. The differs condition is DECISION 7.1 arm 1 reaching this far: a principal that declares its own name has contradicted nothing, so the backstop has nothing to fail closed about. Fail-closed is the only safe reading of a missing mapping when there is a label to compare — the alternative is exactly the silent accept above.

**The backstop never fires on a caller that declared nothing, nor on one that declared its own name.** With no declared label there is nothing to contradict, so a proven principal absent from `principal_labels` is simply authorized on its own proof and, where `known_agents` or `require_id` apply, on those. An unconditional backstop would refuse every authenticated request in a deployment that owes no mapping at all — a gateway that starts and then refuses legitimate traffic, which is precisely the failure section 10 obligation 1 exists to prevent, re-entered through section 7. T26 asserts that such a deployment starts; it now also asserts that a request succeeds through it.

### DECISION 7.2a — the serialized shape, and what "declared labels are accepted" means

Rounds 1 through 4 each found a variant of the same defect: a rule stated normatively in section 7 and then restated, drifting, in section 6, 8, 10 or 11. Two things kept that possible — the config had no written shape, so every section described it in prose, and the startup gate fired on an undefined predicate. Both are closed here, and **section 7 is the single normative source**: where sections 6, 8, 10 and 11 describe the same rule, they are illustrations of these decisions and a conflict is a defect in them, not a second rule.

```yaml
security:
  agent_identity:
    enabled: true
    require_id: true
    # (source, id) pairs. A bare string is a load error (T21).
    known_agents:
      - { source: jwt,  id: "svc-runner" }
      - { source: mtls, id: "spiffe://cluster/ns/agents/sa/runner" }
    principal_labels:
      # Enumerable tier: one entry per registered JWT client_id.
      - source: jwt
        id: "svc-runner"
        labels: ["runner", "runner-canary"]
      # Non-enumerable tier: a namespace-level waiver for the whole proof
      # source. `id` is absent, which is what makes it a namespace entry
      # rather than a per-principal one.
      - source: mtls
        incomparable: true
      # Optional, and the reason an mTLS contradiction refusal is reachable
      # at all: a per-principal mTLS entry. Not required by any startup
      # census — DECISION 7.2 drops totality for this source — but permitted,
      # and enforced at request time for exactly this `id`.
      - source: mtls
        id: "spiffe://cluster/ns/agents/sa/runner"
        labels: ["runner"]
```

`labels` and `incomparable` are mutually exclusive variants of one enum, not two optional fields: a `{ labels: [...] }` entry cannot be mis-read as a waiver, and a waiver cannot be mis-written as a one-element label set. An entry carrying both, or neither, is a load error.

**Precedence between the two mTLS tiers, stated once so it is not an ambiguity gap.** A per-principal entry wins for the `id` it names; the namespace waiver covers every mTLS principal no entry names.

**`source: declared` is not a legal key here, and is a load error.** `principal_labels` exists to compare a *proven* principal against a label it may declare; a declared-to-declared mapping compares a label to itself and means nothing. The `source` key on this surface therefore takes `ProofSource` — the two-valued proof type — not the three-valued `AgentSourceKey` that `known_agents` uses. This is the mirror of T29 on the other config surface: `known_agents` admits `declared` but only under the escape hatch, `principal_labels` never admits it at all. Pinned by T31. So an operator who wants contradiction refusal for a handful of known certificate subjects writes those entries and keeps the waiver for the rest, and an operator who wants none writes only the waiver. A `source: mtls` entry carrying an `id` is **not** a load error — an earlier draft made it one, which is what made change 2's contradiction refusal unreachable for mTLS in every possible configuration.

**"Declared labels are accepted" is a config predicate, not an observation of traffic.** The startup gate cannot wait to see whether a caller sends `X-Agent-ID`. The predicate is: `agent_identity.enabled` is true **and** the declared-label intake has not been switched off. Intake is on by default — that is today's behaviour and this design does not change it — so in practice the predicate is `enabled && !disable_declared_labels`, where `disable_declared_labels` is the third and last new config field, defaulting to `false`. An operator who sets it gets no `principal_labels` obligation at all, because no label can ever arrive to contradict a principal. That is the only way to run enforcement without the mandatory mapping step DECISION 7.1 introduced, and it is the honest answer to that decision's stated cost.

The property preserved is the one that mattered: the operator states in configuration that a namespace is incomparable, rather than the gateway inferring it. What is given up is per-principal granularity for glob policies, which was never available to begin with.

### DECISION 7.3 — no cross-namespace credential combining

Keying by bare identifier lets two independent namespaces collide. A caller presenting a valid client certificate for principal **A** and a valid JWT for principal **B** must not combine A's `known_agents` membership with B's scopes. Both `known_agents` and `principal_labels` are therefore keyed by `(proof source, id)`, and the resolved principal is a single `(source, id)` pair chosen by `ProofSource: Ord` — the losing credential is audited (section 9) and grants nothing.

**Round 2: the pair has to be carried by the types, or it is prose.** Saying the keying is by pair changes nothing while the config surfaces still hold bare strings, and three of them do, verified at source: `known_agents: Vec<String>` (`src/security/agent_identity.rs:49`) compared with `contains(&identity.id)` (`:161`), and `GrantAgent::Exact(String)` compared with `actual == expected` (`src/identity_grants.rs:65-68`, reached from `:232` and `:608`). An implementer reading only section 5's site inventory would keep all three and ship the collision this decision exists to close. The schema changes are therefore part of the decision, not an implementation detail:

- `known_agents` becomes a list of `(source, id)` entries, and `validate_agent_identity` looks up that pair rather than the id. A bare-string entry in an existing config is a load error naming the source it must declare — not a silently widened match. **The config key is a three-valued enum and is deliberately not `ProofSource`.** `ProofSource` (section 4) has exactly two variants, because only two things constitute proof. The `known_agents` key adds a third value, `declared`, for the absence of proof: call it `AgentSourceKey { Mtls, Jwt, Declared }`, where `Mtls` and `Jwt` map onto the two `ProofSource` variants and `Declared` maps onto no `ProvenPrincipal` at all. Keeping them as separate types is the point — a `declared` entry must be unrepresentable anywhere authorization reads proof. `Declared` exists only so the escape hatch has something to match against (section 10) and is a **load error unless `allow_unverified_agent_identity = true`**, so an operator cannot reach declared-label matching without also setting the flag that warns about it.
- `GrantAgent::Exact` carries a **`ProofSource`** — the two-valued proof type, never `AgentSourceKey` — alongside the identifier, and `Grant::covers` receives the proven pair. A grant keyed to a declared label is therefore not expressible, which is DECISION 9.1 enforced by the type rather than by a check. This rides the 4.0.0 grant migration DECISION 9.1 already declares, so it costs no second migration.

Without both, a JWT `sub` of `runner` and an mTLS CN of `runner` remain one principal to the gateway and inherit each other's allowlist membership and grants. String equality between an mTLS CN and a JWT `sub` is a coincidence, never an identity.

**Round 2: "grants nothing" has to include scopes.** Ranking the principal is not sufficient on its own, because scope authorization reads the JWT independently of which principal won the ranking. If an mTLS certificate for A outranks a JWT for B, but B's scopes still authorize the call, the combining this decision exists to prevent happens one layer down. The rule is therefore: **the losing credential contributes no authorization input of any kind** — not a principal, not a scope, not an allowlist membership. When mTLS wins and the JWT belongs to a different principal, the JWT's scopes do not authorize the call: the agent-auth scope gate **fails closed** whenever the JWT `sub` is not the ranked `(source, id)`. A call that needed those scopes is refused. There is no combining mechanism in this design — `principal_labels` binds a proven principal to the *declared labels* it may present, and cannot map one proven principal to another, so it is not the escape route for a dual-credential caller. That leaves dual-auth callers whose mTLS subject and JWT `sub` differ — the common SAN-URI-versus-`client_id` case — unable to use scope-gated tools at all. That lockout is a breaking change, listed as such in section 10; adding a principal-aliasing type is explicitly out of scope for 4.0.0 (section 12).

**Where that rule has to be enforced, since it is not enforced today.** `authorize_tool_target` applies the mTLS policy (`src/gateway/router/authorization.rs:183-204`) and the agent JWT's scopes (`:206-214`) as two independent gates, neither consulting the other's principal. The ranking in this module cannot reach either. So this rule is a funded change at `:206-214` — when a proven principal was resolved and the JWT `sub` is not that principal, the JWT's scopes do not authorize the call — and it is listed in section 12 stage 4 and tested at T16. Left unfunded, the paragraph above would be a decision recorded as done inside the document that hides the gap.

**An exact-match certificate rule is a predicate, not a roster.** Earlier rounds of this table treated an mTLS rule as enumerable whenever its comparison was equality. An exact-match *policy rule* still admits any certificate the CA signs that satisfies it, and the gateway cannot walk the set of such certificates. Enumerable means **the config holds the identifiers that will be resolved as principals**, never **the comparison is exact** — which is the second, independent reason the mTLS row above is `no`.

That closes the namespace trap without weakening change 2:

- Contradiction-is-refusal is the **default**, matching the ruling literally. It fires on every mismatch in a mapped namespace.
- The mTLS case still works: an operator whose SAN URI cannot be compared to a short label sets the waiver. The operator states the namespace is incomparable; the design does not assume it.
- The difference from a guessed soft edge is where the burden sits. Under a default-accept rule the gateway silently decides two identifiers are incomparable and the operator never learns. Under the waiver the operator writes it down, which is also what makes the audit signal meaningful — a mismatch under a waiver is expected, a mismatch under a mapping is an incident.

**The naive alternative, rejected:** `proven.id != declared.id` refuses unconditionally. This looks like the most literal reading of change 2 but rejects every caller presenting a client certificate and an `X-Agent-ID`, because `spiffe://cluster/ns/agents/sa/runner` never string-equals `runner`. It refuses on namespace difference rather than on contradiction, which is a different property than the one the ruling asks for, and it makes mTLS plus a declared label unusable.

**Cost, stated plainly:** requiring `principal_labels` adds a mandatory config step for any deployment combining enforcement with declared labels. That is a third new config surface alongside `allow_unverified_agent_identity` and `disable_declared_labels`, on a release the ruling already notes is carrying the identity-keyed catalogue and the 3.x credential migration. It is the price of not having the gateway guess about identity, and it is flagged here for the design reviewer rather than absorbed quietly. The one documented escape is DECISION 7.2a's `disable_declared_labels`: an operator who turns declared-label intake off owes no mapping at all, because no label can arrive to contradict a principal. That is the honest floor on this cost — enforcement without the mapping step is available, but only by giving up the caller-supplied tag entirely.

## 8. `known_agents` and `require_id` under the split

Change 3: "known_agents APPLIES TO PROVEN IDENTITIES ONLY. A declared-only label can never satisfy it, and never satisfies require_id."

New behaviour of `validate_agent_identity`:

| Config | Today (`:142-169`) | After |
|---|---|---|
| `enabled = false` | `Ok(())` at `:146-148` | unchanged |
| `require_id = true`, nothing present | refuse (`:151-157`) | unchanged |
| `require_id = true`, declared label only | **accept** — `:150` sees `Some`, `:161` allowlist skipped when empty | **refuse**: a label is not an ID |
| `require_id = true`, proven present | accept | unchanged |
| `known_agents` non-empty, nothing present | accept — `:150` returns `Ok` before the allowlist is reached | **unchanged**: still accept. See below. |
| `known_agents` non-empty, declared label only | **accept if the label is listed** (`:161`) | **refuse**: the allowlist is not satisfiable by self-declaration |
| `known_agents` non-empty, proven present | accept if `identity.id` listed | accept if the `(proof source, proven.id)` pair is listed (DECISION 7.3); the label is not consulted |

Two rows flip from accept to refuse. They are the vulnerability.

**The anonymous row does not flip, and the table now says so.** Round 2 read a fourth break here — an unidentified caller against a non-empty `known_agents` losing access on upgrade — so the omission was costing a careful reader a wrong conclusion. Verified at source: `validate_agent_identity` returns `Ok(())` at `src/security/agent_identity.rs:158` when no identity resolves and `require_id` is false, **before** the allowlist check at `:161`. A non-empty `known_agents` has never refused an anonymous caller, and this design does not start. The operator who wanted "listed or nothing" gets that from `require_id = true`, as today. What that operator does lose is the declared-only row, which DECISION 10.1 names as the breaking change and the hatch restores.

The module documentation has to change with them. `src/security/agent_identity.rs:24` currently describes `known_agents` as an "optional allowlist of accepted agent IDs", and `:27-28` states the allowlist applies only "when `known_agents` is non-empty and `require_id` is true" — which the C5 review already found wrong at source, since `:161` runs whenever an identity resolves. Both must be rewritten to say the allowlist is a **proven-principal** allowlist. The C5 review recorded the reason plainly and it still holds: `known_agents` is a declared-label policy, not a cryptographic allowlist, and the name implies otherwise. This change makes the name true rather than continuing to document around it.

## 9. The declared label as telemetry

Change 4: "Multi-agent tracing and cost attribution need a caller-supplied tag; the feature is not wrong, its privilege is. Audit records BOTH."

Sites 12 and 13 in the inventory (`handlers.rs:1448`, `:1900`) currently flatten the identity to one `Option<&str>`. Under the split they must choose, and the choice differs by purpose:

- **Audit** records all of them, always, as distinct fields: `agent_proven`, `agent_proof` (the `ProofSource`), `agent_secondary_proof` and its source (section 4's `secondary_proof`, populated on rows 7 and 8 where a verified JWT rides behind an mTLS certificate), `agent_declared`, and `agent_declared_source`. A record that collapses them cannot distinguish "agent-a proved it" from "someone said agent-a", which is the property the whole change exists to create — and one that drops `agent_secondary_proof` loses the row-7 audit promise the `secondary_proof` field was added to keep.
- **Authorization** reads `proven` only. Already covered by section 6; named again here so no later reader takes "audit records both" as licence to authorize on the declared value.
- **Attribution and tracing** (`tasks::RecoveryCaller.agent_id`, `tasks.rs:112`, `:211`) keep using the declared label when present, falling back to the proven id. Cost attribution wants the caller's own tag, and a caller that lies about its tag mis-attributes its own costs and no one else's. This is the one place the declared label stays primary — and it is safe **only** because DECISION 9.1 below removes the other consumer of the same flattened value.

### DECISION 9.1 — identity grants authorize on the proven id, not the flattened label

An earlier draft of this section asserted that nothing downstream of the flattened `agent_id` makes an access decision. **That is false, verified at source.** `handlers.rs:1448` builds `agent_id` from the conflated `AgentIdentity.id` — which today is header-first (`agent_identity.rs:100-167`) — and carries it into `MetaMcpCallerContext.agent_id` (`:1597`) and the task-intent request (`:1566`). From there it reaches `IdentityGrantStore` evaluation: `identity_grants.rs:608` passes `request.agent_id` to `Grant::covers`, which calls `self.agent.matches(agent_id)` (`:232`), and `GrantAgent::Exact(expected) => agent_id.is_some_and(|actual| actual == expected)` (`:65-68`) is bare string equality.

**The consequence today:** a grant scoped to `GrantAgent::Exact("agent-a")` is satisfied by any caller that sets `X-Agent-ID: agent-a`. The grant system's agent scoping is an unauthenticated string match. This is the same defect as the header-over-mTLS override, on a second surface, and it is in scope here because the ruling's change 3 — controls apply to proven identities only — cannot hold while it stands.

Under the split, the single `agent_id` field becomes two, and the consumers divide by purpose:

| Consumer | Field | Rationale |
|---|---|---|
| `IdentityGrantRequest.agent_id` → `GrantAgent::matches` | **proven `(source, id)` pair** | An access decision. A declared label must never satisfy it, and a bare id would re-open DECISION 7.3: an mTLS subject and a JWT `sub` that happen to be the same string are not the same principal, so `GrantAgent::Exact` must compare the pair. |
| Task-recovery authorization (`handlers/tasks.rs:295`) | **proven `(source, id)` pair** | Also an access decision — see below. |
| `MetaMcpCallerContext` audit / `agent_declared` | both, distinct | Section 9's audit rule. |
| `tasks::RecoveryCaller` attribution / cost | declared, falling back to proven | The only consumer with no access decision behind it. |

**The write path, specified — because a load-reject with no way to write the new shape is the same prose-not-types gap that reopened this design three rounds running.** DECISION 7.3 makes a bare-string `GrantAgent::Exact` a load error. Two places construct that value today and both must be migrated in the same change, or the only way to obtain a 4.0 grant is to hand-edit the store:

| Write path | Source | Migration |
|---|---|---|
| CLI grant creation | `src/commands/identity.rs:329` — `--agent AGENT_ID` parses straight into `GrantAgent::Exact(agent)` | the flag gains a required source qualifier. Spelling it `--agent mtls:spiffe://cluster/ns/agents/sa/runner` — or `--agent mtls:runner` for a certificate whose selected id is the CN `runner` — keeps one flag and makes the pair visible in shell history and runbooks. **The identifier after the prefix is the selected proven id verbatim, never a DN fragment: `mtls:CN=runner` would mint a grant that can never match**, because the resolved principal is the SAN URI else the bare CN value (section 4). An unqualified `--agent runner` is a CLI error naming the two accepted prefixes, never a silent default to one source |
| Grant-request handler | `src/identity_grants.rs:824` — `GrantAgent::Exact(agent_id.clone())` from `request.agent_id` | takes the proven pair from the resolved `AgentIdentity` rather than the flattened id. A request arriving with only a declared label cannot produce a grant at all, which is DECISION 9.1 enforced at the point of issue rather than at the point of use |

Serialized, an `Exact` grant is `{ source: mtls | jwt, id: "..." }` — the same two-valued `ProofSource` as `principal_labels`, never `AgentSourceKey`, because a grant keyed to a declared label is the vulnerability. T19 covers the read side; the CLI rejection of an unqualified `--agent` is T33.

**Round 2 correction — recovery is authorization too.** A round-1 draft of this table left `RecoveryCaller.agent_id` on the attribution side. That is wrong, verified at source: `handlers/tasks.rs:295` assigns `agent_id: caller.agent_id` into a caller context whose own comment at `:286` reads "This context checks authorization only; it never accesses a cache", and whose `signing: None` at `:290-292` exists specifically to keep `check_invocation_policy` running on that read. So the recovery path evaluates invocation policy and grants on the same value. The attribution/authorization split therefore runs *through* `RecoveryCaller`, not around it: the struct carries both fields, and the recovery context reads the proven pair while cost attribution reads the declared label.

This is the second time the "it is only telemetry" claim has been falsified by a grep of its consumers, which is itself the argument for the type split: as long as one `Option<String>` carries both meanings, every new consumer is a coin flip.

**The grant-input change is unconditional, and section 10 must say so.** DECISION 9.1 changes what is passed to `GrantAgent::matches` regardless of `security.agent_identity.enabled`. A deployment that leaves identity enforcement off but uses agent-scoped identity grants **does** change behaviour: grants that matched a declared label stop matching. "Enforcement off means nothing changes" is true of sections 6 through 8 and false of this one. It belongs in the breaking-change set, not in "what does not break".

`GrantAgent::Exact` becomes source-qualified — it carries a `ProofSource` alongside the identifier, per DECISION 7.3 — and `Grant::covers` receives the proven pair. **Two** production construction sites must emit the pair rather than a bare string, verified by searching for the variant across `src/`: the CLI parser (`src/commands/identity.rs:329`) and the lease mint (`src/identity_grants.rs:824`). (An earlier draft named a third, "grant recommendations" at `identity_grants.rs:184`; that line is the grants-file `serde` parse, not a construction site, and the citation is withdrawn. The remaining matches are all in test modules.) Persisted 3.x grants hold a bare string, so loading one is a **rejection with a message naming the proof source it must declare**, not a silent promotion to either namespace; the 4.0.0 grant migration DECISION 9.1 already declares is where that rewrite happens. Grants minted under 3.x against a declared label stop matching once the caller can no longer prove that label — the vulnerability closing, not a regression — and that is listed in section 10's breaking-change set and section 11's Tier 1 rows.
- **Mismatch signal**: when a proven principal and a declared label are both present and differ under a DECISION 7.1 arm 3 waiver, audit emits `declared_label_mismatch` with both values. Under rules 1 and 2 the same situation is a refusal — and **the refusal path emits no audit record today**, verified at source: `handlers.rs:612-617` returns `build_http_error_response(None, -32600, reason, FORBIDDEN)` straight from the `validate_agent_identity` error arm, with no audit call, and `backend_handlers.rs:526` has the same shape. So "the refusal is already its own audit record" is false as written. Emitting an identity audit event on the refusal arm is therefore **new work in this change**, not an existing property being relied on; it is listed in section 12's stages and carries its own Tier 3 test row. Without it, the ruling's detection signal exists only on the waiver path, which is the one path an attacker is least likely to be on.

That last bullet is the ruling's "turning the vulnerability into detection", and it is the part that is cheapest to drop under implementation pressure. It is load-bearing for the ruling and is listed as a distinct test row in section 11.

## 10. Backward compatibility and the config matrix

This change alters who gets refused. That is a decision recorded here, not a side effect.

### DECISION 10.1 — the breaking change is taken, default-on, at 4.0.0

Row 2 of the precedence table is the break. A deployment today that sets `X-Agent-ID` and nothing else, with `agent_identity.enabled = true` and either `require_id = true` or a non-empty `known_agents`, **passes**. After this change it **refuses**. Those deployments do not keep working on the new default, and that is the intent: they are precisely the deployments that believe they have an access control and do not.

Permitted because 4.0.0 is a major release. Recorded because the ruling requires it to be a decision.

The escape hatch is the one the ruling names: `security.agent_identity.allow_unverified_agent_identity`, default `false`. When `true`, a declared-only label may satisfy `require_id`, and may satisfy `known_agents` **by matching a `(declared, id)` entry** — the qualified form DECISION 7.3 requires, which only loads when this flag is set. A declared label never matches an `(mtls, …)` or `(jwt, …)` entry even with the hatch on, so turning the flag on does not re-point existing proven-principal entries at self-declaration; an operator restoring legacy behaviour re-declares those entries as `declared` and the config records which ones they are. The gateway **warns at startup** naming the control that is weakened. Legacy behaviour stays reachable; it stops being the default.

**What the hatch does not restore, stated because its name implies otherwise.** It restores exactly one behaviour: row 2 of the precedence table — declared-only may satisfy `require_id` and `known_agents`. It does **not** restore header-over-proof. With the hatch on, a declared label still never outranks a proven principal (rows 3–8 are unchanged) and a contradiction is still a refusal. The hatch also does not touch DECISION 9.1: identity grants authorize on the proven id whether or not it is set, because a hatch that re-opened grant matching to declared labels would re-open the vulnerability rather than defer it. **Round 6 pressed for a header-over-proof migration path inside this flag; that is refused on the merits.** Restoring it would reverse change 2 — "mTLS > verified JWT claim > declared label" — which is the ruling this whole design implements, so it is a scope change and not a fix. The operator who genuinely needs a header to outrank a certificate has **no route on this surface, by design**, and the note must say that rather than imply otherwise. The nearest thing is the existing front-proxy gate, `trust_caller_identity_headers`, which ranks trusted headers above `cert_identity` at `handlers.rs:61-64` and is explicit operator delegation to a proxy that has already authenticated the caller — but it is **not a substitute**: it governs `caller_grant_subject` and `GrantSubject`, the end-user identity path section 12 rules out of scope, and it neither feeds `validate_agent_identity` nor satisfies `require_id` or `known_agents`. An operator pointed at it for an agent-identity 403 would configure it and still be refused. Section 12 rules that gate out of scope here and section 4 records why it is a different trust decision from self-declaration. The distinction is the whole design: a header a *proxy the operator configured* asserts is not a header the *caller* asserts.

**The mis-aimed-hatch trap.** The operator most likely to reach for this flag is the one running a **JWT** *and* sending `X-Agent-ID` — and they will still get a 403, because their failure is a section 7 contradiction, not an unproven identity. Their fix is a `principal_labels` entry for that `client_id`, which the ruling did not name. The mTLS operator is usually a different case and must not be told the same thing: under DECISION 7.2 mTLS normally carries a namespace waiver, so a mismatched label there is **accepted and audited, not refused** — if such a deployment is seeing 403s, the cause is elsewhere and this flag will not help either. The mTLS 403s this design produces are **two**, and the fix differs: an operator who wrote a **per-principal** `principal_labels` entry for that subject widens that entry's label set, and an operator whose subject has **neither** a per-principal entry nor a namespace waiver is hitting DECISION 7.1 arm 4 and must add one or the other. Neither is fixed by this flag. The startup warning and the migration note must distinguish all four, or this flag becomes the first thing tried and the last thing that helps. Renaming it is out of scope — the ruling names the flag — so the documentation carries the correction.

**The hatch exempts obligation 1.** Startup refusal below fires only when the hatch is `false`. With it `true`, a deployment with no proof source configured is coherent — declared labels satisfy the controls — and must start.

### The interaction that makes a gateway unreachable

The more serious compatibility consequence is not the header-only deployment. It is this: **`security.agent_identity` and the sources of proof are independently gated, and an operator can enable enforcement with no proof source available at all.**

- `security.agent_identity.enabled` defaults `false` (`src/security/agent_identity.rs:38-39`).
- `agent_auth.enabled` defaults `false` (`src/config/features/auth.rs:209-211`), and `AgentAuthState` is built from it at `src/gateway/server/mod.rs:1645`. When it is off, `agent_auth_middleware` returns at `oauth/mod.rs:105-107` and no `OAuthAgentIdentity` is ever inserted.
- mTLS is separately configured and optional.

| `agent_identity.enabled` | `require_id` / `known_agents` | agent auth | mTLS | Result |
|---|---|---|---|---|
| false | any | any | any | No enforcement. Unchanged, and this is the shipped default. |
| true | both off | any | any | Extraction and audit, **plus contradiction enforcement**. No caller is required to prove anything, but a caller that *does* prove a JWT principal and declares a label outside its `principal_labels` set is still refused (section 6 row 4). `enabled` is the switch for the contradiction rule; `require_id` and `known_agents` only add the obligation to be identified at all. |
| true | either on | on | off | Works. JWT `sub` is the principal. |
| true | either on | on | **on** | Works. **mTLS subject is the principal** (section 6 rows 7–8); the JWT `sub` is audited, never the allowlist key. **Every** dual-credential caller loses JWT-scoped tools (DECISION 7.3) — the gate fails closed whenever the ranked principal is not `(jwt, sub)`, and once mTLS is present the ranked principal is `(mtls, subject)`. This includes a caller whose `sub` string-equals its mTLS subject: the pair differs in its source, and string equality across namespaces is a coincidence, never an identity. |
| true | either on | off | on | Works. mTLS subject is the principal. |
| true | **`require_id` on**, hatch **off** | **off** | **off** | **Startup fails** (obligation 1, T13 and T20b). No proof source exists, so no caller could ever satisfy `require_id` — the gateway refuses to start rather than starting and then refusing every request. |
| true | `require_id` off, **`known_agents` non-empty**, hatch **off** | **off** | **off** | **Startup fails** — the same obligation. Nothing in the process can construct a `ProvenPrincipal`, so a non-empty allowlist is unsatisfiable. |
| true | `require_id` off, **`known_agents` non-empty**, hatch **on** | **off** | **off** | **Starts, with the weakening warning. Accepts only listed labels.** The hatch makes a declared label satisfy a `(declared, id)` entry, so this is an allowlist on self-declared names — weak, but not inert and not dead. An unlisted label refuses. |

The **mTLS column stays `off` across all three**: they are the no-proof-source case, and the variable that separates them is the hatch, not a proof source. Turning mTLS on anywhere above supplies a proof source and moves the deployment to the `either on / off / on` row, where obligation 1 never fires.

The two hatch-off rows above are the dead gateway obligation 1 exists to prevent — a config that looks reasonable, reachable from today's working configuration by upgrading alone, which is why it is caught at startup rather than discovered per request. The hatch-on row is the escape, and it is a weak one — an allowlist over self-declared names. Three obligations follow:

1. **Startup validation must catch this combination**, not discover it per request. `agent_identity.enabled` with `require_id` or a non-empty `known_agents`, **no proof source of any kind**, and `allow_unverified_agent_identity = false`, is a configuration error — **fail at startup** naming both the missing proof sources and the hatch. "No proof source of any kind" means agent auth off **and** mTLS off or `mtls.enabled = false`: nothing in the process can ever construct a `ProvenPrincipal`. With the hatch `true` the same combination is legal and starts with the weakening warning. A gateway that starts and then refuses everything is the worst available outcome. **Encryption-only mTLS is a separate, milder case and does not fail startup** — it gates nothing, so a `require_id` deployment relying on it will refuse callers who present no certificate, but callers who present one are proven and served. That combination emits a **startup warning** naming the gap, and enforcement happens per request. Failing startup there would refuse a working deployment, which is the same defect this obligation exists to prevent (see the ruling in section 14).
2. **`known_agents` values change meaning.** Under DECISION 3.1 entries must be registered `client_id` values or mTLS subjects, not free labels. No shipped configuration sets `known_agents` — the only occurrences are test fixtures (section 3) — so the repo carries no inventory to migrate, but operator configurations do.
3. **Upgrade notes.** This needs an entry in the 4.0.0 migration material alongside the identity-keyed catalogue and the 3.x credential migration, which the ruling already flags as concurrent load on this release. The migration framework at `src/commands/upgrade.rs` is the existing home for it.

**"Configured" is the wrong predicate for mTLS, and so is "gates requests" on its own.** `config.mtls.enabled` alone does not mean certificates gate anything: `require_client_cert: false` with empty policies is the documented encryption-only migration mode (`src/mtls/config.rs:56-62`), which requires nobody to present a certificate. The predicate for **gating** is the one `src/gateway/server/support.rs:627-628` already computes for the same question: `mtls.enabled && (mtls.require_client_cert || !mtls.policies.is_empty())`, or `agent_auth.enabled`. **That predicate answers the gating question only, and no startup check in this design uses it.** Obligation 1 and T14d both key on `mtls.enabled` alone, because they ask the *proving* question — see the next paragraph and the F6 ruling. An earlier draft closed this one "Startup uses that, not `enabled`", which contradicted both.

But gating and *proving* are two different questions, and obligation 1 above only needs the second. Encryption-only mTLS **is** a reachable proof source, verified at source: the client verifier is built with `.allow_unauthenticated()` in the `require_client_cert = false` branch (`src/mtls/cert_manager.rs:382-391`), which still verifies a certificate that *is* presented, and `src/gateway/server/support.rs:248` extracts a `CertIdentity` from the peer chain regardless of whether one was required. A caller that presents a valid certificate in that mode has an mTLS-proven identity; a caller that presents nothing simply has no mTLS proof and falls through to the other rungs of section 6. So obligation 1 **warns** here rather than refusing to start — see the ruling below.

**Obligation 2 is a schema change, not a re-reading.** Under DECISION 7.3 `known_agents` entries become `(proof source, id)` pairs, so an existing bare-string list fails to load with a message naming the proof source each entry must declare. That is a louder break than "values change meaning" and it is the intended one: silently reinterpreting an existing string as a proven-principal id is how a stale allowlist entry survives into a release that claims to check proof.

### What does not break

**`agent_identity.enabled = false` exempts request-time enforcement, and nothing else.** With the shipped default, `validate_agent_identity` still returns `Ok(())` at its first branch — sections 6 through 8 are untouched. Two changes are **independent of both that flag and the escape hatch**, and an operator reading "enforcement off means nothing changes" would be misled by either:

- **Identity grants** (DECISION 9.1) authorize on the proven pair regardless of `enabled`, so a deployment running grants against declared labels with enforcement off does change behaviour, and persisted 3.x `GrantAgent::Exact` bindings are rejected on load until migrated.
- **Config loading** rejects bare-string `known_agents` entries regardless of `enabled`, because the schema is checked before the flag is read.
- **Grant and scope authorization change regardless of `enabled` and regardless of the hatch.** DECISION 7.3 gives `GrantAgent::Exact` a `ProofSource` and hands `Grant::covers` the proven pair, and closes the agent-JWT scope gate at `authorization.rs:206-214`. Two consequences an operator can miss: a grant written against a bare agent id no longer matches a caller proven by a *different* source, and a caller combining a certificate for principal A with a JWT for principal B stops inheriting B's scopes. That is a deliberate break — it is the vulnerability this row exists to close — but it is not gated by the identity feature flag, so it belongs in release notes next to the config-loading change rather than under "enable this when ready". T7's "unchanged behaviour" claim is scoped to `validate_agent_identity` only and does not extend to these two surfaces.

Everything else holds: deployments already using mTLS or agent JWT auth gain a principal they did not have and keep passing, unless they also send a contradicting `X-Agent-ID` under DECISION 7.1 arms 2 or 4. Those deployments do acquire a new mandatory config step, `principal_labels`, which section 7 records as a stated cost. Cost attribution and tracing keep receiving the declared label (section 9). The refusal shape on both routes is unchanged, so anything asserting `-32600` plus 403 stays valid.

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
| T4 | Same as T3 with mTLS as the proven source, under a **namespace waiver** for the mTLS source | **accept**, principal stays the mTLS subject, and `declared_label_mismatch` is audited with both values — **not** a refusal | row 6 under a waiver: the operator has declared the namespace incomparable, so the mismatch is a detection signal. Red at `HEAD` on both halves | **accepts, and the header becomes the principal**; no mismatch event exists |
| T4b | Same inputs as T4, but the mTLS subject carries a **per-principal** `principal_labels` entry whose label set excludes the declared label | **refuse**, message naming the contradiction and both values | row 6 under a mapping. The mirror of T4: without this row the mTLS half of change 2's contradiction refusal is never exercised, and an implementer who made per-principal mTLS entries unrepresentable would still pass the suite | **accepts, header wins** |
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
| T12 | `allow_unverified_agent_identity = true`, declared-only label listed in `known_agents` as a **`(declared, id)`** entry | accept — legacy path reachable — **and** a startup warning was emitted. **The same label against an `(mtls, id)` or `(jwt, id)` entry naming the identical string must still refuse**, even with the hatch on: the hatch adds a declared source, it does not re-point proven-principal entries at self-declaration (section 10). Without that second half the row stays green while the escalation it pins is wide open |
| T13 | `agent_identity.enabled = true`, `require_id = true`, agent auth off, mTLS off | **startup fails** with a message naming both missing proof sources and the opt-in (section 10 obligation 1) |
| T14 | Waivered proven principal, unequal declared label | accept, and `declared_label_mismatch` is emitted with both values (DECISION 7.1 arm 3, change 4) |
| T14b | Mapped proven principal, declared label outside its set | **refuse** (DECISION 7.1 arm 2 — reached only because the declared label differs from the proven id; see T14f for the case where it does not) |
| T14c | `agent_identity.enabled`, declared labels accepted, a **registered JWT `client_id`** absent from `principal_labels` | **startup fails** — the enumerable tier must be totally covered (DECISION 7.2) |
| T14d | `agent_identity.enabled`, declared labels accepted, **`mtls.enabled = true` — including the encryption-only case where `require_client_cert = false` and `policies` is empty** — and the mTLS proof source carries **neither a namespace waiver nor any per-principal entry** | **startup fails** — the non-enumerable tier must be explicit, even though it is not required to be total. The mirror of T14c: neither tier may be left implicit. The trigger is the `mtls.enabled` flag alone, never the vaguer "mTLS configured": encryption-only mTLS is a proof source (F6) and therefore owes a label declaration like any other. A deployment carrying only per-principal mTLS entries and no waiver **starts**, and its unnamed subjects hit the request-time backstop |
| T14e | A proven `(source, id)` reaching the request path **with a declared label present that differs from the proven id** and that is absent from `principal_labels`, whose source carries no namespace waiver — e.g. a JWT client registered by a config reload after startup | **refuse** — DECISION 7.1 arm 4, the request-time backstop, never "incomparable". The startup census alone cannot catch this. Two parts of the trigger, and both are load-bearing: with no declared label present the same caller is accepted (T26b), and with a declared label **equal** to the proven id it is accepted under arm 1 (T14f) |
| T14f | A proven `(jwt, "svc-a")` **mapped** to `{"billing"}`, caller declares `X-Agent-ID: svc-a` | **accept** — DECISION 7.1 arm 1 runs ahead of arm 2, so a principal declaring its own name is never refused by a mapping that omits it. Red against any implementation that codes membership before exact match, which is the reading round 6 found the old three-paragraph phrasing permitted |
| T15 | Audit record for any accepted request carrying both | `agent_proven`, `agent_proof`, `agent_declared`, `agent_declared_source` present as distinct fields, **and `agent_secondary_proof` present on a row-7 or row-8 caller** — the field funded change 4 exists to populate (section 4's `secondary_proof`). Without that assertion the stronger proof can overwrite the JWT `sub` and the row still passes |
| T16 | mTLS proves principal A; a valid JWT for principal B rides along; the call needs a scope only B holds | **refuse** — the outranked credential contributes no scope (DECISION 7.3, `authorization.rs:206-214`) |
| T16b | mTLS proves CN `runner`; a valid JWT whose `sub` is the **identical string** `runner` rides along; the call needs a scope that JWT holds | **refuse** — the pair `(jwt, "runner")` is not the ranked `(mtls, "runner")`, so the scope gate still fails closed. Pins the equal-string case that an implementer reading "whose `sub` differs" would readmit |
| T17 | Grant minted for `GrantAgent::Exact` on a proven principal; caller sends only `X-Agent-ID` naming it | **refuse** — a declared label never satisfies a grant (DECISION 9.1). Red at `HEAD`: today it passes |
| T18 | `known_agents` holds `(jwt, "runner")`; caller proves mTLS CN `runner` | **refuse** — the pair does not match; string equality is a coincidence (DECISION 7.3). Red at `HEAD` |
| T19 | Grant holds `(jwt, "runner")`; caller proves mTLS CN `runner` **and sends `X-Agent-ID: runner`** | **refuse** — the same pair rule at the grant surface. Red at `HEAD`, and the declared header is what makes it red: `GrantAgent::Exact` compares `agent_id: Option<&str>` by bare string (`src/identity_grants.rs:65-68`), so at `HEAD` the header supplies `"runner"` and the grant matches across namespaces. Without the header a certificate-only caller has `agent_id = None`, `is_some_and` short-circuits, and `HEAD` already refuses — a green baseline that would prove nothing |
| T20 | `mtls.enabled = true`, `require_client_cert = false`, empty policies, `agent_identity.enabled`, `require_id = true`, hatch `false`, **and an mTLS namespace waiver present** (or `disable_declared_labels = true`) | **startup succeeds with a warning** naming the gap, and enforcement is per request: a caller presenting a valid certificate is **proven and accepted**, a caller presenting none is **refused** under `require_id`. Encryption-only mTLS gates nobody but still verifies what is presented (`cert_manager.rs:382-391`, `server/support.rs:248`), so refusing to start would refuse a working deployment. **The waiver in the config is not decoration.** Obligation 1 asks whether a proof source exists; T14d's census asks whether the labels tier is declared. They are separate obligations over the same config, and round 6 caught this row silently failing the second one — without the waiver, T14d refuses to start the exact config this row asserts starts (section 14, ruling on F6) |
| T20b | `agent_identity.enabled`, `require_id = true`, hatch `false`, agent auth **off** and mTLS **off** entirely | **startup fails** — no proof source of any kind exists, so no caller can ever be proven. This is T13's config; the row is repeated here only as T20's contrast and the two are one test. The distinction from T20 is the whole of the F6 ruling: nothing to prove with versus nothing required to prove |
| T21 | Existing config with bare-string `known_agents` entries | **load error** naming the proof source each entry must declare (section 10 obligation 2) |
| T22 | Contradiction refusal on both routes | the 403 emits an identity audit event carrying both values — the refusal arms are silent today (`handlers.rs:612-617`, `backend_handlers.rs:526`), so this is red at `HEAD` |
| T23 | Durable task admitted with a proven principal and a different declared label; grant checked **after** worker dispatch | the rebuilt `OwnedCallerContext` authorizes on the proven pair and attributes cost to the declared label — a flattened snapshot fails this even when the router is correct |
| T24 | A task **resumed** through the recovery path, where the recovery request carries its own live credentials (`RecoveryCaller`, `handlers/tasks.rs:295`) — run twice: once where the recovering caller's proven pair equals the creating caller's, once where it **differs** | the recovery read authorizes on the **proven pair of the request in front of the gateway**, and attributes to that request's declared label. **Not a snapshot:** `RecoveryCaller`'s own doc comment (`handlers/tasks.rs:201-205`) says every field is this request's live context and nothing is restored from the record — the durable descriptor supplies only the target. Round 6 caught this row asserting the opposite, which would have specified a test that re-authorizes a stored identity. The differing-principal case is the one that matters: it fails if recovery ever judges the target against the creating caller instead of the current one. Distinct from T23: T23 exercises dispatch of a freshly admitted task, and only this row fails if recovery reads the declared field |
| T25 | `principal_labels` entries that are malformed under DECISION 7.2a: one carrying both `labels` and `incomparable`, and one carrying neither | **load error** on each, naming which rule it broke |
| T25b | A `principal_labels` list holding **both** a `source: mtls` namespace waiver **and** a `source: mtls` entry with an `id` | **loads**, and at request time the per-principal entry governs the subject it names while the waiver governs every other mTLS subject. This is the precedence DECISION 7.2a states. An earlier draft made this list a load error, which is what made mTLS contradiction refusal unreachable; this row pins that it is expressible |
| T26 | `enabled = true`, `disable_declared_labels = true`, no `principal_labels` at all | **startup succeeds, and an authenticated request is dispatched successfully** — no label can arrive, so no mapping is owed and the request-time backstop never fires. The negative of T14c/T14d: proves the mandatory-config cost is escapable by the one documented route, and that escaping it does not produce a gateway that starts and then refuses everything. The startup half alone is not enough — a doc that asserts only startup is how that failure mode survived into round 5 |
| T26b | `enabled = true`, a proven principal with **no** `principal_labels` entry and no namespace waiver, **no declared label sent** | **accept** — the backstop is gated on a declared label being present (DECISION 7.2). The negative of T14e, and the row that fails if the backstop is written unconditionally |
| T28 | `allow_unverified_agent_identity = true`, a proven principal present, contradicting `X-Agent-ID` | **refuse** — the hatch restores declared-only matching, never header-over-proof (section 10) |
| T29 | `allow_unverified_agent_identity = false` with a `(declared, id)` entry in `known_agents` | **load error** — the declared source is unreachable without the flag |
| T30 | Anonymous caller, `known_agents` non-empty, `require_id = false` | **accept** — unchanged from `agent_identity.rs:158`; pins the row that deliberately does not flip |
| T27 | Proven mTLS principal, no `principal_labels` entry and no namespace waiver, **declared label present and different from the selected proven id** | **refuse** at request time — a missing mapping is never read as incomparable (DECISION 7.1 arm 4). The mTLS twin of T14e, and it carries the same differs condition: a caller declaring `X-Agent-ID` equal to **the selected proven id** accepts under arm 1, and T14f's mTLS counterpart is that case. **The selected id, not the CN.** Selection is SAN-URI-else-CN (see T32), so on a certificate carrying both, the proven id is the SAN URI and a header equal to the CN is a *contradiction* that refuses under arm 4. Stating this exception as "equal to its own CN" would license accepting precisely the contradictory header this design exists to reject |
| T27a | Client certificate carrying **both** a SAN URI and a CN whose values differ, `X-Agent-ID` equal to the **CN** | **refuse** — the proven id is the SAN URI, so the declared label contradicts it. The falsifier for T27's selection clause: an implementation that compares the header against the certificate subject generally, rather than against the id the selection rule chose, passes T27 and fails here |
| T31 | A `principal_labels` entry keyed `source: declared` | **load error** — the surface exists only to compare a *proven* principal against a label, so a declared-to-declared mapping is meaningless. The parallel of T29 on the other config surface: `known_agents` admits `declared` only under the hatch, `principal_labels` never admits it at all |
| T32 | An **unnameable** client certificate (no SAN URI, no CN) presented alongside a **verified** agent JWT, `known_agents` non-empty | **accept**, with the JWT `sub` as the proven principal and **`secondary_proof` empty** — the positive counterpart to the section 4 selection rule. `secondary_proof` is an `Option<ProvenPrincipal>`, and section 4 forbids constructing a `ProvenPrincipal` for such a certificate, so the type cannot hold it and the assertion must not ask for one; the handshake is recorded, if at all, as a non-principal audit detail. Fails if an implementation falls back to `CertIdentity::display_name` for the principal, which would make a cosmetic field an allowlist key. A suite of refusals alone cannot catch that; this row is its falsifier |
| T33 | `identity grant --agent runner` with no source qualifier | **CLI error** naming the accepted `mtls:` and `jwt:` prefixes — the write path cannot emit a shape the loader rejects, and cannot default to a source on the operator's behalf |

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

Tier 1 is entirely refusals — necessary, and not sufficient. A change that refuses everything passes every refusal test. Each Tier 1 refusal therefore pairs with a positive row proving the legitimate caller still gets through: a verified JWT `sub` on the allowlist accepted (against T1's declared-only refusal), an mTLS subject accepted with a consistent declared label (against T3's contradiction refusal), a **genuinely signed** bearer token accepted and its `sub` used as the principal (against T5's unsigned-token refusal — the point of T5 is that the verified rung was really built, so its counterpart must exercise that rung, not a waiver; the waived-namespace accept is T14's counterpart, not T5's), and a grant scoped to a proven agent still matching for that agent (against DECISION 9.1's new refusal). Existing happy-path tests do not supply this: they were written against the conflated `id`, so several of them pass *because* a declared label satisfies the control, which is the behaviour being removed. They are listed in section 5 as test sites requiring rework for exactly that reason, and a reworked test is not independent evidence of the behaviour it was rewritten to accommodate.

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

Per the ruling, design review comes before any code. Order, from the `MIK-6746.IDENTITY.1` row (`criteria[19]`, tracked as MIK-7512):

1. **Design review** — this document. **Rounds 1 through 6 are complete** (section 14). DECISION 3.1, 7.1, 7.2, 7.3, 9.1 and 10.1 need explicit sign-off, and so do the two **agent rulings** recorded in round 5 (F3, which keeps DECISION 3.1 against the ledger row's analysis prose, and F6, which downgrades an encryption-only-mTLS startup failure to a warning). 7.1 adds a mandatory operator config step, 9.1 narrows an existing grant behaviour, and 10.1 breaks existing deployments; all three are reasonable places for a reviewer to rule differently.
2. **Test review** — section 11 reviewed as a plan, including the red-before-green ordering and the positive rows added in round 1.
3. **Failing tests** — Tier 1 written and demonstrated red against `HEAD`.
4. **Implementation** — sixteen production sites from section 5, **plus five surfaces the review rounds added**: the identity-grant request path (DECISION 9.1, `handlers.rs:1448/1566/1597` → `identity_grants.rs:608`); the JWT-scope gate at `authorization.rs:206-214` that DECISION 7.3 funds; the `MetaMcpCallerContext` and `invoke.rs` ASI03 audit line that carry `agent_id` past the router (`src/gateway/meta_mcp/mod.rs:157`, `invoke.rs:1137`, `:1893-1915`); an identity audit event on the refusal arm (`handlers.rs:612-617`, `backend_handlers.rs:526`), which does not exist today; and **the durable task worker that section 5 puts in scope as the fourth past-the-router site** — `TaskIntentRequest` and `OwnedCallerContext` (`src/gateway/task_service/execution/context.rs:20`) gain separate proven and declared fields, the fill at `handlers/tasks.rs:171` stops flattening them into one `Option<String>`, the rebuild at `context.rs:123` carries both, and the recovery caller at `handlers/tasks.rs:295` authorizes on the proven pair while attributing to the declared label. Omitting the worker was the gap that made section 5's fourth site prose: it is the longest-lived copy of the caller, so a split that stops at the request boundary leaves the conflation intact one dispatch later. Tested at T23 (worker dispatch) and T24 (recovery). The repo gate fires here: `gitnexus_impact` on `extract_agent_identity` and `validate_agent_identity` before editing either, and `gitnexus_detect_changes` before committing.
5. **Final review** — including a re-run of the OWASP Agentic AI checklist at `docs/OWASP_AGENTIC_AI_COMPLIANCE.md`, since ASI03 is the control this module claims.
6. **Docs and housekeeping** — module docs at `:10-15` and `:24-28`, the upgrade notes from section 10, and `MIK-6746.IDENTITY.1` advanced from `stage: graded` in the ledger's `criteria` list. No `funded_work` key is created to do it; the gate rejects any top-level key beyond the three it names.

## 13. Falsifier

The cheapest check that this design is wrong, with a pass/fail threshold, runnable before implementation:

**Claim under test:** the proven principal is available at both call sites, so the precedence table is implementable without new plumbing.

**Check:** at `handlers.rs:603` and `backend_handlers.rs:517`, assert in a route-level test that `CertIdentity` and `OAuthAgentIdentity` are present in request extensions for a caller that presented each, on both routes.

**Threshold:** all four combinations present. **Fail:** any absent on either route means the middleware ordering analysis in section 3 is wrong, the design needs a plumbing stage it does not currently have, and section 6 rows 3 through 8 are unimplementable as written.

**Current expectation, from source rather than execution:** passes. `/mcp/{name}` is registered at `router/mod.rs:256` into `routes`, and the agent-auth layer is applied to `routes` at `:279-284`, so it covers both routes; the wrapping-order comment at `:286-291` places agent auth after authentication and before the handler. `cert_identity` and `oauth_agent_identity` are already bound at `handlers.rs:583-587` and `backend_handlers.rs:489-490`. The routes merged after the layer at `:309-331` are jwks, metrics, key-server and UI — none of them dispatch routes.

This was verified by reading, not by running. Running it is the first task of the implementation stage.

## 14. Design review rounds 1 through 6 — findings and disposition

### Round 1 — two independent non-Claude reviewers

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
| B6 | Contradiction refusals were assumed to be audited; they are not | gpt | `handlers.rs:612-617` returns the error with no audit call; `backend_handlers.rs:526` matches | audit-on-refusal is now named as new work with its own test row |
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

### Round 2 — gpt reviewer, on the revised document

Run record: `/private/tmp/claude-501/.../tasks/bq5l4h41e.output`. Verdict **SHIP-WITH-FIXES**:
"authorization still loses identity provenance at grant and recovery boundaries." Five findings,
all applied. Three of them are round-1 fixes that were incomplete rather than new ground, which
is the expected shape of a second round and the reason one was run.

| # | Finding | Verified at | Disposition |
|---|---|---|---|
| R2-1 | DECISION 9.1 said "proven id", contradicting DECISION 7.3's `(source, id)` keying — an mTLS subject could satisfy a grant meant for a same-named JWT principal | internal inconsistency between two decisions added in the same round | 9.1's table now reads **proven `(source, id)` pair** |
| R2-2 | DECISION 7.3 ranks the principal but leaves the losing credential's **scopes** authorizing independently | scope authorization reads the JWT without consulting which principal won | 7.3 extended: the losing credential contributes no authorization input of any kind |
| R2-3 | `RecoveryCaller.agent_id` was classified attribution-only, but the recovery path authorizes on it | `handlers/tasks.rs:295`, in a context whose comment at `:286` says "checks authorization only" and whose `signing: None` at `:290-292` keeps `check_invocation_policy` running | recovery moved to the authorization side; the split now runs through `RecoveryCaller` |
| R2-4 | "mTLS, explicit subject list" was treated as enumerable on the strength of an exact comparison | an equality rule still admits any CA-signed certificate satisfying it | enumerable redefined: the **config holds the identifiers**, never "the comparison is exact" |
| R2-5 | Section 10 claimed enforcement-off deployments are untouched, but the grant-input change is unconditional | DECISION 9.1 changes `GrantAgent::matches` input regardless of `agent_identity.enabled` | stated as a breaking change; agent-scoped grants change behaviour with enforcement off |

Two improvements also taken: the serialized shape of the source-qualified allowlist and its
treatment of legacy bare strings under the escape hatch needs specifying at implementation
time, and the test plan gains explicit rows for anonymous-allowlist rejection, refusal
auditing, grant spoofing, namespace collision and recovery authorization.

**The pattern worth naming.** R2-3 is the second time a consumer of the flattened `agent_id`
was called telemetry and turned out to authorize. Round 1 found the grant path; round 2 found
the recovery path behind it. Neither was found by reasoning about the design — both were found
by grepping the consumers. Before implementation begins, the remaining consumers of
`MetaMcpCallerContext.agent_id` get the same treatment, and the result is recorded here rather
than assumed.

### Round 2 — grok reviewer, on the revised document

Verdict **SHIP-WITH-FIXES**: *"DECISION 7.3 is not reflected in the `known_agents` config
surface or the validation-site inventory, so the round-1 namespace finding is not closed."*
Four blockers and five improvements. Record at
`~/.claude/data/reviews/runs/grok-20260920T235914Z-54577.md`. Every claim below was checked
against source before it was accepted or rejected; the reviewer's word is not the evidence.

| # | Finding | Verified? | Disposition |
|---|---|---|---|
| G1 | DECISION 7.3 keys by `(proof source, id)` in prose while `known_agents` stays `Vec<String>` | **yes** — `agent_identity.rs:49`, `:161` | applied: the schema change is now part of 7.3, and section 10 obligation 2 states it as a load error rather than a re-reading |
| G2 | Section 10 obligation 1 treats "mTLS configured" as a proof source, weaker than `mtls_gates_tools` | **yes** — `support.rs:627-628`, `mtls/config.rs:56-62` | applied: obligation 1 reuses the existing predicate for what **gates** requests. **Superseded in part by the round-5 F6 ruling**: gating and proving are different questions, and encryption-only mTLS still verifies a certificate that is presented, so it is a reachable proof source. Obligation 1 warns there instead of refusing to start, and T20 now asserts the warning |
| G3 | The row-1 flip — anonymous caller against a non-empty `known_agents` — is an unnamed break | **no** | rejected on source: `:158` returns `Ok` before the allowlist at `:161`, so that row has never refused and does not start. The table was missing the row, which is what produced the misread; the row and the reasoning are now in section 8 |
| G4 | DECISION 9.1 keeps `GrantAgent::Exact` as bare-string equality, reopening 7.3 at the grant surface | **yes** — `identity_grants.rs:65-68`, `:232`, `:608` | applied: `Exact` carries the proof source, `Grant::covers` takes the pair, T19 pins it |
| G5 | Section 5's "no type change past the router" freeze contradicts 9.1 | **yes** — `meta_mcp/mod.rs:157`, `invoke.rs:1137`, `:1893-1915` | applied: the freeze is retracted in place and the three sites are in section 12 stage 4 |
| G6 | 7.2's "mTLS, explicit subject list" describes a type that does not exist | **yes** — `CertMatchConfig` has five fields, `cn`/`ou` are "exact or glob" | applied: enumerability is a property of the configured value, not of the field |
| G7 | 7.3's "the losing credential grants nothing" is false while JWT scopes apply independently | **yes** — `authorization.rs:183-204` and `:206-214` are two independent gates | applied: the rule is funded at `:206-214`, listed in stage 4 and tested at T16, rather than asserted |
| G8 | Show YAML for `principal_labels` and the namespace waiver as distinct fields | n/a — editorial | **deferred to the test-review stage**, where the config shape is reviewed against the tests that exercise it. Recorded here so it is not lost |
| G9 | Add Tier 1 rows for declared-only grant rejection and cross-namespace allowlist | — | applied as T17 and T18 |

Two of these — G1 and G4 — are the same defect wearing two config surfaces, and both are
round-1 fixes that stopped at the prose layer. That is now the second review in a row where
the recurring failure is a decision stated in a paragraph and not carried into a type. The
discriminator the next round should apply to every decision in this document: **name the type
or the config key the decision changes, or the decision is not made.**

### Round 3 — gpt and grok reviewers, on the twice-revised document

Both returned **SHIP-WITH-FIXES**, and both named the same defect class: not a missing
decision this time, but the *same* decision stated two incompatible ways in two sections.
Every finding below was verified against the cited line before it was applied — the
reviewers agreed on six of nine independently.

| # | Finding | Verified at source | Disposition |
|---|---|---|---|
| R3-1 | `Exact` carries the proof source (7.3) but "keeps its shape" (9) — G4 reopened | yes — both sentences present | applied: 9 now states the source-qualified type, its three construction sites, and rejection-on-load for 3.x bindings |
| R3-2 | The enumerable-mTLS tier cannot work: the census keys on policy match values, the proven id is SAN-URI-then-CN | yes — section 4's selection order versus 7.2's table | applied: the mTLS row is `no` unconditionally, plus a request-time fail-closed backstop. **Supersedes the G6 and R2-4 dispositions below** |
| R3-3 | 7.3 says both "authorize on the mTLS path alone" and "refuse what the JWT would have passed", and names `principal_labels` as the combining mechanism though it only binds declared labels | yes | applied: fail-closed stated once, the combining sentence deleted, the dual-auth lockout listed as a breaking change |
| R3-4 | Whether a non-empty `known_agents` refuses an anonymous caller is specified three ways | yes — section 6 row 1 said refuse, section 8 said both | applied: all three now match `agent_identity.rs:158`, which returns `Ok(())` before the allowlist check. The duplicate row is gone and T30 pins it |
| R3-5 | The escape hatch promises declared-only allowlist matching against an allowlist that accepts only proof-qualified entries | yes — no matching rule existed | applied: a `declared` proof source, loadable only with the hatch on; T29 pins the load error |
| R3-6 | The propagation inventory omits the durable task worker's owned caller snapshot | yes — `context.rs:20`, `:123`, `handlers/tasks.rs:171` | applied: a fourth past-the-router site, with T23 testing grant authorization after dispatch |
| R3-7 | Section 10's matrix makes the JWT `sub` the principal even with mTLS on, contradicting rows 7–8 | yes | applied: the row is split by mTLS state |
| R3-8 | **M** is defined as certificate presence, but an unnameable certificate is separately assigned to the no-proof row | yes | applied: M is a *resolved* principal, so such a handshake falls through to the JWT |
| R3-9 | Round 2 recorded recovery-authorization and refusal-audit test rows as taken; section 11 had neither | yes — neither row existed | applied, then **corrected in round 4**: T22 covers the refusal audit, but the T23 written in round 3 covers *worker dispatch*, not recovery. Round 4 adds T24 for the recovery path (`RecoveryCaller`, `handlers/tasks.rs:295`). The round-3 disposition overstated what it had applied |

Residual, recorded rather than resolved: A2A carries no agent-identity path today and stays
unruled as a future bypass; glob-metacharacter definition is now moot for mTLS but still
undefined elsewhere; config-reload re-census is covered by the R3-2 request-time backstop
rather than by a reload hook. The YAML shapes (G8) were deferred here and are **no longer
deferred** — round 4 wrote them into DECISION 7.2a.

What the three rounds have in common is worth stating, because it predicts round 4: round 1
found decisions missing, round 2 found decisions stated in prose but not in types, round 3
found decisions stated twice and differently. Each round's fix created the next round's
defect — adding a decision in one section without reconciling every section that already
spoke to it. The discriminator for the next round: **for each decision, grep the document
for every other place it is described, and make them one sentence or one table.**

### Round 4 — gpt and grok reviewers, on the thrice-revised document

Both returned **SHIP-WITH-FIXES**. The prediction above held exactly: every finding in this
round was a section that still spoke an earlier version of a decision section 7 had since
changed. No reviewer disputed what the work is for, and no new decision was opened.

| # | Finding | Severity | Verified at source | Disposition |
|---|---|---|---|---|
| R4-1 | Section 10 scoped the dual-auth lockout to callers "whose `sub` differs", but DECISION 7.3 fails the scope gate closed whenever the ranked pair is not `(jwt, sub)` — so an mTLS CN and a JWT `sub` that are the *same string* recombine | CRITICAL (grok) | yes — `:307` against the section 10 matrix row | applied: the matrix row now covers every dual-credential caller and says why string equality does not exempt one; pinned at new row T16b |
| R4-2 | DECISION 7.2 made every mTLS policy non-enumerable, but section 7.1's census sentence, section 6 rows 6 and 8, and T4 still described per-principal mTLS mapping and mTLS contradiction refusal | HIGH (grok) / MEDIUM (gpt) | yes — four sites, each read | applied: rows 6 and 8 now accept and audit under the waiver, T4 is retargeted to assert exactly that, and the census sentence names JWT as the only enumerable tier. **Partly superseded by F2/F10 in round 5**: dropping the census was right, but this round also made per-principal mTLS entries unrepresentable, which made change 2's contradiction refusal unreachable for mTLS in every configuration. Rows 6 and 8 are now conditional on whether the subject carries a per-principal mapping |
| R4-3 | `known_agents` was keyed by a three-value source including `declared`, but `ProofSource` has two variants, and `GrantAgent::Exact` was told to carry "the proof source" without saying which type | HIGH (grok) | yes — `:302` against the section 4 enum | applied: the config key is now a named, distinct three-valued `AgentSourceKey`; `GrantAgent::Exact` carries the two-valued `ProofSource`, making a declared-label grant unrepresentable rather than merely forbidden |
| R4-4 | Section 5 put `OwnedCallerContext` and `TaskIntentRequest` in scope as the fourth past-the-router site; section 12 stage 4's implementation list omitted them | HIGH (grok) | yes — `:220` against stage 4 | applied: stage 4 now names the worker sites and the recovery caller, and its surface count is corrected from two to five |
| R4-5 | Section 6 refuses a contradicting label whenever `enabled = true`, but the section 10 matrix called `enabled` with both controls off "extraction and audit only" | MEDIUM (both) | yes | applied: that row now states contradiction enforcement explicitly and separates what `enabled` switches on from what `require_id`/`known_agents` add |
| R4-6 | The matrix claimed **every** request refuses when no proof source exists, but section 6 row 1 accepts when `require_id` is false | MEDIUM (gpt) | yes | applied: the row is split — `require_id` on refuses everything, `require_id` off with a non-empty `known_agents` accepts and the inert allowlist is warned about |
| R4-7 | Section 5 promised no existing configuration fails to parse, while T21 requires a `known_agents` load error | MEDIUM (gpt) | yes — `:214` against T21 | applied: the compatibility claim is narrowed to the additive fields and names the one deliberate break |
| R4-8 | The round-3 disposition recorded a recovery-authorization test as applied; T23 tests worker dispatch, which is a different path | MEDIUM (gpt) | yes — T23 read in full | applied: T24 added for the recovery caller, and the R3-9 row now records that it overstated itself |
| R4-9 | Section 8's grant text named three `GrantAgent::Exact` construction sites, citing `identity_grants.rs:184` for "grant recommendations" | improvement (gpt) | yes — `:184` is the grants-file `serde` parse; a search for the variant across `src/` finds two production sites and the rest in tests | applied: citation withdrawn, count corrected to two |
| R4-10 | The section 4 comment sent an unnameable certificate to "no principal" in a way that read as denying JWT fallback | MEDIUM (gpt) | partly — section 6's **M** definition was already correct, so this was a comment defect, not a rule defect | applied as a comment clarification; the rule was already right |
| R4-11 | `principal_labels` had no written serialization, and the startup gate fired on the undefined predicate "declared labels are accepted" | improvement (both, and G8 since round 1) | n/a — a gap, not a contradiction | applied: DECISION 7.2a writes the YAML, makes the waiver a distinct enum variant, and defines the predicate as `enabled && !disable_declared_labels`. Covered by T25 and T26. **The round-4 draft also made per-principal mTLS entries a load error; the round-5 F2/F10 ruling reverses that**, since it left change 2's contradiction refusal unreachable for mTLS |
| R4-12 | T5's positive counterpart was a waived-namespace accept, which is T14's counterpart | improvement (grok) | yes — `:507` | applied: T5 now pairs with a genuinely signed bearer token, exercising the rung T5 exists to prove |

Two findings were **not** applied as stated. R4-10 was downgraded: gpt read a rule defect where
section 6 already had the rule right, so only the comment changed. And gpt's remaining
improvement — "replace repeated normative rules with references to one authoritative decision
table" — was applied as a **standing rule rather than a table rewrite**: DECISION 7.2a now
declares section 7 the single normative source and every other section an illustration of it.
Rewriting sections 6, 8, 10 and 11 into pure cross-references would cost more readability than
it buys, but a conflict between them and section 7 is now defined as a defect in them, which is
what the four rounds of drift actually needed.

This round added one config field that did not exist when the round began
(`disable_declared_labels`), so section 5's field count was updated in the same pass. Recording
that explicitly because it is precisely the move that seeded rounds 2 through 4: a decision
added in one section and not reconciled with the sections that already counted it.

**Self-check, and what it caught.** Applying the discriminator to this round's own edits — grep
the document for every other place each changed decision is described — found two further sites
neither reviewer reported. Section 7.1's cost paragraph still called `principal_labels` the
"second" new config surface, already stale by one field. More seriously, section 10's
mis-aimed-hatch paragraph told the mTLS operator they "will still get a 403": a fourth instance
of R4-2, in a section neither reviewer cited for it, and the one place a wrong answer would have
reached an operator debugging a live deployment. Under DECISION 7.2 an mTLS mismatch is accepted
and audited, so that operator has no 403 to explain and would have been sent chasing a
`principal_labels` entry the schema now refuses to accept. Both are fixed. The lesson is that
the discriminator works and that reviewer coverage is not a substitute for running it: two
independent seats read this document and neither flagged the paragraph most likely to mislead a
human.

### Round 5 — findings and disposition, plus two agent rulings

Both external reviewers returned **SHIP-WITH-FIXES**; the review lead did not, on the grounds
that four of the defects produce a gateway that starts and then refuses legitimate traffic, or
a checklist that builds the collision this design exists to close. Every finding was
re-verified at source before it was applied.

| # | Finding | Verified at source | Disposition |
|---|---|---|---|
| F1 | The header and section 12 cited `MIK-6746.IDENTITY.PROVABLE` at `funded_work[0]`; neither exists, so the DoD was unexecutable | yes — ledger top-level keys are exactly `schema_version`, `criteria`, `decisions`, and `scripts/release/check_scope_acceptance.py:192-197` rejects any other set. The real row is `MIK-6746.IDENTITY.1` at `criteria[19]`, `stage: graded`, tracked MIK-7512 | applied: header and stages 1 and 6 now name the row, its stage vocabulary and the reason no `funded_work` key may be created |
| F2 / F10 | mTLS contradiction refusal was unreachable in every configuration **and** the document contradicted itself about it — section 6 rows 6 and 8 said "no mTLS contradiction refusal", section 7.2a made a per-principal mTLS entry a load error, yet section 6 property 3 still said rows 4, 6 and 8 refuse | yes — all four sites read. The premise (proven id is SAN-URI-else-CN versus `CertMatchConfig`, `src/mtls/config.rs:122-136`) justifies dropping the **startup census** only, not the rule | applied: `{source: mtls, id, labels}` is permitted and enforced at request time, the waiver stays the default and normal configuration, only totality is dropped. Reconciled across §7.1, §7.2, §7.2a, §6 rows 6 and 8, §6 property 3, §10's mis-aimed-hatch paragraph, T4, T4b, T14d, T25, T25b |
| F3 | DECISION 3.1 diverges from the ledger row's analysis prose | yes — note quoted in §3 | **RULED (team-lead): DECISION 3.1 STANDS.** See §3. Overturn in one line by ruling the proven rung must be an `agent_id` claim |
| F4 | §6 property 1's "no path from `X-Agent-ID` to an authorization pass" stood unqualified while `caller_grant_subject` ranks trusted headers above `cert_identity` one function away | yes — `handlers.rs:51-67`, `:61-64`, and the header set at `:78-91` is `x-gateway-identity-*` / `cf-access-*`, which does **not** include `X-Agent-ID` | applied: property 1 is scoped to `X-Agent-ID` and the query param, and names the neighbouring resolver and its operator gate |
| F5 | §7.2's request-time backstop refused any proven `(source, id)` absent from `principal_labels` with no requirement that a declared label be present, so a `disable_declared_labels` deployment would start (T26) and then refuse every authenticated request | yes — §7.2 backstop against §7.2a and T26 | applied: the backstop is gated on a declared label being present, T26 now asserts a successful dispatch, T26b pins the no-label accept, T14e names the label as part of its trigger |
| F6 | §10 failed startup for `require_client_cert = false` plus empty policies, a config that does verify presented certificates | yes — `src/mtls/cert_manager.rs:382-391` builds the verifier with `.allow_unauthenticated()` at `:388` in that branch, and `src/gateway/server/support.rs:248` extracts a `CertIdentity` from the peer chain regardless | **RULED (team-lead): DOWNGRADED to a startup warning plus request-time enforcement.** mTLS-proven identity is reachable in that config, so failing startup refuses a working deployment — the failure obligation 1 exists to prevent. Same shape as the F2 fix: drop totality at load, enforce at the request. T20 inverted, T20b added as its contrast. Overturn in one line by ruling that a proof source which gates nobody may not satisfy obligation 1 |
| F7 | T24, T25 and T26 each appeared twice for different scenarios | yes — two occurrences of each | applied: the first occurrences keep their identifiers so round-5's references stay readable; the second occurrences become **T28, T29 and T30**. The round-3 and round-4 dispositions that pointed at the second occurrences were repointed (R3-4 → T30, R3-5 → T29); those naming the first occurrences were left alone |
| F8 | §5 site 6 told the implementer to test `proven.id` only, contradicting DECISION 7.3's pair lookup — and §5 is the checklist implementation builds from | yes — §5 against DECISION 7.3 | applied: site 6 states the `(proof source, proven.id)` pair and names the collision the bare id would build |
| F9 | T12 asserted only that a declared-only label listed in `known_agents` is accepted with the hatch on, so it stayed green while matching an `(mtls, …)` row — the escalation it exists to catch | yes — T12 against §10's `(declared, id)` rule | applied: T12 now requires the entry to be a `(declared, id)` row **and** requires a refusal against an identically-named proven-source row |
| — | `secondary_proof` was missing from §9's audit field list and from T15, though it is funded change 4's own field | yes — §4 declares it, §9 and T15 omitted it | applied to both (grok, round 4 carry-over) |
| — | The `ProvenPrincipal.id` comment said an unnameable certificate is "refused under `require_id` or a non-empty `known_agents`" | yes — contradicts `agent_identity.rs:158` and §8's settled row | applied: the comment now matches section 8 |
| — | `handlers.rs:612-618` cited the refusal arm one line long | yes — the arm is `:612-617`; `:618` is blank | applied at all four sites. The round-5 review proposed `:611-618`, which is wrong in the other direction: `:611` closes `code_mode_url_active` |

**On the peer-reported `agent_identity.rs:106-112`.** No such citation exists in this document —
sections 2, 6 and 11 all already read `:105-111`, which is correct: `:105` is the comment,
`:106` the `if let`, `:107-110` the returned literal, `:111` the closing brace, `:112` blank.
The off-by-one was in the peer's report, not here, and nothing was changed for it.

**The two rulings above are agent rulings, not operator rulings.** They were made so the work is
not blocked, and each is written to be overturned in a single line. F3 and F6 were both referred
up by the reviewer precisely because they trade off against operator intent rather than against
source, and the record should not read as though an operator settled them.

**What this round's discriminator caught.** Applying the standing rule — grep the document for
every other place a changed decision is described — F2 reached nine sites beyond the three the
review named, including §10's mis-aimed-hatch paragraph, which round 4's self-check had already
fixed once for the same underlying decision. That paragraph has now been wrong about mTLS in two
consecutive rounds for two different reasons, which makes it the first place round 6 should look.


### Round 6 — findings and disposition

Both reviewers returned **SHIP-WITH-FIXES** on the revised document. Every claim below was
re-verified against the source tree before it was accepted; two were rejected on the merits and
one declined as out of scope. The reviewers disagreed usefully — each found a defect the other
missed, and the one rated HIGH by grok was invisible to gpt because it lives in the gap between
two test rows rather than inside either one.

| # | Claim | Verified at source | Disposition |
|---|---|---|---|
| R6-1 | T20 and T14d specify opposite startup outcomes for the same encryption-only mTLS config (grok, HIGH, CERTAIN) | yes — T20's config satisfies T14d's trigger exactly: `mtls.enabled` with no waiver and no per-principal entry | **applied.** The two obligations were being read as one. Obligation 1 asks whether a proof source exists; the DECISION 7.2 census asks whether the labels tier is declared. T20 now carries a namespace waiver so it answers both, and T14d's trigger is the `mtls.enabled` flag — encryption-only included — instead of the undefined phrase "mTLS configured". Without this, an implementer taking T20 literally ships a gateway that starts and then 403s every certificate-plus-header caller: the starts-then-refuses failure this document spent five rounds closing, re-entered through the test plan |
| R6-2 | DECISION 7.1's three rules are not one ordered function; exact match, mapping membership and T14e reach opposite outcomes for the same request (both reviewers, independently) | yes — rule 1 called `declared.id == proven.id` consistent while rule 2 and T14b refused a label outside the mapped set, with no stated precedence | **applied, and it closes three findings at once.** DECISION 7.1 is now a single ordered match with four arms — exact match accepts and stops, else the mapping decides membership, else a waiver accepts and audits, else refuse. Arm 1 sits ahead of arm 2 deliberately: a principal declaring its own name is declaring the one label that cannot be a lie, so it is a member of its own set by construction. T14e is narrowed to a declared label that differs from the proven id, and T14f is new — it is red against any implementation that codes membership before exact match |
| R6-2b | The exact-match exception had not propagated to every site asserting the backstop (self-check after R6-2) | yes — T27 and section 7.2's backstop prose both still refused on "declared label present" with no differs condition | **applied.** T27 and both backstop paragraphs now carry it. Found by re-reading every site that restates the refuse case rather than by a reviewer, which is the check round 7 should run on section 5 |
| R6-3 | Section 6 rows 6 and 8 omit the unmapped-no-waiver case and describe acceptance where the backstop refuses (gpt) | yes — the rows' "otherwise" branch conflated "a waiver covers this subject" with "nothing covers this subject" | **applied.** Rows 6 and 8 no longer restate the comparison; they invoke DECISION 7.1's ordered match. A table that paraphrases a rule is a second copy of that rule, and this is the third round in which the paraphrase drifted from the original |
| R6-4 | The compatibility summary omits DECISION 7.3's grant and scope changes, which are not gated by `enabled` (gpt) | yes — DECISION 7.3 re-keys `GrantAgent::Exact` and closes the scope gate at `authorization.rs:206-214`, neither behind the feature flag | **applied.** Both are now listed as breaking regardless of the flag and the hatch, and T7's unchanged-behaviour claim is scoped explicitly to `validate_agent_identity` |
| R6-5 | The no-proof migration row's headline is wrong under both hatch settings (gpt) | yes — hatch off refuses every request under obligation 1; hatch on enforces a `(declared, id)` allowlist | **applied.** Split into two rows. The sentence following the matrix called "that last row" a dead gateway, which after the split named the wrong row — corrected in the same edit. **Corrected again in the round-6 verification pass**: both the finding and the split were wrong about the hatch-off outcome. Obligation 1 **fails startup** for that config — it does not refuse requests — and the split varied the mTLS column instead of the hatch, producing a rescued row that claimed no proof source while its own column said mTLS on. All three rows are now hatch-keyed with mTLS `off`, and the two hatch-off rows fail startup, matching T13 and T20b |
| R6-6 | T24 assumes recovery re-authorizes a saved caller snapshot (gpt) | yes — `handlers/tasks.rs:201-205`: "Every field is THIS request's live context. Nothing here is restored from the record." The reviewer's citation was exact | **applied.** T24 now runs twice, once where the recovering caller's proven pair matches the creating caller's and once where it differs. The differing case is the one with teeth: it fails if recovery ever judges the target against a stored identity |
| R6-7 | T19 cannot be red at `HEAD` (gpt) | yes — `src/identity_grants.rs:65-68`, `Exact(expected) => agent_id.is_some_and(...)`; a certificate-only caller has `agent_id = None`, so `HEAD` already refuses | **applied.** The baseline now sends `X-Agent-ID: runner` so `HEAD`'s bare-string match admits it and the source-qualified grant refuses it. A green baseline mistaken for a passing security property is worse than no test |
| R6-8 | The 4.0 `GrantAgent::Exact` write path is unspecified while the 3.x shape is a load error (grok, improvement) | yes — two constructors take bare strings: `src/commands/identity.rs:329` and `src/identity_grants.rs:824` | **applied.** DECISION 9.1 gains the serialized shape, the CLI qualifier and both migration sites, plus T33. A load-reject with no way to write the accepted shape leaves hand-editing the store as the only route to a 4.0 grant |
| R6-9 | A `principal_labels` entry keyed `source: declared` should be a load error (grok, improvement) | n/a — a gap, not a contradiction | **applied.** DECISION 7.2a states it and T31 pins it. The surface compares proof against a label, so a declared-to-declared mapping compares a label with itself |
| R6-10 | Tier 1 refusals need positive counterparts, including unnameable certificate plus verified JWT (grok, improvement) | n/a | **applied in part.** T32 adds the one row with a named falsifier behind it — it fails if an implementation reaches for `CertIdentity::display_name` and makes a cosmetic string an allowlist key. The general rule of a counterpart per refusal is declined as test-plan inflation; a suite is not improved by symmetry for its own sake |
| R6-11 | The anonymous early return is at `agent_identity.rs:158`, not `:159` (gpt, improvement) | yes — `:158` is `return Ok(());` and `:159` closes the `let`-`else` | **applied** at all six citations |
| R6-12 | The type snippets are not self-consistent (gpt, improvement) | yes — `Ord` does not compile without `Eq` and `PartialEq`, and the empty initializer omitted `secondary_proof` | **applied** |
| R6-13 | The escape hatch should carry a header-over-proof migration path (gpt, HIGH) | doc read; the ruling's change 2 is "mTLS > verified JWT claim > declared label" | **rejected on the merits.** Restoring header-over-proof reverses the ruling this design implements, so it is a scope change, not a fix. The half of the finding that was right is applied: the paragraph now names the one supported route for an operator who genuinely needs it — the existing `trust_caller_identity_headers` front-proxy gate at `handlers.rs:61-64`, which is operator delegation to an authenticating proxy rather than caller self-declaration |
| R6-14 | Replace superseded policy explanations with references and keep review history separately (gpt, improvement, MEDIUM cost) | n/a | **declined.** This section is the review history by design, and restructuring it is not this revision's scope. Worth raising again if the document outlives the release |

**What round 6 says about the document's failure mode.** Round 5 predicted the mis-aimed-hatch
paragraph would be where round 6 found its next defect. It was not — that paragraph held. The
defects came from the same underlying cause one layer down: a rule stated once and then
paraphrased somewhere else, with the paraphrase drifting. R6-2 and R6-3 are both that, and R6-1
is the test-plan version of it, two rows each correct about one obligation and silently
contradicting on the other. The structural answer taken here is to stop paraphrasing — section 6
now invokes DECISION 7.1 rather than restating it. A round 7 should check the remaining
restatements on the same suspicion, starting with section 5's call-site inventory, which is the
last place in this document where a rule is described twice in different words.
