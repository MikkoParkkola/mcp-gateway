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
2. That defence does not hold for this claim. `agent_id` occurs **zero times** in `src/gateway/oauth/jwt.rs`. The verified claim set `AgentClaims` (`jwt.rs:50-67`) is `sub`, `iss`, `aud`, `exp`, `iat`, `scope`. `validate_agent_token` verifies the signature and those claims; `agent_id` is not among them, so no middleware has ever verified it.
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
    /// Caller-supplied tag. Telemetry and attribution only; carries no
    /// privilege and can never satisfy an authorization control.
    pub declared: Option<DeclaredLabel>,
}

pub struct ProvenPrincipal {
    /// The principal's identifier: the mTLS subject, or the verified JWT `sub`.
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
| 1 | no | no | no | none | Accept if `require_id = false`. **Refuse** if `require_id = true` (no ID at all). Unchanged from today. |
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

A declared label **contradicts** the proven principal when the two are comparable and differ. "Comparable" is established by configuration, never guessed:

1. **Exact match.** `declared.id == proven.id` — consistent. The common case under DECISION 3.1, where the proven id is a `client_id`.
2. **Operator mapping.** `agent_identity.principal_labels` maps a proven id to the set of labels it may declare. A declared label outside that set is a **contradiction** — refuse.
3. **Explicit waiver.** A principal mapped to the waiver value (`unmapped_ok`) declares that its labels are in a namespace the gateway cannot compare. Any label is accepted and the pair is audited.

**There is no fourth case.** When `agent_identity.enabled` is set, a proven source is configured, and declared labels are accepted, `principal_labels` must cover every configured principal — by an explicit label set or by an explicit waiver. This is enforced at **startup**, alongside the validation section 10 already requires, so an unmapped principal is impossible by construction rather than resolved at request time.

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
| `known_agents` non-empty, proven present | accept if `identity.id` listed | accept if `proven.id` listed; the label is not consulted |

Two rows flip from accept to refuse. They are the vulnerability.

The module documentation has to change with them. `src/security/agent_identity.rs:24` currently describes `known_agents` as an "optional allowlist of accepted agent IDs", and `:27-28` states the allowlist applies only "when `known_agents` is non-empty and `require_id` is true" — which the C5 review already found wrong at source, since `:161` runs whenever an identity resolves. Both must be rewritten to say the allowlist is a **proven-principal** allowlist. The C5 review recorded the reason plainly and it still holds: `known_agents` is a declared-label policy, not a cryptographic allowlist, and the name implies otherwise. This change makes the name true rather than continuing to document around it.

## 9. The declared label as telemetry

Change 4: "Multi-agent tracing and cost attribution need a caller-supplied tag; the feature is not wrong, its privilege is. Audit records BOTH."

Sites 12 and 13 in the inventory (`handlers.rs:1448`, `:1900`) currently flatten the identity to one `Option<&str>`. Under the split they must choose, and the choice differs by purpose:

- **Audit** records both, always, as distinct fields: `agent_proven`, `agent_proof` (the `ProofSource`), `agent_declared`, `agent_declared_source`. A record that collapses them cannot distinguish "agent-a proved it" from "someone said agent-a", which is the property the whole change exists to create.
- **Authorization** reads `proven` only. Already covered by section 6; named again here so no later reader takes "audit records both" as licence to authorize on the declared value.
- **Attribution and tracing** (`tasks::RecoveryCaller.agent_id`, `tasks.rs:112`, `:211`) keep using the declared label when present, falling back to the proven id. This is deliberate: cost attribution wants the caller's own tag, and a caller that lies about its tag mis-attributes its own costs and no one else's. This is the one place the declared label stays primary, and it is safe because nothing downstream of `tasks.rs` makes an access decision on it.
- **Mismatch signal**: when a proven principal and a declared label are both present and differ under a DECISION 7.1 rule 3 waiver, audit emits `declared_label_mismatch` with both values. Under rules 1 and 2 the same situation is a refusal, which is already its own audit record. The waiver case is where the ruling's detection signal lives, because it is the only accept-with-mismatch path that remains.

That last bullet is the ruling's "turning the vulnerability into detection", and it is the part that is cheapest to drop under implementation pressure. It is load-bearing for the ruling and is listed as a distinct test row in section 11.

## 10. Backward compatibility and the config matrix

This change alters who gets refused. That is a decision recorded here, not a side effect.

### DECISION 10.1 — the breaking change is taken, default-on, at 4.0.0

Row 2 of the precedence table is the break. A deployment today that sets `X-Agent-ID` and nothing else, with `agent_identity.enabled = true` and either `require_id = true` or a non-empty `known_agents`, **passes**. After this change it **refuses**. Those deployments do not keep working on the new default, and that is the intent: they are precisely the deployments that believe they have an access control and do not.

Permitted because 4.0.0 is a major release. Recorded because the ruling requires it to be a decision.

The escape hatch is the one the ruling names: `security.agent_identity.allow_unverified_agent_identity`, default `false`. When `true`, a declared-only label may satisfy `require_id` and `known_agents` exactly as today, and the gateway **warns at startup** naming the control that is weakened. Legacy behaviour stays reachable; it stops being the default.

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

1. **Startup validation must refuse this combination**, not discover it per request. `agent_identity.enabled` with `require_id` or a non-empty `known_agents`, and neither agent auth nor mTLS configured, is a configuration error — fail at startup naming both the missing proof sources and `allow_unverified_agent_identity`. A gateway that starts and then refuses everything is the worst available outcome.
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

1. **Design review** — this document. DECISION 3.1, DECISION 7.1 and DECISION 10.1 need explicit sign-off. DECISION 7.1 is the one that adds a mandatory operator config step, and DECISION 10.1 is the one that breaks existing deployments; both are reasonable places for a reviewer to rule differently.
2. **Test review** — section 11 reviewed as a plan, including the red-before-green ordering.
3. **Failing tests** — Tier 1 written and demonstrated red against `HEAD`.
4. **Implementation** — sixteen production sites from section 5. The repo gate fires here: `gitnexus_impact` on `extract_agent_identity` and `validate_agent_identity` before editing either, and `gitnexus_detect_changes` before committing.
5. **Final review** — including a re-run of the OWASP Agentic AI checklist at `docs/OWASP_AGENTIC_AI_COMPLIANCE.md`, since ASI03 is the control this module claims.
6. **Docs and housekeeping** — module docs at `:10-15` and `:24-28`, the upgrade notes from section 10, and `funded_work[0]` moved off `stage: design`.

## 13. Falsifier

The cheapest check that this design is wrong, with a pass/fail threshold, runnable before implementation:

**Claim under test:** the proven principal is available at both call sites, so the precedence table is implementable without new plumbing.

**Check:** at `handlers.rs:603` and `backend_handlers.rs:517`, assert in a route-level test that `CertIdentity` and `OAuthAgentIdentity` are present in request extensions for a caller that presented each, on both routes.

**Threshold:** all four combinations present. **Fail:** any absent on either route means the middleware ordering analysis in section 3 is wrong, the design needs a plumbing stage it does not currently have, and section 6 rows 3 through 8 are unimplementable as written.

**Current expectation, from source rather than execution:** passes. `/mcp/{name}` is registered at `router/mod.rs:256` into `routes`, and the agent-auth layer is applied to `routes` at `:279-284`, so it covers both routes; the wrapping-order comment at `:286-291` places agent auth after authentication and before the handler. `cert_identity` and `oauth_agent_identity` are already bound at `handlers.rs:583-587` and `backend_handlers.rs:489-490`. The routes merged after the layer at `:309-331` are jwks, metrics, key-server and UI — none of them dispatch routes.

This was verified by reading, not by running. Running it is the first task of the implementation stage.
