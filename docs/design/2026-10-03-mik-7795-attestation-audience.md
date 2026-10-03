<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# MIK-7795 (audience half): audience-bound attestation tokens

Status: design, for review before code. Scope: the audience acceptance
criteria only. The delegation chain is MIK-7813 (v4.1.0).

## Problem

`TokenClaims` carry no destination, and `AttestationValidator` checks
signature, issuer, expiry, rotation and capability, never where the token was
meant to go. Two gateways that share a signing key accept each other's tokens
(cross-destination replay). The defect is latent today (no issuer outside this
repository mints these tokens, and `enforce` is opt-in), which is why the
claims format is cheapest to change now, in a major release.

## Decisions

1. **A required `audience: String` claim.** No serde default: a token without
   it fails to parse and is refused as `MalformedToken`. There are no issued
   tokens to migrate. Recorded in `docs/UPGRADING-4.0.md`.
2. **The audience belongs to the signer, not the request.**
   `BnautAttestationSigner::with_audience(..)`; `issue` and `rotate` stamp it.
   A per-request field would need every mint site to remember it, and the site
   that forgets mints a token any gateway accepts. The validator already owns a
   signer, so it checks against the same value: one source for both sides.
3. **The check.** After signature and issuer, before expiry: the token's
   `audience` must equal the validator's. Mismatch is the new rejection
   `AudienceMismatch { expected, presented }`. An empty audience on either side
   never matches, so a validator with no audience refuses every token instead
   of accepting all.
4. **Wiring.** `GATEWAY_ATTESTATION_AUDIENCE` (trimmed; blank is unset).
   `enforce` without it fails startup, as it does without a key. `observe`
   without it starts, warns, and audits every token as an audience mismatch,
   which mirrors the existing blank-key posture. Mode `off` is unchanged.
   Operators pick one stable audience per destination: replicas of one
   destination share it, two destinations never do (two gateways that choose
   the same string still accept each other's tokens). A rotation successor is
   minted only from a predecessor that validated, so a foreign token cannot be
   relabelled as local by rotation; a test pins it.
5. **Propagated assertions (second criterion).** The receiving side of a
   `SignedAssertion` is the backend, which verifies against the gateway JWKS.
   Add a test that a standard verifier configured for another audience rejects
   a minted assertion and one configured for the right audience accepts it, so
   the `aud` binding is pinned by a verifying test and not only decoded.
6. **Docs.** `MULTI_USER.md` states the single-principal model and the
   passthrough exception (credentials forwarded unexamined).

## Rejected

- **Audience on `TokenRequest`:** see decision 2.
- **A default audience** (for example the product name): every gateway would
  share it, which is the bug.
- **A per-audience derived key** (HKDF with the audience as `info`): sound, but
  the signature already covers the claim; it adds key-handling churn for no
  extra property here.
- **Accept a missing audience in observe mode:** an unbound token must not
  look valid anywhere.

## Red rows (written first)

- Wrong audience is refused, the right one accepted (validator).
- Empty audience refused on the token side and on the validator side.
- A token with no `audience` claim is `MalformedToken`.
- `issue` stamps the signer's audience; `rotate` carries the predecessor's, so
  a rotated token keeps its destination.
- `enforce` without an audience fails startup; `observe` without one starts and
  rejects; the env value is trimmed.
- A gateway with another audience and the same key refuses the first one's
  token at the boundary (the replay in the title).
- Both audiences empty: refused.
- The replay is refused at the meta-route boundary and the direct route, not
  only in the validator unit test.
- Rotation of a foreign-audience predecessor is refused.
- The propagated-assertion audience test of decision 5.

## Mutants (each must be RED)

Drop the stamp; invert the comparison; remove the empty guard; skip the
`enforce` audience requirement; do not carry the audience through `rotate`.

## Risk and rollback

Public types change (`TokenClaims` gains a field, `BnautAttestationSigner`
gains a builder and getter). Existing constructors keep their signatures; test
fixtures add `.with_audience(..)`. Revert the commit; no data migration, since
no token outlives its expiry.
