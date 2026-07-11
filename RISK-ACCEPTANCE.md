# Risk Acceptance — shipping the Noncommercial flip without specialist sign-off

**Work:** mcp-gateway
**Decision date:** 2026-07-12
**Decision owner:** Mikko Parkkola (licensor)
**Status:** ACCEPTED

## Context

The v3.3.0 relicensing (PolyForm-Noncommercial-1.0.0 default + MIT core + a
separate commercial-license offer) was engineered, hardened over four counsel
rounds, and audited for chain of title (see
[`docs/CHAIN-OF-TITLE-ANALYSIS.md`](docs/CHAIN-OF-TITLE-ANALYSIS.md) and
[`docs/COUNSEL-OPINIONS-v3.3.0.md`](docs/COUNSEL-OPINIONS-v3.3.0.md)). The one
gate left open was sign-off by a bar-admitted Finnish/EU IP attorney on the
per-file marking scheme, the CLA, and the NOTICE/withdrawal wording.

A Finnish IP specialist is not available. The licensor has decided to proceed
with a bounded, informed risk rather than block indefinitely.

## What was decided

Ship in two tiers, taking only the reversible, backstopped risk now:

- **Tier 1 — TAKEN NOW.** Tag and publish the Noncommercial-default flip on new
  versions. Reversible in substance (a version supersedes; nothing binds a
  counterparty), and backstopped: every NC file carries an affirmative SPDX
  header, so even a contested per-file scheme falls back to the repo-level
  `LICENSE`, not to ambiguity.
- **Tier 2 — DEFERRED.** No commercial license will be signed until a real buyer
  exists. At that point a single deal justifies a one-off fixed-fee consult with
  a competent IP lawyer on that specific contract — no retained specialist
  required. `COMMERCIAL.md` requires prospective licensees to make contact; it
  does not auto-grant, so no commercial license can form by publication alone.

## What was relied on

- Dual AI-counsel review (GPT-5.5, Grok) — both **SHIP-ABLE**; not legal advice.
- Verified precedent: *Thaler v. Perlmutter* (D.C. Cir. 2025), USCO "Copyright
  and AI" Part 2 (2025), EU Software Directive 2009/24/EC Art 1(3), CJEU
  Infopaq/Painer/SAS/BSA, Finland Tekijänoikeuslaki 404/1961.
- Clean snippet-provenance audit; permissive-only dependency SBOM.
- The eight convergent MUST-FIX items from counsel Rounds 1–4, implemented and
  green in CI.

## Residual risk accepted

- The per-file marking scheme has not had a human lawyer's sign-off; a contested
  file relies on the repo-level `LICENSE` fallback. Probability of a marking
  challenge reaching enforcement litigation for a solo project is low; the
  fallback resolves most such cases.
- The already-distributed 3.0.0–3.2.1 MIT artifacts remain usable forever
  (a granted license cannot be revoked). This is a sunk fact, not a new risk.
- The CLA is untested (no external contributors yet); exposure is zero until the
  first contribution and is revisited then.

## Revisit triggers

Get human legal review before: (a) signing any commercial license; (b) accepting
the first external contribution; (c) any enforcement action; (d) withdrawing or
deleting already-distributed artifacts.

This document records a conscious, evidence-based business decision. It is not
legal advice and does not substitute for it.
