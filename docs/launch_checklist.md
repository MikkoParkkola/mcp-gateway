# Launch Checklist — Sovereign Coding-Agent Stack

**Status**: DRAFT. Not ready to publish. Use this file to track what ships now vs. what's deferred.
**Owner**: Mikko Parkkola
**Target post**: `docs/show-hn.md` + `docs/blog/sovereign-stack-2026-04.md`
**Today**: 2026-04-12

---

## 0. Hard blockers — MUST be green before posting

- [ ] **OPSEC review**: `git filter-repo` audit on every public repo for accidental secrets, API keys, private paths, hostnames.
  - [ ] mcp-gateway: `git log -p | rg -i 'api_key|secret|token|password'` — clean
  - [ ] botnaut-client: same
  - [ ] metacognition (if any part goes public): same
  - [ ] hebb (patent-history scrub still pending — see MEMORY.md) — **may defer if hebb not referenced as public link in post**
- [ ] **Trademark check**: "botnaut" not infringing, "Goose" fork language complies with upstream AGPL/ASL terms.
  - [ ] Confirm Block's Goose license is what we think it is. Botnaut-client README must credit upstream correctly.
  - [ ] `botnaut` string on USPTO TESS search — no collision in SW class
- [ ] **Patent strategy**: decide filing order.
  - [ ] I-019 (HIGGS asymmetric) — provisional? full? wait until runtime integrated?
  - [ ] I-020 (formal-verified constitutional compliance) — provisional recommended before public post
  - [ ] I-021 (MetaThinker fine-tuned meta-thinker) — provisional recommended before public post
  - [ ] Disclosure question: does a draft blog post count as public disclosure under 35 USC §102? **Ask patent counsel.** Blog post mentions each claim explicitly.
- [ ] **License audit** on each repo:
  - [ ] mcp-gateway: MIT confirmed in `LICENSE`
  - [ ] botnaut-client: PolyForm-Noncommercial 1.0.0 confirmed in `LICENSE`; upstream Goose attribution present
  - [ ] botnaut: proprietary, formal/ directory readable (Z3 + TLA+ spec only) without exposing core IP
  - [ ] metacognition: clarify what is public (techniques/mod.rs + design doc) vs private (engine, RL reward)

## 1. Must-do before publishing

- [ ] **Show HN draft reviewed** by at least one outside reader who can push back on overclaim.
- [ ] **Blog post reviewed** for same.
- [ ] **Smoke test each repo**, fresh clone on a clean machine:
  - [ ] `mcp-gateway`: `brew tap MikkoParkkola/tap && brew install mcp-gateway && mcp-gateway --help` — binary runs
  - [ ] `mcp-gateway`: run wizard, import Petstore spec, point Claude Code at `http://localhost:39400/mcp`, invoke one tool — green path
  - [ ] `botnaut-client`: `cargo install --path .`; `botnaut chat` launches; hebb + metacognition extensions spawn; constitutional hook blocks a test `rm -rf ~` payload
  - [ ] `botnaut/formal/`: `python formal/enforcement_proof.py` on a fresh venv — all 5 proved, exit 0
- [ ] **Reproducibility block** — for each headline number, a commit-hash + command readers can rerun:
  - [ ] 2765 tests: `cd mcp-gateway && cargo test --quiet 2>&1 | tail -5`
  - [ ] 1155+ tests: `cd botnaut-client && cargo test --quiet 2>&1 | tail -5`
  - [ ] 91% token savings: `cd mcp-gateway && python benchmarks/token_savings.py`
  - [ ] 8 ms startup: `hyperfine 'mcp-gateway --config gateway.yaml --dry-run'`
  - [ ] Z3 proofs: `python botnaut/formal/enforcement_proof.py`
- [ ] **Screenshot or ASCII capture** of:
  - [ ] mcp-gateway AX-010 rejecting a tool-poisoning payload
  - [ ] Constitutional gate denying a tool call (from `~/.botnaut/audit/constitutional_audit.jsonl`)
  - [ ] Z3 PROVED lines (terminal)
- [ ] **Contact info**: email (`mikko.parkkola@iki.fi`), HN username, repos all link to each other.

## 2. Strongly recommended (not hard blockers)

- [ ] **Short demo video (60–90 s)**:
  - [ ] Terminal recording of the constitutional hook blocking a `rm -rf ~/.ssh` payload, with the audit line appearing.
  - [ ] Hosted on asciinema or raw .gif in `docs/`. Embedded in blog post.
  - [ ] **If this can't ship in 24 h, defer and flag in the post.**
- [ ] **Release tag** on botnaut-client (`v0.1.0` or similar) so readers have a stable reference point.
- [ ] **Blog post link in mcp-gateway README** ("See also: sovereign-stack-2026-04.md").
- [ ] **One GitHub issue per deferred item** so readers see the tracker, not just the blog gaps.
- [ ] **Pre-submit to /r/LocalLLaMA or /r/rust**? Lower-stakes crowd for early bug reports before HN.

## 3. Acceptable to ship now (documented as in-progress)

Each of these is acknowledged in the blog post; it's fine to publish with them in flight:

- [x] MetaThinker checkpoint not trained — blog says "scaffolded, frozen schema, not trained"
- [x] HIGGS Phase 2 not integrated into hot path — blog says "compiles, not yet swapped in"
- [x] Mojo gradient firewall Phase 1 skeleton only — blog says "Phase 1 skeleton, 11 tests"
- [x] Upstream MCP hash-pinning needs spec extension — blog says "on the roadmap, needs MCP spec"
- [x] Runtime MCP output sanitization pattern-based — blog says "pattern-based, structured contracts are the real fix"

## 4. Defer (do NOT block launch)

- hebb public scrub (MEMORY.md flags this; not referenced publicly in Show HN)
- botnaut-engine public split (partial split exists, not ready for public link)
- Full Mojo gradient firewall
- PQC audit across all 7 repos (strategic, not launch-blocking)
- Constitution formal-verification of claim 3 (orthogonality proof, Z3 port pending)
- Trained MetaThinker model weights
- A2A (agent-to-agent) support in mcp-gateway
- Per-tool JSON schema enforcement for MCP responses

## 5. Risk checklist

| Risk | Severity | Mitigation |
|---|---|---|
| Patent disclosure via public post before provisional | **HIGH** | File provisional for I-019/I-020/I-021 before post, OR redact specific claim language in post |
| Upstream Goose license noncompliance in botnaut-client | MED | Verify AGPL/ASL compliance, proper attribution in README |
| AX-010 bypass published by a commenter within 24 h | MED | Accept it gracefully; it's a test of the system. Have a PR-ready response template. |
| Z3 proof found to have a gap | MED | Same; the proof being attacked is the point. Offer the beer. |
| HN tanks the post for overclaiming | HIGH | Tone: say what's shipped, say what's scaffolding, name the gaps in §7 of the blog. Do NOT call anything "production-ready" unless verifiable. |
| Reader tries to compile and can't | HIGH | §1 smoke test on a fresh box. `cargo build` must succeed from a clean clone. |
| Trademark collision on "botnaut" | LOW | USPTO search before launch |
| Someone fine-tunes a MetaThinker before I do | LOW | Publish design + 9 draft claims as defensive publication if filing slips |

## 6. Post-publish actions (first 48 h)

- [ ] Monitor HN comments every 30 min for first 4 h
- [ ] Respond to every technical question within 2 h during that window
- [ ] Track: stars/forks/issues/PRs per repo
- [ ] If AX-010 bypass posted: merge, credit, deploy, thank publicly
- [ ] If Z3 gap posted: reproduce locally, credit, fix, thank publicly, update proof output in blog
- [ ] Write a retro (lessons learned) within 7 days, store in `docs/retro/2026-04-show-hn-retro.md`

## 7. Kill criteria

Publish is NO-GO if any of:

- Patent counsel says posting blows novelty and no provisional filed
- A repo doesn't build from a clean clone
- AX-010 is found to silently let through the literal Invariant payload
- Z3 proof exits non-zero on a clean run
- TLA+ spec model-check fails on the bounded config

If any of these trip, defer launch by at least 7 days.
