# Authorship and Chain of Title

**Work:** mcp-gateway (this repository)
**Author:** Mikko Parkkola, Finland
**Date of declaration:** 2026-07-12
**Last amended:** 2026-10-06 (outside contributions recorded)

## Declaration

Mikko Parkkola is the principal human author of mcp-gateway and the author of
its protectable expression as described below. Outside contributions accepted
into the work are listed under [Contributors](#contributors), together with
whether that contributor's [`CLA.md`](CLA.md) acceptance is on record. Under
that agreement a contributor grants the licences this project's licensing
scheme requires while retaining copyright in their own contribution.

The work is an original work of authorship. Its protectable expression — the
architecture, module structure, control and data flow, interface design, naming,
factoring, and the selection, arrangement, and integration of its ~400 source
files into a working system — is the product of the author's own intellectual
creation, reflecting free and creative choices at every level of the design.

## Use of AI coding tools

AI coding assistants (including Claude Code and GitHub Copilot) were used
**assistively** during development, in the way a compiler, linter, or
autocomplete is a tool rather than an author. For all code in this repository,
the author:

- directed the work and specified the intent;
- reviewed, selected among, accepted, rejected, and edited suggested code;
- tested, debugged, and integrated the result into the larger system;
- made the architectural and structural decisions that give the work its
  expressive form.

No AI system is or is claimed to be an author of any part of this work. No
portion of this repository is asserted to be the autonomous output of an AI
system with human creative input disclaimed.

This posture is consistent with the governing framework:

- **EU / Finland** — Software Directive 2009/24/EC Art. 1(3) protects a computer
  program that is "the author's own intellectual creation." Finland's
  Tekijänoikeuslaki (404/1961) protects computer programs as literary works and
  recognizes only a natural person as author. The author's free and creative
  choices in producing and integrating the work satisfy this standard.
- **United States** — the U.S. Copyright Office's *Copyright and Artificial
  Intelligence, Part 2: Copyrightability* (2025) confirms that using AI tools to
  assist rather than stand in for human creativity does not affect the
  availability of copyright, and that a larger human-authored work containing
  AI-assisted material is copyrightable. *Thaler v. Perlmutter* (D.C. Cir. 2025)
  bars copyright only for works authored *solely* by AI with human input
  disclaimed — not this work.

## Contributors

Outside contributions accepted into the work, in the order they were merged.
[`CLA.md`](CLA.md) binds on submission — contributing is acceptance, and no
signature is required — so a contribution made while the CLA was in the
repository is covered by it. A contributor may also record the acceptance
explicitly in their pull request. Where a contribution predates
[`CLA.md`](CLA.md) (added 2026-07-11) the CLA does not reach it, and this table
says so rather than implying an acceptance that was never given.

| Contributor | Contribution | Pull request | CLA on record |
|---|---|---|---|
| Bryan Zick, submitted by [v4de](https://github.com/v4de) | `structuredContent` in responses from tools that declare an `outputSchema`, as the MCP 2025-06-18 spec requires | [#159](https://github.com/MikkoParkkola/mcp-gateway/pull/159) | **not applicable** — merged 2026-04-27, before `CLA.md` existed |
| [v4de](https://github.com/v4de) | Rust 1.95 clippy, rustfmt and compilation fixes across ~15 sites | [#160](https://github.com/MikkoParkkola/mcp-gateway/pull/160) | **not applicable** — merged 2026-04-28, before `CLA.md` existed |
| [terafin](https://github.com/terafin) | Parallel, timeout-bounded backend fan-out for `prompts/list` and `resources/list`; cancellation-safe cleanup of in-flight transport requests | [#465](https://github.com/MikkoParkkola/mcp-gateway/pull/465) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [yfcyfc123234](https://github.com/yfcyfc123234) | `APPDATA` and `LOCALAPPDATA` passed through to stdio child processes on Windows | [#522](https://github.com/MikkoParkkola/mcp-gateway/pull/522) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [yfcyfc123234](https://github.com/yfcyfc123234) | One host-platform parser for configured stdio commands, following `CommandLineToArgvW` rules on Windows; `doctor` fails invalid quoting instead of reporting a false pass | [#564](https://github.com/MikkoParkkola/mcp-gateway/pull/564) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | A per-backend package-manager cache for stdio backends, so concurrent `npx` installs no longer tear a shared cache | [#622](https://github.com/MikkoParkkola/mcp-gateway/pull/622) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | The `-full` container image variant with the Node.js, `uv` and `git` runtimes stdio backends shell out to | [#644](https://github.com/MikkoParkkola/mcp-gateway/pull/644) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | `EXTRA_APT_PACKAGES` and `/docker-entrypoint.d` drop-ins on the `-full` image variant, with privileges dropped to the gateway user | [#729](https://github.com/MikkoParkkola/mcp-gateway/pull/729) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | Restored the smoke-gate port lock the `-full` variant work had dropped | [#695](https://github.com/MikkoParkkola/mcp-gateway/pull/695) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | A timeout ceiling on every probe in the `-full` variant smoke gate | [#744](https://github.com/MikkoParkkola/mcp-gateway/pull/744) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | Tool search matches the name of the backend that serves a tool | [#2317](https://github.com/MikkoParkkola/mcp-gateway/pull/2317) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| Shawn Blackmore ([blackmore-technology-group](https://github.com/blackmore-technology-group)) | Keyed legacy `gateway_set_state` retries bound to the calling session, so one session cannot replay another session's retained result | [#2670](https://github.com/MikkoParkkola/mcp-gateway/pull/2670) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at merge; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | A stdio backend whose npm cache cannot install clears its gateway-assigned cache and retries once; non-secret npm settings forwarded to stdio backends. Carried onto the release line in [#3242](https://github.com/MikkoParkkola/mcp-gateway/pull/3242) and the npm-settings follow-up | [#1759](https://github.com/MikkoParkkola/mcp-gateway/pull/1759) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at submission; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | Tool search fills a backend's tool list when nothing filled it yet, so a backend left out of warm start becomes searchable instead of staying invisible. Carried onto the release line in [#3042](https://github.com/MikkoParkkola/mcp-gateway/pull/3042) | [#3036](https://github.com/MikkoParkkola/mcp-gateway/pull/3036) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at submission; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | Regression tests that a stdio backend's process group is ended when its leader ignores SIGTERM and when its close is cancelled. Carried in [#3780](https://github.com/MikkoParkkola/mcp-gateway/pull/3780) | [#3419](https://github.com/MikkoParkkola/mcp-gateway/pull/3419) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at submission; no explicit statement was requested or given |
| [terafin](https://github.com/terafin) | The response cache answers only for tools declared read-only, so a repeated write is never answered from the cache. Ported with his tests in [#3851](https://github.com/MikkoParkkola/mcp-gateway/pull/3851) | [#3773](https://github.com/MikkoParkkola/mcp-gateway/pull/3773) | **accepted on submission** — [`CLA.md`](CLA.md) was in the repository at submission; no explicit statement was requested or given |
| [robn](https://github.com/robn) | Reported that `serve --stdio` wrote logs into the JSON-RPC stream and that `tool list` failed without a capability directory; fixed in a12c5b22d, first shipped in v2.12.2 | [#224](https://github.com/MikkoParkkola/mcp-gateway/issues/224), [#225](https://github.com/MikkoParkkola/mcp-gateway/issues/225) | **not applicable** — a report; no code was contributed |
| [robn](https://github.com/robn) | Reported that a remote backend stayed unusable after a 404 ended its session; fixed in 32a1046f8 and pinned in 4da895ed3, first shipped in v3.0.0 | [#247](https://github.com/MikkoParkkola/mcp-gateway/issues/247) | **not applicable** — a report; no code was contributed |
| [crepererum](https://github.com/crepererum) | Reported the wrong OAuth discovery path; the RFC 8414 path-aware metadata URL fix 39361f5c8 first shipped in v3.3.0 | [#346](https://github.com/MikkoParkkola/mcp-gateway/issues/346) | **not applicable** — a report; no code was contributed |
| [akaralar](https://github.com/akaralar) | Requested a configurable OAuth client host, port and secret; `callback_host` first shipped in v2.10.1 (41f67f6c8) | [#140](https://github.com/MikkoParkkola/mcp-gateway/issues/140) | **not applicable** — a report; no code was contributed |

## Third-party material

- **Dependencies** — third-party crates are licensed under their own permissive
  terms (predominantly MIT / Apache-2.0). They are not first-party material, are
  not relicensed under this project's Noncommercial default, and retain their
  own notices. See [`docs/legal/dependency-licenses.md`](docs/legal/dependency-licenses.md).
- **Copied snippets** — a provenance audit found no third-party source code
  copied into first-party files. See
  [`docs/legal/snippet-provenance.md`](docs/legal/snippet-provenance.md).

## Standing of this document

This declaration records the author's factual position on authorship and chain
of title. It is not legal advice. The overall licensing scheme remains subject
to sign-off by a qualified Finnish/EU IP attorney before any release tag.
