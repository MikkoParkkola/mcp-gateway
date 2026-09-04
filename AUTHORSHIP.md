# Authorship and Chain of Title

**Work:** mcp-gateway (this repository)
**Author:** Mikko Parkkola, Finland
**Date of declaration:** 2026-07-12
**Last amended:** 2026-09-04 (outside contributions recorded)

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

Outside contributions accepted into the work, in the order they were merged. A
contributor's acceptance of [`CLA.md`](CLA.md) is recorded in the pull request
that introduced their first contribution; where that record is outstanding, or
where the contribution predates [`CLA.md`](CLA.md) (added 2026-07-11), this
table says so rather than implying an acceptance that was never given.

| Contributor | Contribution | Pull request | CLA on record |
|---|---|---|---|
| Bryan Zick, submitted by [v4de](https://github.com/v4de) | `structuredContent` in responses from tools that declare an `outputSchema`, as the MCP 2025-06-18 spec requires | [#159](https://github.com/MikkoParkkola/mcp-gateway/pull/159) | **not applicable** — merged 2026-04-27, before `CLA.md` existed |
| [v4de](https://github.com/v4de) | Rust 1.95 clippy, rustfmt and compilation fixes across ~15 sites | [#160](https://github.com/MikkoParkkola/mcp-gateway/pull/160) | **not applicable** — merged 2026-04-28, before `CLA.md` existed |
| [terafin](https://github.com/terafin) | Parallel, timeout-bounded backend fan-out for `prompts/list` and `resources/list`; cancellation-safe cleanup of in-flight transport requests | [#465](https://github.com/MikkoParkkola/mcp-gateway/pull/465) | **outstanding** — requested 2026-09-04, after the merge |

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
