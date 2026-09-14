<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Capability pin policy

Which shipped capability YAMLs carry a `sha256:` pin, which deliberately do
not, and why. Enforced by `tests/capability_pin_policy.rs`, which runs in the
`Tests` job of `.github/workflows/ci.yml` (`cargo test --all-features`).

Release criterion: `MIK-7235.PIN.1`.

## What a pin buys

A pin is the rug-pull guard described in `src/capability/hash.rs`: the loader
recomputes the SHA-256 of the file (with its own `sha256:` line stripped) and
`src/capability/parser.rs` rejects the file if the embedded pin disagrees. A
capability YAML rewritten after approval — by a compromised sync tool, a
dependency update, a poisoned PR — stops loading instead of executing.

Pinning costs one line per file and one re-pin per edit. The policy spends
that cost where a rewritten file can do real damage, and declines it where a
rewritten file can only return wrong data.

## Axis 1 — privilege

A capability is **high-privilege** if any of the following holds. Each
disjunct names something the capability can *reach*; none of them is a
judgement about file size, age or popularity.

| # | Test | What it reaches |
|---|------|-----------------|
| P1 | `auth.required: true` | A credential. The YAML names the env var, OAuth scope or header the gateway will attach; rewriting it redirects a live secret to an attacker-chosen host. Covers every money path in the catalogue — Stripe, banking and billing capabilities all require auth. |
| P2 | `metadata.read_only` is not exactly `true` | A declared outbound write. The capability's own metadata says it mutates external state. |
| P3 | any provider's `config.method` is present and not `GET` | An outbound write by verb, independent of the label. `read_only` is a self-declared field; the HTTP verb is what the executor actually sends. |
| P4 | any provider is `service: mcp` / `service: cli`, or its `config` carries a `command` | Local code execution. These providers spawn a process on the operator's machine; a rewritten `command:` is arbitrary code, the highest privilege in the catalogue. |

**Fail closed.** A file that does not parse, or that is missing `metadata` or
`auth`, classifies high-privilege. Absence of evidence is not evidence of
low privilege.

Everything else is **low-privilege**: an unauthenticated `GET` against a
public read-only endpoint. Poisoning one yields wrong data — bad, but there is
no secret to exfiltrate, no write to redirect and no process to spawn.

## Axis 2 — stability

**Production catalogue** — everything under `capabilities/` except
`capabilities/examples/`. This is the shipped inventory, and it is the same
boundary the repository already uses: `capabilities/README.md` counts the
catalogue "excluding `examples/`", as does the frozen ranking baseline in
`benchmarks/ranking-baseline/FREEZE.md`.

**Examples** — `capabilities/examples/` holds copy-and-edit templates. They
exist to be modified in place by an operator following the docs. A pin there
fails closed on the reader's first edit and trains operators to strip pins,
which is the opposite of what pinning is for.

## The rule

> Every high-privilege capability in the production catalogue carries a valid
> `sha256:` pin. Every file that carries a pin must match its recomputed hash.

Low-privilege files *may* be pinned. Six capabilities carried a pin before
this policy — four of them low-privilege — and all six stay pinned, because
the drift half of the check covers any file with a pin, not only the
required set.

## Current classification

Counts as of 2026-09-14. They are descriptive, not normative — the rule above
is what CI enforces, so a new capability changes the counts without changing
the policy.

| Class | Count |
|-------|-------|
| High-privilege, production catalogue — pin required | 89 |
| High-privilege, `examples/` — excluded | 5 |
| Low-privilege | 31 |
| **Total shipped YAMLs** | **125** |

## Exclusion list

Deliberately unpinned. Re-derive with `tests/capability_pin_policy.rs`, which
holds the same list as its single source of truth.

### Named exclusions — high-privilege, not pinned

| File | Why |
|------|-----|
| `capabilities/examples/github_graphql.yaml` | Copy-and-edit template. Documented as a starting point for a GraphQL capability; edited by the reader on first use. |
| `capabilities/examples/github_integration.yaml` | Copy-and-edit template for a multi-tool integration. |
| `capabilities/examples/github_user.yaml` | Copy-and-edit template, the simplest REST example in the docs. |
| `capabilities/examples/jsonrpc_example.yaml` | Copy-and-edit template for the JSON-RPC provider. |
| `capabilities/examples/linear_integration.yaml` | Copy-and-edit template for the Linear integration. |

These five are outside the shipped inventory by the catalogue's own
definition, so a rewrite of one does not change what the gateway ships.

### Categorical exclusion — the low-privilege class

The 31 low-privilege capabilities are not required to carry a pin. They hold
no credential (`auth.required: false`), declare `read_only: true`, issue only
`GET`, and spawn no process. The residual risk of an unpinned one is a wrong
answer from a public endpoint, which the pin would not prevent anyway — a
poisoned upstream returns poisoned data through a perfectly valid pin.

`capabilities/examples/check_weather.yaml` is excluded on both axes.

## Re-pinning after an edit

```bash
mcp-gateway cap pin capabilities/<category>/<name>.yaml
```

Or reproduce the hash from a shell:

```bash
grep -v '^sha256:' capabilities/<category>/<name>.yaml | sha256sum
```

CI fails on both halves: a high-privilege production file with no pin, and any
pinned file whose contents no longer match.

Editing a pinned capability through the admin Web UI
(`PUT /ui/api/capabilities/:name`) writes the body verbatim and does **not**
re-pin. That is deliberate — the guard fails closed on every rewrite,
including an authorized one, because an admin session is itself a plausible
rug-pull path. After a UI edit, run `cap pin` on the file or the capability
will stop loading.
