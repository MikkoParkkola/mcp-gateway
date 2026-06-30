# Protocol Imports — Review-First Import Workflow

> **mcp-gateway cap import** converts external API descriptions into reviewable capability drafts. Every imported capability starts **disabled** and requires **human approval** before it appears in `tools/list`.

## Quick Start

```bash
# OpenAPI import (most common)
mcp-gateway cap import --format openapi --file api.yaml --out capabilities/

# Preview what would be generated (dry-run)
mcp-gateway cap import --format openapi --file api.yaml --review

# Approve a pending draft after review
mcp-gateway cap import --approve capabilities/petstore_addpet.yaml

# Postman collection import
mcp-gateway cap import --format postman --file collection.json --out capabilities/

# GraphQL schema import
mcp-gateway cap import --format graphql --file schema.graphql --out capabilities/

# OCI MCP package import
mcp-gateway cap import --format oci --file server.json --out capabilities/
```

## Supported Formats

| Format | Flag | Input | Status |
|--------|------|-------|--------|
| OpenAPI 3.x / Swagger 2.0 | `--format openapi` | `.yaml`, `.json` | Stable |
| GraphQL SDL / Introspection | `--format graphql` | `.graphql`, `.json` | Stable |
| Postman Collection v2.1 | `--format postman` | `.json` | Stable |
| OCI MCP Package | `--format oci` | `server.json` | Prototype |

## Review-First Workflow

Every import goes through these gates:

1. **Generate** — The importer produces `CapabilityDraft` values from the source.
2. **Classify** — Each draft gets a `SafetyClassification`:
   - `ReadOnly` — GET/HEAD/query operations, safe to enable after cursory review.
   - `Mutation` — POST/PUT/PATCH operations, **review required**.
   - `Destructive` — DELETE operations, **review required**.
   - `OpenWorld` — Broad-scope packages, **review required**.
3. **Review (pending review)** — Destructive, mutation, and open-world tools are **disabled** (`enabled: false`) and remain invisible to `tools/list` until a human marks them approved.
4. **Approve** — Use `--approve` to mark a draft as reviewed and enable it.

```bash
# Review all pending drafts
mcp-gateway cap import --review

# Approve specific capabilities
mcp-gateway cap import --approve capabilities/*.yaml
```

## TrustCard

Every generated draft includes a **TrustCard** stub (`<name>.trustcard.md`) with:

- Source identity (URL, file path, or package identifier)
- Risk annotations (why this tool requires review)
- Generated timestamp
- Reviewer assignment slot

After human review, the operator fills in the `reviewer` and `notes` fields and marks the TrustCard as reviewed.

## Legacy `cap import` Compatibility

The existing `mcp-gateway cap import` command continues to work as before. It now internally routes through the draft flow:

1. Old path: `OpenApiConverter` → `GeneratedCapability` → YAML (immediate write)
2. New path: `OpenApiDraftConverter` → `CapabilityDraft` → `ImportGenerator` → YAML + TrustCard + Examples + Risk Report

The old path remains available for backward compatibility. The new path is the recommended workflow for all new imports.

## Deterministic Output

All importers produce **deterministic, snapshot-testable** output:

- Draft names are sorted alphabetically
- YAML keys are emitted in stable order
- File names are derived from draft names
- Risk annotations are sorted
- Two consecutive generations from the same input produce **byte-identical** output trees

## Example: Full OpenAPI Import Cycle

```bash
# 1. Import with review (dry-run first)
mcp-gateway cap import --format openapi --file petstore.yaml --review

# 2. Generate to disk
mcp-gateway cap import --format openapi --file petstore.yaml --out capabilities/

# 3. Review generated TrustCards
ls capabilities/*.trustcard.md

# 4. Approve after review
mcp-gateway cap import --approve capabilities/petstore_getpetbyid.yaml
mcp-gateway cap import --approve capabilities/petstore_findpetsbystatus.yaml

# 5. Check pending reviews
mcp-gateway cap import --review
# Output: 2 approved, 5 pending review
```

## Architecture

```text
OpenAPI spec  ──┐
GraphQL SDL   ──┤
Postman coll. ──┼──▶ CapabilityDraft ──▶ ImportGenerator ──▶ YAML + TrustCard + Risk Report
OCI package   ──┘
```

Source: `src/capability/import/`
- `draft.rs` — `CapabilityDraft`, `ImportSourceKind`, `SafetyClassification`
- `openapi.rs` — `OpenApiDraftConverter`
- `graphql.rs` — `GraphQlImporter`
- `postman.rs` — `PostmanImporter`
- `oci.rs` — `OciMcpPackageImporter`
- `generator.rs` — `ImportGenerator`
