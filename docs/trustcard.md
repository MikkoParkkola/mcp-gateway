# TrustCard and CBOM

TrustCard is the compact human summary for an MCP server. CBOM is the
machine-readable capability bill of materials for tools, prompts, resources,
runtime profiles, dependencies, permissions, data classes, provenance, and
evaluation status.

The first implementation slice is advisory and local:

- Generate TrustCard metadata from protocol tool definitions and local
  capability YAML.
- Produce deterministic CBOM component digests from canonical JSON schemas.
- Validate required fields with stable finding codes.
- Degrade unknown or missing metadata to warnings or failures instead of
  treating it as safe.
- Group missing metadata into TrustCard Assistant decisions so people answer
  ownership, license, runtime, risk, or repair questions instead of raw schema
  fields.
- Expose local CLI workflows:
  - `mcp-gateway trust generate --capabilities capabilities --format json`
  - `mcp-gateway trust inspect weather_current --capabilities capabilities`
  - `mcp-gateway trust validate --capabilities capabilities`
  - `mcp-gateway trust validate --file trustcard.json --strict`

## TrustCard Assistant

`trust_card_assistant.v1` is an advisory plan generated from TrustCard
validation findings. It lists automated actions to try first, such as package
metadata scans or descriptor regeneration, then groups remaining human work into
meaningful decisions:

- source ownership and canonical source URI
- license or usage-rights review
- runtime transport and profile review
- risk and data-handling acceptance
- machine metadata repair

`mcp-gateway trust validate --format json` includes the grouped human decisions
for automation consumers. Table and plain output include decision counts, and
`trust inspect` prints the compact human decision list.

Free/core owns the schema, local generation, validation, and JSON output.
Enterprise owns signed attestations, policy overlays, continuous drift reports,
approval workflows, and evidence export.

Focused validation:

```bash
cargo test trust::tests -- --nocapture
cargo test commands::trust::tests -- --nocapture
```
