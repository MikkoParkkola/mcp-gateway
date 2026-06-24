# mcp-gateway Plugin Dependency Chain

Addresses MIK-4625.AC.5: downstream portfolio plugins declare `mcp-gateway` as
their Claude Code plugin dependency, while `mcp-gateway` itself has a
schema-valid `dependencies` array in `.claude-plugin/plugin.json`.

Expected downstream declarations:

```json
{
  "dependencies": [
    {
      "name": "mcp-gateway",
      "version": "~2.12.1"
    }
  ]
}
```

The first downstream plugins expected to consume this substrate are `nab`,
`hebb`, and `pithy`. Their implementation is tracked separately under the
MIK-4615 constellation, so this repo verifies the upstream manifest shape and
documents the dependency contract without attempting a live cross-plugin
install.
