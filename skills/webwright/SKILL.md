---
name: webwright
description: Webwright browser-automation skill for mcp-gateway spike (MIK-5205). Cross-runtime loadable by Claude Code, Codex CLI, and OpenClaw.
version: 0.1.0
effort: medium
allowed_tools:
  - browser_navigate
  - browser_extract
  - browser_screenshot
  - gateway_invoke
triggers:
  - webwright
  - browser scrape
  - browser automation
keywords:
  - webwright
  - browser
  - scrape
  - hebb-recall
  - bnaut-memory
  - bnaut-attestation
---

# Webwright Browser-Automation Skill

This skill integrates Microsoft Research's Webwright (MIT, 2026-05-27) browser-automation
agent with mcp-gateway's bnaut-memory and bnaut-attestation primitives.

## Architecture

Webwright provides a memoryless browser-automation loop: terminal + browser + model.
mcp-gateway closes the memory gap via:

- **bnaut-memory** (hebb-recall): caches browser-task results, short-circuiting repeat
  executions. Measurable cache-hit on second run of the same task.
- **bnaut-attestation**: identity tagging propagates through mcp-gateway trace and
  hebb decision-pins under tag `webwright-spike`.

## Usage

```
webwright scrape --target <url> --output csv
```

## Integration Points

| Primitive | Role |
|-----------|------|
| `TaskMemory` | Hebb-recall cache for browser-task results |
| `HebbDecisionPins` | Durable checkpoints under tag `webwright-spike` |
| `BnautAttestationSigner` | Identity token issuance for each run |
| `AttestationValidator` | Identity validation at gateway boundary |
| `ArtifactBundle` | Collects code + screenshots + DOM + trace + pins |

## Cross-Runtime

This skill folder loads identically across:
- Claude Code (`.claude/skills/webwright/`)
- Codex CLI (deferred — not accessible in spike environment)
- OpenClaw (deferred — not accessible in spike environment)

## References

- Webwright: <https://github.com/microsoft/Webwright> (MIT, ~1.5K LoC core)
- Ticket: MIK-5205
- Spike report: `docs/spikes/MIK-5205-webwright-spike.md`
