# Firewall rules

`security.firewall.rules` overrides what the firewall does with a finding, per tool, backend and key. Without a rule, every finding gets its severity's default: Critical and High block, Medium warns, Low is allowed.

```yaml
security:
  firewall:
    rules:
      - match: "*"
        servers: ["crm", "billing-*"]
        keys: ["support-bot"]
        scan: [credentials]
        action: allow
        reason: "the CRM returns account keys by design"
        except:
          - tool: "export_*"
```

## Keys of a rule

| Key | Required | Meaning |
|---|---|---|
| `match` | yes | A glob over the tool name (`*`, `?`, `[abc]`, `[!abc]`). |
| `action` | yes | `allow`, `warn` or `block`: what this rule does with a finding it decides. |
| `reason` | no | Text logged in the audit entry when the rule decides a finding. |
| `scan` | no | The finding types this rule decides (list below). Absent or empty: every type. |
| `servers` | no | Globs over the backend's registry name. Absent: every backend. A call to a tool the gateway serves itself has no backend, so a rule with `servers` never covers the call. An answer that names no single backend (a discovery listing, a notification, a gateway tool's answer) is judged as every registered backend could have sent it, so a `servers` rule does cover it. |
| `keys` | no | API key names, matched exactly. Absent: every caller. |
| `except` | no | Calls this rule skips. Each entry sets one or more of `server` (a glob), `tool` (a glob) and `key` (an exact name); a call is skipped when it matches every field the entry sets. |

## How a finding is decided

1. A rule covers a call when `match` covers the tool, `servers` (if set) covers the backend, `keys` (if set) holds the caller's key, and no `except` entry matches the call.
2. Each finding goes to the first covering rule, in file order, whose `scan` holds the finding's type. If no rule takes it, the finding gets its severity's default.
3. The call or answer takes the most restrictive result over all its findings: `block` over `warn` over `allow`.

So an `allow` rule written for credentials allows credentials only. A shell injection in the same call still falls to a later rule, or to its default.

**A caller whose key isn't known.** Some paths judge a call where the caller's key isn't available. There the firewall resolves the call under every key any rule names, and under no key, and takes the most restrictive result. So a `keys` rule that could apply does apply, and an `except` naming one possible key never exempts the call.

## Finding types for `scan`

`credentials`, `pii`, `prompt_injection`, `shell_injection`, `path_traversal`, `sql_injection`, `sequence_anomaly`, `memory_poisoning`, `cross_tenant_reach`, `budget_exceeded`, `collusion_relay`.

## Load rules

A rule that breaks one of these fails the config load. The error names the key path, for example `security.firewall.rules[2].servers`, and never prints a value.

- An unknown key anywhere under a rule is refused, as everywhere in `gateway.yaml`.
- `match`, every `servers` glob, and every `except` glob must parse. An invalid glob is never read as `*`.
- `servers`, `keys` and `except` must not be empty when present. Leave a key out to apply to all.
- An `except` entry must set at least one field.
