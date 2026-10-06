# Security posture

This page lists which protections are on in a default install, which ones you turn on yourself
and how, what each one protects against, and what none of them covers. The per-risk mapping,
with source files, is in the [OWASP Agentic AI self-assessment](OWASP_AGENTIC_AI_COMPLIANCE.md).

## On by default

| Layer | What it protects against |
|---|---|
| Loopback bind (`server.host: 127.0.0.1`) | Other machines reaching the gateway. The gateway refuses to start on a network address with auth off, unless `server.allow_unauthenticated_network_bind` says that something in front of it authenticates callers |
| Strict config loading | Running on a config it does not fully understand. The gateway refuses to start on an unknown key, on a config or env file that other users can read, or when a secret reference resolves to nothing. Two references are checked later instead: a missing `server.metrics_token` leaves `/metrics` answering 401, and a personal account's `client_secret_ref` fails when a token is requested |
| Request firewall (`security.firewall`) | Shell injection and path traversal in tool arguments. High-severity findings are blocked and medium ones are logged as warnings |
| Response firewall | Credentials leaking out in tool results, which are redacted. Prompt-injection text in a result is flagged and stays in place |
| Memory-poisoning scanner | Control tokens and role-confusion text written through memory tools such as `remember` and `kv_set` |
| Tool policy (`security.tool_policy`) | A fixed list of high-risk tool names, such as `write_file`, `run_command`, `drop_table` and `shutdown`, is refused. Any other name is allowed unless you add it to the deny list |
| SSRF guard (`security.ssrf_protection`) | Tool arguments that point the gateway at private, loopback, link-local or cloud-metadata addresses |
| Tool-description screening | Backend tools whose descriptions carry poisoning patterns. They are withheld from tool lists |
| Per-caller visibility | A credentialled caller seeing or reaching backends it was not granted, once auth is on |
| Destructive-call confirmation | A destructive meta-tool running without the user agreeing to it |
| Capability pin check | Tampering with a pinned capability file. A file whose `sha256:` pin no longer matches is refused |
| Process limits for CLI capabilities | A CLI capability starting arbitrary programs. It runs only if it is pinned and its command is on `capabilities.process_commands`, with no shell, in a private directory, with a cleared environment, an output cap and a timeout. Unset, the list admits the commands the shipped catalogue runs: `gws`, `openpencil-mcp`, `pact-mcp`, `pyghidra-mcp` and `skill-scanner scan`. Setting the key replaces that list, so keep the entries you still need |
| Response inspection and context integrity | Nothing is blocked by default. Both observe tool output and record what they find |

## Opt-in

| Setting | Turn it on | What it adds |
|---|---|---|
| Authentication | `auth.enabled: true` with API keys or a bearer token ([Multi-User Setup](MULTI_USER.md)) | Callers on paths outside `auth.public_paths` must identify themselves, and each key reaches only its listed backends. The config `mcp-gateway init` writes has auth on but lists `/mcp` in `auth.public_paths`, so tool calls stay anonymous; remove `/mcp` from that list to require credentials for tools. With auth on, the gateway also requires the audit log below and refuses plain HTTP on a network address unless `server.cleartext_http` says how traffic is protected |
| Audit log | `security.transparency_log.enabled: true` | A hash-chained record of every call. A failed write withholds the result |
| Hardened posture | `security.posture: hardened` | Several controls raised together: context integrity at `team_shared` or stricter and not bypassable, the firewall and anomaly blocking on, backends confined by the SSRF guard (list exceptions in `security.hardened.private_backends`), and message signing required. Needs a restart |
| Context integrity | `security.context_integrity.preset: team_shared` | Tool output that fails the baseline is withheld instead of delivered |
| Response inspection blocking | `security.response_inspection.action_mode: true` | Anomalous responses are blocked instead of logged |
| Anomaly detection | `security.firewall.anomaly_detection: true`, plus `anomaly_block_threshold` to block | Unusual tool-call sequences. Calls with no caller identity are refused |
| Relay detection | `security.firewall.collusion` with `action: observe` or `block` | Content delivered to one caller that another caller then sends out |
| Message signing | `security.message_signing.enabled: true` with a `shared_secret` | An HMAC signature on `gateway_invoke` responses, which the client must verify to detect tampering. Replay protection needs a nonce from the client; `require_nonce: true` makes it mandatory |
| mTLS | `mtls.enabled: true` ([Deployment Guide](DEPLOYMENT.md)) | Callers without a valid client certificate |
| Identity headers from a proxy | `security.caller_identity` | Spoofed identity headers. They count only from listed proxy addresses or Cloudflare Access |
| Remote backend provenance | `security.remote_server_signing` | A remote backend whose URL or identity was swapped |
| Boundary-call attestation | `GATEWAY_ATTESTATION_MODE=enforce`, plus `GATEWAY_ATTESTATION_SIGNING_KEY` and `GATEWAY_ATTESTATION_AUDIENCE`: without either, the gateway refuses to start ([upgrade item 46](UPGRADING-4.0.md#46-attestation-enforce-enforces-on-every-route)) | Calls outside their signed task scope |
| Capability pinning | `mcp-gateway cap pin <file>` | Edits to a capability file you have pinned. Unpinned files still load |

To turn CLI capabilities off entirely, set `capabilities.process_execution: disabled`.

## Known limits

- **The starter config leaves tools open.** `mcp-gateway init` turns auth on for the dashboard
  and admin actions, but keeps `/mcp` in `auth.public_paths`. Any process that can reach the
  port can call tools until you remove it.
- **Prompt injection is flagged, not removed.** The response firewall warns about injection text
  but delivers it. Withholding it needs context integrity at `team_shared` or the hardened
  posture.
- **Configured backend URLs are trusted.** The SSRF guard does not re-check URLs you put in
  `backends:` unless you set `security.trust_configured_backends: false` or use the hardened
  posture.
- **Failed logins are not throttled.** Rate limits and circuit breakers apply only after a
  token authenticates.
- **Legacy HTTP clients skip destructive confirmation** when they cannot answer it. They get a
  warning instead.
- **A stdio caller is always admin**, because it started the gateway process itself.
- **CLI capabilities are confined, not sandboxed.** They run as the gateway's own user. Give
  that user least privilege.
- **Relay detection matches verbatim text only.** It compares the first and last 3 KiB of each
  result, so paraphrased or re-encoded content goes unseen.
- **Downstream tools keep their own risks.** The gateway screens calls and results. It cannot
  make an unsafe backend safe.

For the full list of what changed in 4.0, see [UPGRADING-4.0.md](UPGRADING-4.0.md).
