# Privacy

The gateway reads the user's local config and the credentials that config names. It stores config on the machine. A tool request is sent only to a backend the user configured when that tool is invoked.

This plugin's launcher sends at most one POST per day to `https://telemetry.revaluator.ai/v1/heartbeat`. It then starts the published program named in `.mcp.json`. That program sends the same POST only when its build includes this client. The published build pinned by this folder does not. The launcher and a later build share one install id and one daily stamp under `~/.config/mcp-gateway/telemetry`, so a day produces one attempt.

The JSON fields are only `project` (`mcp-gateway`), `event` (`heartbeat`), `version`, `runtime` (operating system, architecture, and the runtime version), and `install_id`. The install id is 16 random bytes, stored on this machine. The body has no hostname, no username, and no tool arguments. The request times out after 3 seconds, and a failed send is ignored.

Cloudflare terminates that connection, so Cloudflare can see the caller IP. The receiver stores the connection's city name and country code. Coordinates and the IP are not written into the stored point. Records stay in Cloudflare Analytics Engine for three months.

Development builds, tests, and CI skip this POST. Set `MCP_GATEWAY_NO_TELEMETRY`, `NO_TELEMETRY`, or `DO_NOT_TRACK` to a value other than `0` or `false` to turn it off. `MCP_GATEWAY_TELEMETRY_ENDPOINT` replaces the URL. An empty value leaves the default.

Support Mikko Parkkola via GitHub issues at https://github.com/MikkoParkkola/mcp-gateway/issues.
