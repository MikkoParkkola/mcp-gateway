# MCP Gateway in 2 Minutes

Get from zero to a working gateway with tools your AI can use.

## The fast way (recommended)

```bash
brew install MikkoParkkola/tap/mcp-gateway   # 1. install
mcp-gateway setup wizard --configure-client  # 2. import existing servers + wire up clients
mcp-gateway serve                            # 3. run
mcp-gateway doctor                           # 4. verify
```

The wizard scans Claude Desktop, Claude Code, Cursor, Windsurf, Zed, Continue.dev, and Codex for existing MCP servers, imports them into `gateway.yaml`, previews the gateway client entry, writes it into detected clients, verifies the write, and prints any backup/rollback paths.

> **Nothing to import yet?** `mcp-gateway setup wizard --configure-client` now bootstraps the local starter profile when no existing MCP servers are found. You can still run `mcp-gateway init --profile local` directly if you only want to create `gateway.yaml` plus zero-key sample capability files. The starter profile turns on the memory and sequential-thinking servers, which recommend Node.js 24 or later.

## The manual way (learn what's happening)

<details>
<summary>Step-by-step setup with explanation</summary>

### Prerequisites

- **Rust toolchain** (1.95+): [rustup.rs](https://rustup.rs), or use Homebrew
- **Node.js with `npx`**, for the manual config's example backend. Its first start downloads the package, so it needs network access once. The built-in filesystem, memory and sequential-thinking servers (2.0.0) recommend Node.js 24 or later; they run on Node 22 too.

### 1. Install

```bash
# Homebrew (macOS/Linux, recommended)
brew install MikkoParkkola/tap/mcp-gateway

# Or from crates.io
cargo install mcp-gateway
```

### 2. Create a Config

```bash
mcp-gateway init --profile local
```

This writes `gateway.yaml` with sensible defaults and two free capability files under `capabilities/knowledge/`.

It also generates an **admin credential** for this install. `init` stores it in
the store selected by `secrets.store` and writes only a reference into
`auth.bearer_token`; neither the config nor its samples contain the literal token.
The default `auto` prefers the OS keychain and falls back to owner-only files
under `<config-dir>/secrets` if the keychain probe fails. If the keychain write
fails after a passing probe, `auto` falls back to those files with a new token and a
warning naming the reason; an explicit `secrets.store: keychain` refuses instead. It never
falls back to a literal in the config. `init` also reads `MCP_GATEWAY_SECRETS__STORE`
(`auto`, `keychain` or `files`) for that run, and prints where the token went.
Tool calls do not need it —
`init` lists `/health` and `/mcp` under `auth.public_paths` so the client you
configure keeps working. Managing the gateway does: the four tools that change
it for every session, and the operator dashboard.

To open the dashboard, use the link `serve` prints on startup — on a loopback
bind, which is the default. A browser cannot attach an `Authorization` header to
a navigation, so the link carries a single-use value that is exchanged for a
session cookie and then spent:

```
DASHBOARD (opens once, then remembered in this browser):
  http://127.0.0.1:39400/dashboard?bootstrap=...
```

#### Read the admin token for a client

Run `mcp-gateway doctor --no-registry-check` against this config and read its
`admin-token` line (or inspect `auth.bearer_token` in `gateway.yaml`). Use that
reference, not the `secret-store` line, which describes the store for future
writes. For `keychain:NAME`, copy everything after `keychain:` as `NAME` below.
Init entry names have the form
`mcp-gateway.auth-bearer-token.<milliseconds>.<16-hex>`; use the actual name,
not this pattern. Run the matching recipe as the user who ran init:

```bash
# macOS Keychain: service = NAME, account = mcp-gateway
export MCP_GATEWAY_TOKEN="$(security find-generic-password -a mcp-gateway -s 'NAME' -w)"

# Linux Secret Service: service attribute = NAME (requires secret-tool)
export MCP_GATEWAY_TOKEN="$(secret-tool lookup service 'NAME')"

# File store on macOS/Linux: use the exact path after file:
export MCP_GATEWAY_TOKEN="$(cat '/absolute/config-dir/secrets/NAME')"
```

The file store uses `<config-dir>/secrets/NAME`. On Windows, read the exact
path after `file:` with PowerShell:

```powershell
$env:MCP_GATEWAY_TOKEN = [IO.File]::ReadAllText('C:\config-dir\secrets\NAME').TrimEnd("`r", "`n")
```

For Windows Credential Manager, read the **generic credential** whose target
is `NAME` and whose user is `mcp-gateway`. The blob is UTF-8 bytes, not a
UTF-16 password. This PowerShell recipe calls `CredReadW` with generic type 1
and flags 0, checks the user, and frees the returned credential:

```powershell
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class GatewayCredential {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct Credential {
        public uint Flags, Type;
        public IntPtr TargetName, Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes, TargetAlias, UserName;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    static extern bool CredReadW(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    static extern void CredFree(IntPtr credential);
    public static string Read(string target) {
        IntPtr pointer;
        if (!CredReadW(target, 1, 0, out pointer))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        Credential credential = new Credential();
        byte[] bytes = null;
        try {
            credential = (Credential)Marshal.PtrToStructure(pointer, typeof(Credential));
            if (Marshal.PtrToStringUni(credential.UserName) != "mcp-gateway")
                throw new InvalidOperationException("Unexpected credential user");
            bytes = new byte[checked((int)credential.CredentialBlobSize)];
            Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);
            return Encoding.UTF8.GetString(bytes);
        } finally {
            if (bytes != null) Array.Clear(bytes, 0, bytes.Length);
            for (int i = 0; i < credential.CredentialBlobSize; i++)
                Marshal.WriteByte(credential.CredentialBlob, i, 0);
            CredFree(pointer);
        }
    }
}
'@
$env:MCP_GATEWAY_TOKEN = [GatewayCredential]::Read('NAME')
```

The Windows recipe is documented but not run in CI. The native-store recipes
still need end-to-end verification against a real init entry and an admin request.
Export the retrieved token value, never the `keychain:` or `file:` reference.
Clients such as `mcp-gateway dashboard-link` and `mcp-gateway api` read
`MCP_GATEWAY_TOKEN` from their environment.

#### Recover an interrupted init

Init attempts rollback on handled failures and reports recovery required if
publication or cleanup is uncertain. A crash can leave an orphan store entry
or a config without its samples. Inspect the config reference and doctor's
unused-entry report, remove the orphan store entry, delete the partial config,
and re-run init. Remove any sample files left by that attempt too; preserve
pre-existing files. Init refuses an existing config, so rerunning it alone
does not repair a partial install. Do not remove an entry used by a config
you intend to keep.

Or create the config manually:

<!-- quickstart-minimal-config -->
```yaml
server:
  port: 39400

backends:
  everything:
    command: "npx -y @modelcontextprotocol/server-everything"

capabilities:
  directories:
    - ./capabilities
```
<!-- /quickstart-minimal-config -->

`everything` is the MCP reference server; replace it with any server you already
run. The capability directory may stay empty until step 3.

The gateway refuses a config file other users can read, because it can hold
credentials, so make it yours alone:

```bash
chmod 600 gateway.yaml
```

### 3. Add Capabilities

The `init --profile local` command creates these automatically. If you're writing config by hand, create a `capabilities/` directory and add capability YAML files (no API keys needed):

**capabilities/weather.yaml**
```yaml
fulcrum: "1.0"
name: weather
description: Get current weather for a location (free, no API key)

schema:
  input:
    type: object
    properties:
      latitude:
        type: number
        description: Latitude coordinate
      longitude:
        type: number
        description: Longitude coordinate
    required: [latitude, longitude]

providers:
  primary:
    service: rest
    cost_per_call: 0
    config:
      base_url: https://api.open-meteo.com
      path: /v1/forecast
      method: GET
      params:
        latitude: "{latitude}"
        longitude: "{longitude}"
        current_weather: "true"
      response_path: current_weather

cache:
  strategy: exact
  ttl: 300

auth:
  required: false

metadata:
  category: weather
  read_only: true  # only a read-only capability is cached
  tags: [weather, forecast, free]
```

**capabilities/wikipedia.yaml**
```yaml
fulcrum: "1.0"
name: wikipedia_summary
description: Get a Wikipedia article summary (free, no API key)

schema:
  input:
    type: object
    properties:
      title:
        type: string
        description: Article title (use underscores for spaces, e.g. "Albert_Einstein")
    required: [title]

providers:
  primary:
    service: rest
    cost_per_call: 0
    config:
      base_url: https://en.wikipedia.org
      path: /api/rest_v1/page/summary/{title}
      method: GET
      headers:
        Accept: "application/json"

cache:
  strategy: exact
  ttl: 86400

auth:
  required: false

metadata:
  category: knowledge
  read_only: true  # only a read-only capability is cached
  tags: [wikipedia, encyclopedia, free]
```

## 4. Start the Gateway

```bash
mcp-gateway serve
```

You should see:

```
INFO  mcp_gateway: Starting MCP Gateway on 127.0.0.1:39400
INFO  mcp_gateway: Meta-MCP enabled (compact gateway tool surface)
INFO  mcp_gateway: Loaded 2 capabilities
```

## 5. Test It

Search for tools:

```bash
curl -s http://localhost:39400/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "gateway_search_tools",
      "arguments": { "query": "weather" }
    }
  }' | python3 -m json.tool
```

Invoke the weather tool:

```bash
curl -s http://localhost:39400/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "gateway_invoke",
      "arguments": {
        "server": "fulcrum",
        "tool": "weather",
        "arguments": { "latitude": 60.17, "longitude": 24.94 }
      }
    }
  }' | python3 -m json.tool
```

### 6. Connect to your AI client

```bash
mcp-gateway setup export --target all --dry-run  # preview first
mcp-gateway setup export --target all            # write, back up, and verify
mcp-gateway setup export --target claude-code    # or a specific client
```

When an existing client config is updated, the command prints a backup path and a rollback command such as:

```bash
mcp-gateway setup export --rollback ~/.claude.json.mcp-gateway.bak.123456789
```

Or manually — add to your client config:

```json
{
  "mcpServers": {
    "gateway": {
      "type": "http",
      "url": "http://localhost:39400/mcp"
    }
  }
}
```

Restart your client. The gateway's compact Meta-MCP surface (11 tools for an administrator on the default HTTP setup, 9 to 17 depending on configuration; a caller without admin standing sees fewer) replaces every backend tool definition.

See [examples/claude-desktop.json](../examples/claude-desktop.json) for a full example config.

### 7. Pick a deployment recipe

Use the same config model everywhere:

```bash
# Local developer
mcp-gateway init --profile local
mcp-gateway setup export --target all --dry-run
mcp-gateway serve
mcp-gateway doctor --format json
scripts/dev/first-run-smoke.sh  # repo checkout: clean init -> routed tool call
scripts/dev/usability-smoke.sh  # repo checkout: no prompts + safe export + routed tool call

# Container
# Linux bind mounts: prepare a dedicated owner-only copy for container UID 1001.
install -m 600 gateway.yaml gateway.container.yaml
# init wrote a reference to a token stored on this host, which the container
# cannot read: point the copy at an environment variable and read the token out
# with the recipe in "Read the admin token for a client" above.
sed -i 's|^\( *bearer_token: *\).*|\1"env:MCP_GATEWAY_TOKEN"|' gateway.container.yaml
export MCP_GATEWAY_TOKEN="$(cat '/absolute/config-dir/secrets/NAME')"  # or the recipe for your store
sudo chown 1001:1001 gateway.container.yaml
# The container must bind 0.0.0.0 to receive anything, and the config `init`
# writes keeps /mcp public, so the gateway refuses that pairing unless the
# allow-flag is set. The boundary is the publish: 127.0.0.1 only, so nothing
# off this host reaches the port. The same publish is why the auth `init` turns
# on may cross the container's 0.0.0.0 in plain HTTP (host_local_publish).
# Mirrors deploy/single-node/docker-compose.yaml.
docker run --rm --stop-timeout 31 -p 127.0.0.1:39400:39400 \
  -e MCP_GATEWAY_TOKEN \
  -e MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND=true \
  -e MCP_GATEWAY_SERVER__CLEARTEXT_HTTP=host_local_publish \
  -v "$PWD/gateway.container.yaml:/config.yaml:ro" \
  -v "$PWD/capabilities:/capabilities:ro" \
  ghcr.io/mikkoparkkola/mcp-gateway:latest --config /config.yaml --host 0.0.0.0 --port 39400
scripts/dev/docker-smoke.sh  # repo checkout: container health + routed tool call

# Native service templates
docker compose -f deploy/single-node/docker-compose.yaml config
scripts/dev/service-template-smoke.sh  # repo checkout: systemd/launchd path + start smoke

# Team-shared gateway
mcp-gateway doctor --format json
mcp-gateway tls init-ca --cn "MCP Gateway Root CA" --out ./tls
```

On Linux, the image runs as UID/GID 1001, so its bind-mounted deployment copy
must be readable by that identity. Keep the copy owner-only as shown; do not
`chmod 644` a config that may contain credentials, and do not change ownership
on your working config. Docker Desktop handles bind-mount identity differently
on macOS and Windows.

For a team-shared gateway, keep auth enabled, bind behind TLS or mTLS, and distribute only the generated client entry or managed config profile to users.

</details>

## Next Steps

- **Add more backends**: `mcp-gateway add tavily` (35 servers in the built-in registry). Or `mcp-gateway add my-server -- npx -y @some/mcp-server`.
- **Add more capabilities**: Copy any YAML from the `capabilities/` directory that ships with the gateway. 130+ ship; the keyless ones work with zero config, and one that needs an API key is listed once you set that key.
- **Import OpenAPI specs**: `mcp-gateway cap import stripe-openapi.yaml --output capabilities/`
- **Add remote backends**: For a zero-auth remote backend you can try in seconds, see [Adding remote MCP backends](REMOTE_BACKENDS.md).
- **Find unmanaged MCP servers**: `mcp-gateway cap discover --shadow --format json` emits a passive ShadowRadar report with stable finding IDs, ownership, transport exposure, trust status, data risk, recommended action, confidence, verification, and rollback. It does not invoke discovered tools. Add `--write-config` only after reviewing adoptable local findings.
- **Inspect the local control plane**: Open `http://127.0.0.1:39400/ui#control-plane` for read-only inventory, runtime health, decision queue, RBAC, and license-boundary status.
- **Caching**: on already, with nothing to configure. The gateway caches only results of tools whose annotations mark them read-only.
- **Enable auth**: on a config `init` wrote, it is already on with a reference to a stored generated credential; see [Read the admin token for a client](#read-the-admin-token-for-a-client). On a hand-written one, use `auth: { enabled: true, bearer_token: "env:MCP_GATEWAY_TOKEN", public_paths: ["/health", "/mcp"] }` and set that variable to a secret you keep.

  Two halves, both load-bearing. `public_paths` is not optional: turning authentication on gates **every** path, so enabling it alone makes the MCP client you already configured start failing. And do not use `bearer_token: "auto"` if anything needs to authenticate — it mints a fresh random token on every start and logs only a fingerprint, never the value, so no client can present it. See [DEPLOYMENT.md](DEPLOYMENT.md#admin-requires-a-credential).
- **Install from registry**: Run `mcp-gateway cap search finance` and `mcp-gateway cap install stock_quote`.
- **Check health**: `mcp-gateway doctor` diagnoses config, port, runtime health, MCP handshake, tool listing, env vars, client config, and passive ShadowRadar unmanaged-MCP findings. A stdio backend that fails to start: `mcp-gateway doctor --start-stdio` starts each one the way the gateway does and shows why it died (exit status and a cause class matched from its stderr; the stderr text is never logged, and is shown only with `--show-stderr`, masked and under a may-contain-secrets banner); it runs the configured commands, so it is opt-in. A backend under a runtime profile is not launched and is reported as skipped, naming the profile. Use `mcp-gateway doctor --format json` for automation-friendly results with fix hints, risk, confirmation, verification, and rollback metadata. In a repo checkout, `scripts/dev/usability-smoke.sh` verifies the local first-use path stays noninteractive by default and only uses backup/rollback for config mutation, and `scripts/dev/service-template-smoke.sh` verifies the Docker Compose, systemd, and launchd templates consume the same generated config layout. Doctor also warns when a stdio backend pins a registry npm package to a version npm marks deprecated: that lookup is on by default and sends only package names from the gateway's own registry to registry.npmjs.org, which sees this host's IP address. Turn it off with `--no-registry-check`, `MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK=1`, or `security.posture: hardened`.
- **Full config reference**: See the [README](../README.md) or [examples/gateway-full.yaml](../examples/gateway-full.yaml).
