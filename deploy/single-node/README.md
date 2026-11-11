# Single-Node Deployment Templates

These templates use the same first-run config produced by:

```bash
mcp-gateway init --profile local
```

The generated `gateway.yaml` references `capabilities/` relative to the
gateway process working directory. Keep `gateway.yaml` and `capabilities/`
together when moving from local development to Docker Compose, systemd, or
launchd.

`init` stores the admin token outside `gateway.yaml` and writes a reference to it
in `auth.bearer_token`. For a service that runs as another user (systemd,
launchd), install the stored token file next to the deployed config, owner-only,
and point the deployed copy's reference at it, for example
`bearer_token: "file:/etc/mcp-gateway/secrets/NAME"`. Find `NAME` and the
original path on the `admin-token` line of `mcp-gateway doctor`.

## Docker Compose

```bash
# Linux: gateway.yaml here is a deployment copy, not your working config
install -m 600 <working-config> gateway.yaml
# init wrote a reference to a token stored on this host; the container cannot
# read it. Use an environment variable instead (QUICKSTART: "Read the admin token for a client").
sed -i 's|^\( *bearer_token: *\).*|\1"env:MCP_GATEWAY_TOKEN"|' gateway.yaml
export MCP_GATEWAY_TOKEN="$(cat '/absolute/config-dir/secrets/NAME')"
sudo chown 1001:1001 gateway.yaml
docker compose -f deploy/single-node/docker-compose.yaml up -d
curl -sf http://127.0.0.1:39400/readyz
```

The gateway refuses a config file other users can read (see
[UPGRADING-4.0](../../docs/UPGRADING-4.0.md), item 35), and a bind mount keeps
the host file's mode and owner, so a default `0644` file stops the container.

The checks in this guide use `/readyz`, which answers 200 once the config has
loaded and the listener is up. It never reads backend health. `/livez` answers
200 while the process serves, and `/health` answers 503 whenever any backend is
marked down, so it suits dashboards rather than install checks.

Run Compose from the directory that contains `gateway.yaml` and `capabilities/`.
The Compose template mounts `$PWD/gateway.yaml` as `/config.yaml` and
`$PWD/capabilities` as `/capabilities`. The container runs from `/`, so the
relative `capabilities` directory in the local profile resolves to the mounted
`/capabilities` path.

On Linux, use a dedicated deployment directory rather than changing ownership
on your working config. The image runs as UID/GID 1001, so prepare the copy with
`install -m 600 <working-config> gateway.yaml && sudo chown 1001:1001
gateway.yaml` before starting Compose. Do not make a credential-bearing config
world-readable. Docker Desktop handles bind-mount identity differently on
macOS and Windows.

## Linux systemd

Run these commands in a root shell or through your configuration-management
tool:

```bash
install -d -o mcp-gateway -g mcp-gateway /etc/mcp-gateway
install -m 600 -o mcp-gateway -g mcp-gateway gateway.yaml /etc/mcp-gateway/gateway.yaml
cp -R capabilities /etc/mcp-gateway/capabilities
cp deploy/single-node/mcp-gateway.service /etc/systemd/system/mcp-gateway.service
systemctl daemon-reload
systemctl enable --now mcp-gateway
systemctl status mcp-gateway
curl -sf http://127.0.0.1:39400/readyz
```

The unit sets `WorkingDirectory=/etc/mcp-gateway`, so the same relative
capability directory works without editing `gateway.yaml`.
The config is installed `0600` and owned by the service user because the
gateway refuses a config file other users can read (see
[UPGRADING-4.0](../../docs/UPGRADING-4.0.md), item 35).

## macOS launchd

Run these commands in a root shell or through your configuration-management
tool:

```bash
install -d /usr/local/etc/mcp-gateway
install -m 600 gateway.yaml /usr/local/etc/mcp-gateway/gateway.yaml
cp -R capabilities /usr/local/etc/mcp-gateway/capabilities
cp deploy/single-node/com.mikkoparkkola.mcp-gateway.plist /Library/LaunchDaemons/
launchctl bootstrap system /Library/LaunchDaemons/com.mikkoparkkola.mcp-gateway.plist
launchctl print system/com.mikkoparkkola.mcp-gateway
curl -sf http://127.0.0.1:39400/readyz
```

The launchd template sets `WorkingDirectory` to
`/usr/local/etc/mcp-gateway`, matching the generated config layout. The daemon runs as
root, so a root-owned `0600` copy is readable by it and by no other user.

## Template Smoke

From a repo checkout:

```bash
scripts/dev/service-template-smoke.sh
```

The smoke creates a fresh local profile, verifies the template paths, and
starts the gateway from systemd-like and launchd-like working directories
without requiring root or a service manager.
