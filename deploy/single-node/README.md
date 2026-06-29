# Single-Node Deployment Templates

These templates use the same first-run config produced by:

```bash
mcp-gateway init --profile local
```

The generated `gateway.yaml` references `capabilities/` relative to the
gateway process working directory. Keep `gateway.yaml` and `capabilities/`
together when moving from local development to Docker Compose, systemd, or
launchd.

## Docker Compose

```bash
docker compose -f deploy/single-node/docker-compose.yaml up -d
curl -sf http://127.0.0.1:39400/health
```

Run Compose from the directory that contains `gateway.yaml` and `capabilities/`.
The Compose template mounts `$PWD/gateway.yaml` as `/config.yaml` and
`$PWD/capabilities` as `/capabilities`. The container runs from `/`, so the
relative `capabilities` directory in the local profile resolves to the mounted
`/capabilities` path.

## Linux systemd

Run these commands in a root shell or through your configuration-management
tool:

```bash
install -d -o mcp-gateway -g mcp-gateway /etc/mcp-gateway
cp gateway.yaml /etc/mcp-gateway/gateway.yaml
cp -R capabilities /etc/mcp-gateway/capabilities
cp deploy/single-node/mcp-gateway.service /etc/systemd/system/mcp-gateway.service
systemctl daemon-reload
systemctl enable --now mcp-gateway
systemctl status mcp-gateway
curl -sf http://127.0.0.1:39400/health
```

The unit sets `WorkingDirectory=/etc/mcp-gateway`, so the same relative
capability directory works without editing `gateway.yaml`.

## macOS launchd

Run these commands in a root shell or through your configuration-management
tool:

```bash
install -d /usr/local/etc/mcp-gateway
cp gateway.yaml /usr/local/etc/mcp-gateway/gateway.yaml
cp -R capabilities /usr/local/etc/mcp-gateway/capabilities
cp deploy/single-node/com.mikkoparkkola.mcp-gateway.plist /Library/LaunchDaemons/
launchctl bootstrap system /Library/LaunchDaemons/com.mikkoparkkola.mcp-gateway.plist
launchctl print system/com.mikkoparkkola.mcp-gateway
curl -sf http://127.0.0.1:39400/health
```

The launchd template sets `WorkingDirectory` to
`/usr/local/etc/mcp-gateway`, matching the generated config layout.

## Template Smoke

From a repo checkout:

```bash
scripts/dev/service-template-smoke.sh
```

The smoke creates a fresh local profile, verifies the template paths, and
starts the gateway from systemd-like and launchd-like working directories
without requiring root or a service manager.
