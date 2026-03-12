# Webhook Receiver Documentation

The MCP Gateway includes a powerful webhook receiver system that allows external services to push events into the gateway, which then distributes them as MCP notifications to all connected clients via Server-Sent Events (SSE).

## Overview

```
┌─────────────┐                    ┌──────────────┐                    ┌────────────┐
│   External  │  POST /webhooks/*  │  MCP Gateway │  SSE notifications │ MCP Clients│
│   Service   ├───────────────────▶│  (validates, │───────────────────▶│  (Claude,  │
│ (Linear,    │                    │  transforms, │                    │   etc.)    │
│  GitHub)    │                    │   routes)    │                    │            │
└─────────────┘                    └──────────────┘                    └────────────┘
```

## Features

- **HMAC Signature Validation**: Validates webhook signatures using HMAC-SHA256 to ensure authenticity
- **Flexible Payload Transformation**: Extract and transform webhook payloads into structured MCP notifications
- **Multiple Webhook Support**: Single capability can define multiple webhook endpoints
- **Automatic Route Registration**: Webhooks are automatically registered when capabilities load
- **Hot-Reload Support**: Webhook definitions reload when capability files change
- **Rate Limiting**: Configurable rate limiting per webhook endpoint
- **Secret Management**: Supports environment variables, keychain, and other secret sources

## Configuration

### Gateway Config (`config.yaml`)

```yaml
webhooks:
  enabled: true                # Enable webhook receiver system
  base_path: /webhooks         # Base path for all webhook endpoints
  require_signature: true      # Require HMAC validation (recommended)
  rate_limit: 100             # Requests per minute per endpoint
```

### Capability Definition

Webhooks are defined in capability YAML files alongside regular REST API providers:

```yaml
fulcrum: "1.0"
name: linear_integration
description: Linear webhook integration

webhooks:
  issue_updated:
    # HTTP path (full URL: /webhooks/linear/issues)
    path: /linear/issues
    method: POST

    # Secret for HMAC validation (supports {env.VAR}, keychain:name)
    secret: "{env.LINEAR_WEBHOOK_SECRET}"
    signature_header: "Linear-Signature"

    # Transform webhook payload to MCP notification
    transform:
      event_type: "linear.issue.{action}"
      data:
        id: "{data.id}"
        title: "{data.title}"
        state: "{data.state.name}"

    # Send as MCP notification
    notify: true
```

## Payload Transformation

The `transform` section defines how webhook payloads are converted into MCP notifications.

### Event Type Template

The `event_type` supports template variables extracted from the payload:

```yaml
transform:
  event_type: "linear.issue.{action}"  # Becomes "linear.issue.created"
```

Variables use dot-notation to access nested fields:
- `{action}` → payload.action
- `{data.id}` → payload.data.id
- `{repository.full_name}` → payload.repository.full_name

### Data Extraction

The `data` map extracts specific fields from the webhook payload:

```yaml
transform:
  data:
    issue_id: "{data.id}"              # Extract data.id as "issue_id"
    title: "{data.title}"              # Extract data.title as "title"
    assignee: "{data.assignee.name}"   # Extract nested field
```

If no `data` mapping is specified, the entire webhook payload is included in the notification.

## MCP Notification Format

Transformed webhooks are sent as MCP notifications via SSE:

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/webhook",
  "params": {
    "source": "linear_integration",
    "event_type": "linear.issue.created",
    "data": {
      "issue_id": "LIN-123",
      "title": "Fix bug in authentication",
      "assignee": "Alice"
    },
    "received_at": "2026-02-19T14:30:00Z"
  }
}
```

## HMAC Signature Validation

The gateway validates webhook signatures using HMAC-SHA256 to prevent unauthorized requests.

### Signature Formats

Different services use different signature formats:

**GitHub**: `X-Hub-Signature-256: sha256=<hex>`
```yaml
signature_header: "X-Hub-Signature-256"
```

**Linear**: `Linear-Signature: <hex>`
```yaml
signature_header: "Linear-Signature"
```

**Stripe**: `Stripe-Signature: t=<timestamp>,v1=<hex>`
```yaml
signature_header: "Stripe-Signature"
```

The gateway automatically handles both `sha256=<hex>` and `<hex>` formats.

### Secret Management

Webhook secrets should NEVER be hardcoded in YAML files. Use environment variables or keychain:

```yaml
# Environment variable (recommended)
secret: "{env.LINEAR_WEBHOOK_SECRET}"

# macOS Keychain
secret: "keychain:linear-webhook-secret"

# Linux secret-tool
secret: "keychain:linear-webhook-secret"
```

Set the environment variable before starting the gateway:
```bash
export LINEAR_WEBHOOK_SECRET="your_secret_here"
mcp-gateway
```

## Examples

### Linear Integration

**Capability**: `capabilities/examples/linear_webhook.yaml`

```yaml
webhooks:
  issue_updated:
    path: /linear/issues
    secret: "{env.LINEAR_WEBHOOK_SECRET}"
    signature_header: "Linear-Signature"
    transform:
      event_type: "linear.issue.{action}"
      data:
        id: "{data.id}"
        title: "{data.title}"
```

**Setup in Linear**:
1. Go to Settings → API → Webhooks
2. Create webhook: `http://your-gateway:39401/webhooks/linear/issues`
3. Set signing secret
4. Select events: Issue created, updated, deleted

### GitHub Integration

**Capability**: `capabilities/examples/github_webhook.yaml`

```yaml
webhooks:
  repository_events:
    path: /github/events
    secret: "{env.GITHUB_WEBHOOK_SECRET}"
    signature_header: "X-Hub-Signature-256"
    transform:
      event_type: "github.{action}"
      data:
        repository: "{repository.full_name}"
        sender: "{sender.login}"
```

**Setup in GitHub**:
1. Repository → Settings → Webhooks → Add webhook
2. Payload URL: `http://your-gateway:39401/webhooks/github/events`
3. Content type: `application/json`
4. Set secret
5. Select events: Issues, Pull requests, etc.

## Testing Webhooks

### Using curl

```bash
# Test webhook without signature (if require_signature: false)
curl -X POST http://localhost:39401/webhooks/linear/issues \
  -H "Content-Type: application/json" \
  -d '{
    "action": "created",
    "data": {
      "id": "LIN-123",
      "title": "Test issue"
    }
  }'
```

### With HMAC Signature

```bash
# Generate signature
secret="your_webhook_secret"
payload='{"action":"created","data":{"id":"LIN-123"}}'
signature=$(echo -n "$payload" | openssl dgst -sha256 -hmac "$secret" | cut -d' ' -f2)

# Send request
curl -X POST http://localhost:39401/webhooks/linear/issues \
  -H "Content-Type: application/json" \
  -H "Linear-Signature: $signature" \
  -d "$payload"
```

### Receive Notifications

Connect to the SSE stream to receive webhook notifications:

```bash
curl -N http://localhost:39401/mcp
```

You'll see:
```
event: connected
data: {"session_id":"gw-abc123"}

event: linear.issue.created
data: {"source":"linear_integration","event_type":"linear.issue.created",...}
```

## Security Best Practices

1. **Always use HMAC validation**: Set `require_signature: true` in production
2. **Use environment variables for secrets**: Never commit secrets to version control
3. **Use HTTPS in production**: Webhook payloads should be encrypted in transit
4. **Rate limiting**: Configure appropriate rate limits to prevent abuse
5. **Validate payload structure**: Use the transform to extract only expected fields
6. **Monitor webhook logs**: Check gateway logs for failed signature validations

## Troubleshooting

### Webhook not receiving events

1. Check gateway logs for webhook registration:
   ```
   INFO Registered webhook endpoint capability=linear webhook=issue_updated path=/webhooks/linear/issues
   ```

2. Verify the webhook is accessible:
   ```bash
   curl -X POST http://localhost:39401/webhooks/linear/issues
   ```

3. Check capability is loaded:
   ```bash
   mcp-gateway cap list capabilities/
   ```

### Signature validation fails

1. Verify secret is correctly set:
   ```bash
   echo $LINEAR_WEBHOOK_SECRET
   ```

2. Check signature header matches service:
   - Linear: `Linear-Signature`
   - GitHub: `X-Hub-Signature-256`

3. Ensure payload is sent as JSON (not form-encoded)

### Notifications not appearing

1. Verify streaming is enabled in `config.yaml`:
   ```yaml
   streaming:
     enabled: true
   ```

2. Check SSE connection is established:
   ```bash
   curl -N http://localhost:39401/mcp
   ```

3. Verify `notify: true` in webhook definition

## Performance

- **Request handling**: <10ms per webhook (excluding notification broadcast)
- **HMAC validation**: ~1ms per request
- **Payload transformation**: <1ms for typical payloads
- **Notification broadcast**: ~0.1ms per connected client

## Limitations

- Maximum payload size: Configured by `server.max_body_size` (default 10MB)
- Rate limiting applies per endpoint (not globally)
- Signature validation uses HMAC-SHA256 only (no other algorithms)
- Template extraction uses simple dot-notation (not full JSONPath)

## Advanced Usage

### Multiple Webhooks in One Capability

```yaml
webhooks:
  issue_events:
    path: /linear/issues
    ...
  comment_events:
    path: /linear/comments
    ...
  project_events:
    path: /linear/projects
    ...
```

### Webhook-Only Capabilities

Capabilities can define only webhooks without any REST providers:

```yaml
fulcrum: "1.0"
name: webhook_receiver
description: Pure webhook receiver

providers: {}  # No REST providers

webhooks:
  events:
    path: /service/events
    ...
```

### Custom Event Types

Use static event types for simple notifications:

```yaml
transform:
  event_type: "custom.event.notification"  # No variables
  data:
    message: "{message}"
```

## API Reference

### WebhookDefinition

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | URL path (relative to base_path) |
| `method` | string | No | HTTP method (default: POST) |
| `secret` | string | No | HMAC secret (supports templates) |
| `signature_header` | string | No | Header containing signature |
| `transform` | object | No | Payload transformation config |
| `notify` | boolean | No | Send as MCP notification (default: true) |

### WebhookTransform

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | No | Event type template |
| `data` | map | No | Field extraction mappings |

### WebhookConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | true | Enable webhook system |
| `base_path` | string | "/webhooks" | Base URL path |
| `require_signature` | boolean | true | Require HMAC validation |
| `rate_limit` | number | 100 | Requests per minute |
