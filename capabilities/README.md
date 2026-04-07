# MCP Gateway Built-in Capabilities

mcp-gateway currently ships **93 built-in capabilities** (marketed publicly as **90+**), derived from the tracked YAML inventory under `capabilities/` excluding `examples/`.

## Categories

| Category | Count |
|----------|-------|
| **automation/** | 1 |
| **communication/** | 2 |
| **entertainment/** | 4 |
| **finance/** | 6 |
| **food/** | 1 |
| **google/** | 21 |
| **infrastructure/** | 1 |
| **knowledge/** | 7 |
| **linear/** | 13 |
| **media/** | 4 |
| **productivity/** | 25 |
| **search/** | 1 |
| **security/** | 2 |
| **utility/** | 3 |
| **verification/** | 2 |

## Discovering the Catalog

Use the live registry commands instead of relying on a hard-coded starter subset:

```bash
# List everything shipped with the gateway
mcp-gateway cap registry-list

# Search the built-in catalog
mcp-gateway cap search weather
mcp-gateway cap search finance
mcp-gateway cap search github
```

For the exact current inventory on disk:

```bash
find capabilities -name '*.yaml' -not -path '*/examples/*' | wc -l
```

## Auth and Configuration

Authentication requirements are declared per capability in each YAML file's `auth` block. Some capabilities work instantly with no credentials; others require API keys or OAuth tokens.

Use the capability YAML itself as the source of truth for:

- whether auth is required
- which environment variable name is expected
- where to sign up for credentials (`auth.description`)
- cache and timeout behavior

## Usage with MCP Gateway

```yaml
# gateway.yaml
capabilities:
  directories:
    - ./capabilities
```

Then invoke via Meta-MCP:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "gateway_invoke",
    "arguments": {
      "backend": "capabilities",
      "tool": "weather",
      "args": {"latitude": 52.37, "longitude": 4.89}
    }
  },
  "id": 1
}
```

## Adding Your Own

Copy any YAML file as a template. Required fields:

```yaml
fulcrum: "1.0"
name: your_capability
description: What it does

schema:
  input:
    type: object
    properties:
      # your parameters
  output:
    type: object
    properties:
      # response shape

providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /v1/endpoint
      method: GET

auth:
  required: true/false
  type: api_key/bearer/oauth2
  key: ENV_VAR_NAME

metadata:
  category: utility
  tags: [tag1, tag2]
  cost_category: free/cheap/paid
```

## API Categories Explained

- **knowledge/**: Reference data, facts, geocoding, academic papers
- **search/**: Web, news, images, code search
- **finance/**: Stock quotes, currency exchange, SEC filings, company data
- **geo/**: IP geolocation
- **entertainment/**: Movies, music, jokes, trivia
- **utility/**: QR codes, UUIDs, mock data, air quality, GitHub issues
- **communication/**: Email, messaging
- **food/**: Product nutrition, recipes
