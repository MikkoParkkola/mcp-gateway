# Community Registry

Share, discover, and install capability definitions from the community.

## Installing Capabilities

### From the Built-in Registry

All 52+ capabilities ship with mcp-gateway. Browse what is available:

```bash
# List everything
mcp-gateway cap registry-list

# Search by keyword
mcp-gateway cap search weather
mcp-gateway cap search finance
```

### From GitHub

Install a capability from any GitHub repository that follows the standard layout:

```bash
# Install from the official repository
mcp-gateway cap install stock_quote --from-github

# Install from a community repository
mcp-gateway cap install my_tool --from-github --repo owner/repo

# Install from a specific branch
mcp-gateway cap install my_tool --from-github --repo owner/repo --branch develop

# Install to a custom directory
mcp-gateway cap install my_tool --from-github --output ./my-capabilities
```

The installer looks for the capability YAML in standard category subdirectories (`finance/`, `knowledge/`, `search/`, `utility/`, `entertainment/`, `communication/`, `food/`, `geo/`) within the repository's `capabilities/` directory.

## Creating a Capability

### YAML Template

Every capability is a single YAML file following the Fulcrum 1.0 schema:

```yaml
fulcrum: "1.0"
name: your_capability_name
description: Short, clear description of what this capability does

schema:
  input:
    type: object
    properties:
      param1:
        type: string
        description: What this parameter controls
      param2:
        type: number
        description: Numeric value for something
    required: [param1]
  output:
    type: object
    properties:
      result:
        type: string

providers:
  primary:
    service: rest
    cost_per_call: 0
    timeout: 30
    config:
      base_url: https://api.example.com
      path: /v1/endpoint
      method: GET
      params:
        q: "{param1}"
        limit: "{param2}"

cache:
  strategy: exact
  ttl: 300

auth:
  required: false
  # If auth is required:
  # required: true
  # type: bearer        # or api_key, oauth2
  # key: env:API_TOKEN  # environment variable reference
  # description: "Get your API key at https://example.com/keys"

metadata:
  category: utility     # knowledge, search, finance, geo, entertainment, communication, food, utility
  tags: [tag1, tag2]
  cost_category: free   # free, cheap, paid
  execution_time: fast  # fast, medium, slow
  read_only: true       # true for GET/HEAD, false for mutations
```

### Required Fields

| Field | Description |
|-------|-------------|
| `fulcrum` | Schema version, always `"1.0"` |
| `name` | Unique snake_case identifier |
| `description` | What the capability does (shown in search results) |
| `schema.input` | JSON Schema for parameters the AI provides |
| `providers.primary` | At least one provider with service type and config |
| `auth` | Whether authentication is required |
| `metadata.category` | One of the standard categories |

### Validate Before Sharing

```bash
mcp-gateway cap validate your_capability.yaml
```

This checks all required fields, schema validity, and provider configuration.

### Test Locally

```bash
mcp-gateway cap test your_capability.yaml --args '{"param1": "test"}'
```

## Sharing via GitHub

### Repository Layout

Your repository should place capabilities under `capabilities/<category>/`:

```
your-repo/
  capabilities/
    finance/
      my_stock_tool.yaml
    utility/
      my_converter.yaml
  README.md
```

This layout is required for `mcp-gateway cap install --from-github` to find your capabilities automatically.

### Step-by-Step

1. **Create** your capability YAML and validate it locally.

2. **Organize** it under the correct category directory:
   ```bash
   mkdir -p capabilities/utility
   cp my_tool.yaml capabilities/utility/
   ```

3. **Push** to a public GitHub repository.

4. **Test** the install flow:
   ```bash
   mcp-gateway cap install my_tool --from-github --repo your-username/your-repo
   ```

5. **Share** the install command with others:
   ```
   mcp-gateway cap install my_tool --from-github --repo your-username/your-repo
   ```

## Submitting to the Official Registry

The official registry lives in the [MikkoParkkola/mcp-gateway](https://github.com/MikkoParkkola/mcp-gateway) repository under `capabilities/`.

### Submission Criteria

- Capability must validate: `mcp-gateway cap validate your_capability.yaml`
- Capability must test successfully: `mcp-gateway cap test your_capability.yaml --args '{...}'`
- Free-tier or zero-config APIs are preferred (no paid-only capabilities)
- Name must be unique (check with `mcp-gateway cap search your_name`)
- Description must be clear and concise
- Correct `metadata.category` and meaningful `tags`
- `auth.description` must include signup URL if a key is required

### Pull Request Process

1. **Fork** the repository on GitHub.

2. **Add** your capability YAML to the correct category:
   ```bash
   cp my_tool.yaml capabilities/<category>/
   ```

3. **Validate** the full registry still loads:
   ```bash
   mcp-gateway cap list capabilities/
   ```

4. **Open a PR** with:
   - Title: `cap: add <capability_name>`
   - Description: what the API does, free tier details, example usage
   - The `mcp-gateway cap test` output demonstrating it works

5. **CI checks** will verify:
   - YAML parses correctly
   - Schema validation passes
   - No duplicate names

### Example PR Description

```markdown
## Add `openweathermap_forecast` capability

**API**: OpenWeatherMap One Call 3.0
**Free tier**: 1,000 calls/day
**Auth**: API key (free signup at openweathermap.org)

### Test output
$ mcp-gateway cap test capabilities/knowledge/openweathermap_forecast.yaml \
    --args '{"lat": 60.17, "lon": 24.94}'
Success:
{
  "temp": 5.2,
  "description": "partly cloudy"
}
```

## Categories Reference

| Category | Directory | Use For |
|----------|-----------|---------|
| `knowledge` | `capabilities/knowledge/` | Reference data, facts, geocoding, academic |
| `search` | `capabilities/search/` | Web, news, images, code search |
| `finance` | `capabilities/finance/` | Stock quotes, currency, filings, company data |
| `geo` | `capabilities/geo/` | IP geolocation, mapping |
| `entertainment` | `capabilities/entertainment/` | Movies, music, jokes, trivia |
| `utility` | `capabilities/utility/` | QR codes, UUIDs, mock data, tracking |
| `communication` | `capabilities/communication/` | Email, messaging |
| `food` | `capabilities/food/` | Nutrition, recipes |
