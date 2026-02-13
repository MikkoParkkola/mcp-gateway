# OpenAPI Import

Convert any OpenAPI 3.0/3.1 (or Swagger 2.0) specification into gateway capability YAML files.

## Quick Start

```bash
# Import from a local file
mcp-gateway cap import openapi.yaml

# Import with a name prefix and auth
mcp-gateway cap import openapi.json --prefix stripe --auth-key env:STRIPE_API_KEY

# Write to a custom output directory
mcp-gateway cap import petstore.yaml --output capabilities/petstore
```

## How It Works

The importer reads an OpenAPI spec and generates one capability YAML file per operation (path + method combination). Each generated file is a self-contained capability definition ready for the gateway to load.

```
OpenAPI spec (YAML/JSON)
  |
  v
+------------------------------+
| For each path + method:      |
|  - Extract operationId/name  |
|  - Build input schema        |
|  - Build output schema       |
|  - Map parameters & body     |
|  - Detect auth requirements  |
|  - Apply cache defaults      |
+------------------------------+
  |
  v
capabilities/<name>.yaml (one per operation)
```

## Supported Formats

| Format | Extensions | Detection |
|--------|-----------|-----------|
| OpenAPI 3.0 | `.yaml`, `.yml`, `.json` | `openapi: "3.0.x"` field |
| OpenAPI 3.1 | `.yaml`, `.yml`, `.json` | `openapi: "3.1.x"` field |
| Swagger 2.0 | `.yaml`, `.yml`, `.json` | `swagger: "2.0"` field |

The importer tries YAML parsing first, then falls back to JSON, so the file extension does not matter.

## CLI Reference

```
mcp-gateway cap import [OPTIONS] <SPEC>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `<SPEC>` | Yes | Path to an OpenAPI specification file (YAML or JSON) |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output <DIR>` | `capabilities` | Output directory for generated capability files |
| `-p, --prefix <PREFIX>` | None | Prefix prepended to every generated capability name |
| `--auth-key <KEY>` | None | Default auth key reference (e.g. `env:API_TOKEN`) |

## Examples

### Basic Import

Given a `petstore.yaml` with three endpoints (`GET /pets`, `POST /pets`, `GET /pets/{id}`):

```bash
mcp-gateway cap import petstore.yaml
```

Output:

```
Generated 3 capabilities from petstore.yaml

  listpets.yaml
  createpets.yaml
  showpetbyid.yaml

Capabilities written to capabilities/
```

### With Prefix

Prefix avoids name collisions when importing multiple APIs:

```bash
mcp-gateway cap import stripe-openapi.json --prefix stripe
```

This generates names like `stripe_listcharges`, `stripe_createpayment`, etc.

### With Authentication

When the spec declares security schemes, the importer marks capabilities as requiring auth. You can supply a default credential reference:

```bash
mcp-gateway cap import api.yaml --auth-key env:MY_API_TOKEN
```

This sets `auth.type: bearer` and `auth.key: env:MY_API_TOKEN` on every generated capability.

### Custom Output Directory

Organize imported capabilities separately:

```bash
mcp-gateway cap import api.yaml --output capabilities/my-service
```

The directory is created automatically if it does not exist.

## What Gets Generated

Each generated capability YAML contains:

```yaml
# Auto-generated from OpenAPI spec
# Get a user by ID

fulcrum: "1.0"
name: getuser
description: Get a user by ID

schema:
  input:
    type: object
    properties:
      id:
        type: string
    required:
      - id
  output:
    type: object
    properties:
      id:
        type: string
      name:
        type: string

providers:
  primary:
    service: rest
    cost_per_call: 0
    timeout: 30
    config:
      base_url: https://api.test.com
      path: /users/{id}
      method: GET

cache:
  strategy: exact
  ttl: 300

auth:
  required: false

metadata:
  category: api
  tags: [openapi, generated]
  cost_category: unknown
  execution_time: medium
  read_only: true
```

### Mapping Rules

| OpenAPI Concept | Capability Field |
|----------------|-----------------|
| `operationId` | `name` (lowercased, cleaned) |
| `summary` / `description` | `description` |
| `servers[0].url` | `providers.primary.config.base_url` |
| Path string | `providers.primary.config.path` |
| HTTP method | `providers.primary.config.method` |
| `parameters` (query) | `providers.primary.config.params` |
| `parameters` (header) | `providers.primary.config.headers` |
| `requestBody` properties | Merged into `schema.input.properties` |
| `responses.200` schema | `schema.output` |
| `securitySchemes` present | `auth.required: true` |
| GET/HEAD methods | `metadata.read_only: true` |

### Name Generation

If the operation has an `operationId`, it is used as the capability name. Otherwise, the name is derived from the HTTP method and path:

```
GET /users/{id}  ->  get_users_id
POST /orders     ->  post_orders
```

Names are lowercased, non-alphanumeric characters are replaced with underscores, and consecutive underscores are collapsed.

## Post-Import Workflow

After importing, review and customize the generated files:

1. **Validate** each capability:
   ```bash
   mcp-gateway cap validate capabilities/getuser.yaml
   ```

2. **Test** with real arguments:
   ```bash
   mcp-gateway cap test capabilities/getuser.yaml --args '{"id": "123"}'
   ```

3. **Customize** as needed:
   - Adjust `cache.ttl` for frequently changing data
   - Add `response_path` to extract nested JSON fields
   - Tune `timeout` for slow endpoints
   - Set `cost_per_call` for metered APIs
   - Add body templates for POST/PUT operations

4. **Start the gateway** to serve the new capabilities:
   ```bash
   mcp-gateway -c gateway.yaml
   ```

## Limitations

- **Request bodies**: POST/PUT body templates are generated as placeholders. You need to fill in the actual `{param}` substitution template for your use case.
- **Complex schemas**: Deeply nested `$ref` schemas are not fully resolved. The importer works with inline schemas and single-level references.
- **Authentication**: Only bearer token auth is generated by default. For OAuth2, API key headers, or other schemes, edit the generated files.
- **Pagination**: Paginated endpoints are imported as single-call capabilities. Add cursor/offset logic manually if needed.
