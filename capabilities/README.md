# MCP Gateway Starter Capabilities

34 curated capabilities for AI enthusiasts and home users. Mix of zero-config (17) and free-tier APIs (17).

## Categories

| Category | Count | Auth Required |
|----------|-------|---------------|
| **knowledge/** | 11 | None |
| **search/** | 11 | API key (Brave: 2K/mo free) |
| **finance/** | 4 | API key (free tiers) |
| **geo/** | 1 | API key (50K/mo free) |
| **entertainment/** | 3 | API key / OAuth2 |
| **utility/** | 4 | Mixed |

## Zero-Config (Works Instantly)

These 17 capabilities need no API keys:

```
knowledge/weather.yaml          # Open-Meteo
knowledge/wikipedia_*.yaml      # Wikipedia (2)
knowledge/nominatim_*.yaml      # OpenStreetMap (2)
knowledge/timezone_convert.yaml # Local
knowledge/open_library_book.yaml
knowledge/npm_package.yaml
knowledge/pypi_package.yaml
knowledge/hackernews_*.yaml     # (2)
search/reddit_search.yaml
search/youtube_transcript.yaml
finance/sec_edgar_filings.yaml
utility/air_quality.yaml        # OpenAQ
utility/qr_generate.yaml        # GoQR
search/github_search.yaml       # 60/hr unauthenticated
```

## Free Tier (2-min Signup)

| Capability | Service | Free Tier | Signup |
|------------|---------|-----------|--------|
| `brave_*` (8) | Brave Search | 2,000/mo | brave.com/search/api |
| `stock_quote` | Alpha Vantage | 25/day | alphavantage.co |
| `finnhub_quote` | Finnhub | 60/min | finnhub.io |
| `exchangerate_convert` | ExchangeRate | 1,500/mo | exchangerate-api.com |
| `ipinfo_lookup` | IPinfo | 50,000/mo | ipinfo.io |
| `tmdb_*` (2) | TMDB | Unlimited | themoviedb.org |
| `spotify_search` | Spotify | Unlimited | developer.spotify.com |
| `recipe_search` | Spoonacular | 150/day | spoonacular.com |
| `package_track` | 17track | 100/day | api.17track.net |

## Configuration

Set environment variables for API keys:

```bash
# Search
export BRAVE_API_KEY="your-key"

# Finance
export ALPHA_VANTAGE_API_KEY="your-key"
export FINNHUB_API_KEY="your-key"
export EXCHANGERATE_API_KEY="your-key"

# Geo
export IPINFO_TOKEN="your-key"

# Entertainment
export TMDB_API_KEY="your-key"
export SPOTIFY_CLIENT_ID="your-id"
export SPOTIFY_CLIENT_SECRET="your-secret"

# Utility
export SPOONACULAR_API_KEY="your-key"
export 17TRACK_API_KEY="your-key"

# Optional (increases rate limit)
export GITHUB_TOKEN="your-token"
```

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
    service: service_name
    config:
      endpoint: https://api.example.com/v1/endpoint
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
