# MCP Gateway Starter Capabilities

42 curated capabilities for AI enthusiasts and home users. Mix of zero-config (25) and free-tier APIs (17).

## Categories

| Category | Count | Auth Required |
|----------|-------|---------------|
| **knowledge/** | 14 | None |
| **search/** | 11 | API key (Brave: 2K/mo free) |
| **finance/** | 4 | API key (free tiers) |
| **geo/** | 1 | API key (50K/mo free) |
| **entertainment/** | 6 | None / API key / OAuth2 |
| **utility/** | 6 | None / API key |

## Zero-Config (Works Instantly)

These 25 capabilities need no API keys:

```
knowledge/weather.yaml          # Open-Meteo
knowledge/wikipedia_*.yaml      # Wikipedia (2)
knowledge/nominatim_*.yaml      # OpenStreetMap (2)
knowledge/timezone_convert.yaml # Local
knowledge/open_library_book.yaml
knowledge/npm_package.yaml
knowledge/pypi_package.yaml
knowledge/hackernews_*.yaml     # (2)
knowledge/country_info.yaml     # RestCountries
knowledge/public_holidays.yaml  # Nager.Date
knowledge/number_facts.yaml     # Numbers API

search/reddit_search.yaml
search/youtube_transcript.yaml
search/github_search.yaml       # 60/hr unauthenticated

finance/sec_edgar_filings.yaml  # SEC EDGAR (free gov data)

entertainment/random_joke.yaml   # JokeAPI
entertainment/trivia_question.yaml # Open Trivia DB
entertainment/random_quote.yaml  # Quotable

utility/air_quality.yaml        # OpenAQ
utility/qr_generate.yaml        # GoQR
utility/random_user.yaml        # Random User Generator
utility/uuid_generate.yaml      # UUID Tools
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

- **knowledge/**: Reference data, facts, geocoding
- **search/**: Web, news, images, code search
- **finance/**: Stock quotes, currency exchange, SEC filings
- **geo/**: IP geolocation
- **entertainment/**: Movies, music, jokes, trivia
- **utility/**: QR codes, UUIDs, mock data, air quality
