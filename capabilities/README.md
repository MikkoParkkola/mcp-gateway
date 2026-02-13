# MCP Gateway Starter Capabilities

52+ curated capabilities for AI enthusiasts and home users. Mix of zero-config (30+) and free-tier APIs (20+).

## Categories

| Category | Count | Auth Required |
|----------|-------|---------------|
| **knowledge/** | 17 | None |
| **search/** | 11 | API key (Brave: 2K/mo free) |
| **finance/** | 8 | API key (free tiers) |
| **geo/** | 1 | API key (50K/mo free) |
| **entertainment/** | 7 | None / API key / OAuth2 |
| **utility/** | 8 | None / API key |
| **communication/** | 2 | OAuth2 |
| **food/** | 1 | None |

## Zero-Config (Works Instantly)

These 30+ capabilities need no API keys:

```
knowledge/weather.yaml          # Open-Meteo
knowledge/weather_current.yaml  # Current weather
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
knowledge/semantic_scholar.yaml # Academic papers

search/reddit_search.yaml
search/github_search.yaml       # 60/hr unauthenticated

finance/sec_edgar_filings.yaml  # SEC EDGAR (free gov data)

entertainment/random_joke.yaml   # JokeAPI
entertainment/trivia_question.yaml # Open Trivia DB
entertainment/random_quote.yaml  # Quotable
entertainment/musicbrainz_search.yaml # Music database

utility/air_quality.yaml        # OpenAQ
utility/qr_generate.yaml        # GoQR
utility/random_user.yaml        # Random User Generator
utility/uuid_generate.yaml      # UUID Tools
utility/recipe_search.yaml      # Recipe API
utility/github_create_issue.yaml # GitHub (no auth)

food/openfoodfacts_product.yaml # Product nutrition data
```

## Free Tier (2-min Signup)

| Capability | Service | Free Tier | Signup |
|------------|---------|-----------|--------|
| `brave_*` (8) | Brave Search | 2,000/mo | brave.com/search/api |
| `stock_quote` | Alpha Vantage | 25/day | alphavantage.co |
| `yahoo_stock_quote` | Yahoo Finance | Unlimited | No key needed |
| `finnhub_quote` | Finnhub | 60/min | finnhub.io |
| `ecb_exchange_rates` | ECB | Unlimited | ecb.europa.eu |
| `exchangerate_convert` | ExchangeRate | 1,500/mo | exchangerate-api.com |
| `stripe_list_charges` | Stripe | API access | stripe.com |
| `prh_company` | PRH Finland | Unlimited | avoindata.prh.fi |
| `ipinfo_lookup` | IPinfo | 50,000/mo | ipinfo.io |
| `tmdb_*` (2) | TMDB | Unlimited | themoviedb.org |
| `spotify_search` | Spotify | Unlimited | developer.spotify.com |
| `package_track` | 17track | 100/day | api.17track.net |
| `gmail_send_email` | Gmail | OAuth2 | Google API Console |
| `slack_post_message` | Slack | OAuth2 | api.slack.com |

## Configuration

Set environment variables for API keys:

```bash
# Search
export BRAVE_API_KEY="your-key"

# Finance
export ALPHA_VANTAGE_API_KEY="your-key"
export FINNHUB_API_KEY="your-key"
export EXCHANGERATE_API_KEY="your-key"
export STRIPE_API_KEY="your-key"

# Geo
export IPINFO_TOKEN="your-key"

# Entertainment
export TMDB_API_KEY="your-key"
export SPOTIFY_CLIENT_ID="your-id"
export SPOTIFY_CLIENT_SECRET="your-secret"

# Utility
export 17TRACK_API_KEY="your-key"

# Communication (OAuth2)
export GMAIL_CLIENT_ID="your-id"
export GMAIL_CLIENT_SECRET="your-secret"
export SLACK_BOT_TOKEN="your-token"

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

- **knowledge/**: Reference data, facts, geocoding, academic papers
- **search/**: Web, news, images, code search
- **finance/**: Stock quotes, currency exchange, SEC filings, company data
- **geo/**: IP geolocation
- **entertainment/**: Movies, music, jokes, trivia
- **utility/**: QR codes, UUIDs, mock data, air quality, GitHub issues
- **communication/**: Email, messaging
- **food/**: Product nutrition, recipes
