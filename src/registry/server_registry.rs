//! Static curated registry of popular MCP servers.
//!
//! Provides compile-time metadata for ~50 well-known MCP servers so commands
//! like `mcp-gateway add <name>` can bootstrap a backend entry without the
//! user needing to know the exact `npx` incantation or required env vars.
//!
//! # Examples
//!
//! ```rust
//! use mcp_gateway::registry::server_registry;
//!
//! let entry = server_registry::lookup("tavily").unwrap();
//! assert_eq!(entry.category, "search");
//!
//! let results = server_registry::search("database");
//! assert!(!results.is_empty());
//!
//! let all = server_registry::all();
//! assert!(all.len() >= 40);
//! ```

/// Transport type for a registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Launched via a child process (npx / binary).
    Stdio,
    /// Connected via HTTP; carries a default URL that works out of the box.
    Http {
        /// The default HTTP URL to use when none is configured.
        default_url: &'static str,
    },
}

/// A single entry in the curated MCP server registry.
#[derive(Debug, Clone, Copy)]
pub struct RegistryEntry {
    /// Short identifier used to look up this entry (e.g. `"tavily"`).
    pub name: &'static str,
    /// Human-readable description shown in `add` and `setup` output.
    pub description: &'static str,
    /// The shell command (or `npx` incantation) used to launch the server.
    pub command: &'static str,
    /// Environment variables that **must** be set for the server to function.
    pub required_env: &'static [&'static str],
    /// Environment variables that are optional but may enhance functionality.
    pub optional_env: &'static [&'static str],
    /// Transport mechanism for this server.
    pub transport: Transport,
    /// Functional category (e.g. `"search"`, `"filesystem"`, `"database"`).
    pub category: &'static str,
    /// Project homepage or npm registry URL.
    pub homepage: &'static str,
}

// ── Static registry data ──────────────────────────────────────────────────────

static REGISTRY: &[RegistryEntry] = &[
    // ── search ────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "tavily",
        description: "Web search and content extraction via the Tavily AI search API",
        command: "npx -y @anthropic/mcp-server-tavily",
        required_env: &["TAVILY_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://www.npmjs.com/package/@anthropic/mcp-server-tavily",
    },
    RegistryEntry {
        name: "brave-search",
        description: "Web and local search using the Brave Search API",
        command: "npx -y @anthropic/mcp-server-brave-search",
        required_env: &["BRAVE_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://www.npmjs.com/package/@anthropic/mcp-server-brave-search",
    },
    RegistryEntry {
        name: "exa",
        description: "Neural web search and content crawling via Exa AI",
        command: "npx -y exa-mcp-server",
        required_env: &["EXA_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://www.npmjs.com/package/exa-mcp-server",
    },
    RegistryEntry {
        name: "perplexity",
        description: "AI-powered research search via Perplexity API",
        command: "npx -y @perplexity-ai/mcp-server",
        required_env: &["PERPLEXITY_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://www.npmjs.com/package/@perplexity-ai/mcp-server",
    },
    // ── filesystem ────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "filesystem",
        description: "Read, write, and navigate the local file system",
        command: "npx -y @modelcontextprotocol/server-filesystem",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "filesystem",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-filesystem",
    },
    RegistryEntry {
        name: "everything-search",
        description: "Fast file search on Windows via the Everything search engine",
        command: "npx -y @modelcontextprotocol/server-everything",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "filesystem",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-everything",
    },
    // ── database ──────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "postgres",
        description: "Query and inspect PostgreSQL databases via natural language",
        command: "npx -y @modelcontextprotocol/server-postgres",
        required_env: &["POSTGRES_URL"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-postgres",
    },
    RegistryEntry {
        name: "sqlite",
        description: "Read and write SQLite database files",
        command: "npx -y @modelcontextprotocol/server-sqlite",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-sqlite",
    },
    RegistryEntry {
        name: "surrealdb",
        description: "Multi-model database queries via SurrealDB",
        command: "npx -y @surrealdb/mcp-server",
        required_env: &["SURREAL_URL"],
        optional_env: &["SURREAL_USER", "SURREAL_PASS", "SURREAL_NS", "SURREAL_DB"],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://www.npmjs.com/package/@surrealdb/mcp-server",
    },
    RegistryEntry {
        name: "mysql",
        description: "Query MySQL and MariaDB databases",
        command: "npx -y @benborla29/mcp-server-mysql",
        required_env: &["MYSQL_HOST", "MYSQL_USER", "MYSQL_PASS", "MYSQL_DB"],
        optional_env: &["MYSQL_PORT"],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://www.npmjs.com/package/@benborla29/mcp-server-mysql",
    },
    RegistryEntry {
        name: "redis",
        description: "Interact with Redis key-value stores",
        command: "npx -y @modelcontextprotocol/server-redis",
        required_env: &[],
        optional_env: &["REDIS_URL"],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-redis",
    },
    // ── dev-tools ─────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "github",
        description: "GitHub repos, issues, PRs, code search, and file browsing",
        command: "npx -y @modelcontextprotocol/server-github",
        required_env: &["GITHUB_TOKEN"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "dev-tools",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-github",
    },
    RegistryEntry {
        name: "gitlab",
        description: "GitLab projects, issues, MRs, and CI pipelines",
        command: "npx -y @modelcontextprotocol/server-gitlab",
        required_env: &["GITLAB_TOKEN"],
        optional_env: &["GITLAB_URL"],
        transport: Transport::Stdio,
        category: "dev-tools",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-gitlab",
    },
    RegistryEntry {
        name: "linear",
        description: "Linear project management: issues, cycles, and roadmaps",
        command: "npx -y @modelcontextprotocol/server-linear",
        required_env: &["LINEAR_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "dev-tools",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-linear",
    },
    RegistryEntry {
        name: "sentry",
        description: "Sentry error tracking, issues, and release data",
        command: "npx -y @modelcontextprotocol/server-sentry",
        required_env: &["SENTRY_AUTH_TOKEN", "SENTRY_ORG"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "dev-tools",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-sentry",
    },
    RegistryEntry {
        name: "jira",
        description: "Jira issues, sprints, and project management",
        command: "npx -y @atlassian/jira-mcp-server",
        required_env: &["JIRA_API_TOKEN", "JIRA_EMAIL", "JIRA_HOST"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "dev-tools",
        homepage: "https://www.npmjs.com/package/@atlassian/jira-mcp-server",
    },
    RegistryEntry {
        name: "asana",
        description: "Asana tasks, projects, and workspace management",
        command: "npx -y @modelcontextprotocol/server-asana",
        required_env: &["ASANA_ACCESS_TOKEN"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "dev-tools",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-asana",
    },
    // ── cloud ─────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "aws",
        description: "AWS resource exploration via CloudControl and AWS CLI",
        command: "npx -y @modelcontextprotocol/server-aws",
        required_env: &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        optional_env: &["AWS_REGION", "AWS_SESSION_TOKEN"],
        transport: Transport::Stdio,
        category: "cloud",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-aws",
    },
    RegistryEntry {
        name: "cloudflare-workers",
        description: "Deploy and manage Cloudflare Workers, KV, and D1",
        command: "npx -y @cloudflare/mcp-server-cloudflare",
        required_env: &["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "cloud",
        homepage: "https://www.npmjs.com/package/@cloudflare/mcp-server-cloudflare",
    },
    RegistryEntry {
        name: "gcp",
        description: "Google Cloud Platform resource management",
        command: "npx -y @modelcontextprotocol/server-gcp",
        required_env: &["GOOGLE_APPLICATION_CREDENTIALS"],
        optional_env: &["GCP_PROJECT"],
        transport: Transport::Stdio,
        category: "cloud",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-gcp",
    },
    // ── memory ────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "memory",
        description: "Persistent key-value memory store for agents",
        command: "npx -y @modelcontextprotocol/server-memory",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "memory",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-memory",
    },
    RegistryEntry {
        name: "pieces",
        description: "Pieces OS long-term memory and developer context management",
        command: "npx -y @pieces.app/mcp-server",
        required_env: &[],
        optional_env: &["PIECES_PORT"],
        transport: Transport::Stdio,
        category: "memory",
        homepage: "https://www.npmjs.com/package/@pieces.app/mcp-server",
    },
    // ── communication ─────────────────────────────────────────────────────────
    RegistryEntry {
        name: "slack",
        description: "Post messages, read channels, and search Slack workspaces",
        command: "npx -y @modelcontextprotocol/server-slack",
        required_env: &["SLACK_BOT_TOKEN"],
        optional_env: &["SLACK_TEAM_ID"],
        transport: Transport::Stdio,
        category: "communication",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-slack",
    },
    RegistryEntry {
        name: "discord",
        description: "Discord channel messages and guild management",
        command: "npx -y @modelcontextprotocol/server-discord",
        required_env: &["DISCORD_TOKEN"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "communication",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-discord",
    },
    RegistryEntry {
        name: "gmail",
        description: "Read, compose, and manage Gmail messages and drafts",
        command: "npx -y @modelcontextprotocol/server-gmail",
        required_env: &[
            "GMAIL_CLIENT_ID",
            "GMAIL_CLIENT_SECRET",
            "GMAIL_REFRESH_TOKEN",
        ],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "communication",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-gmail",
    },
    RegistryEntry {
        name: "google-calendar",
        description: "Create and query Google Calendar events",
        command: "npx -y @modelcontextprotocol/server-google-calendar",
        required_env: &[
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_REFRESH_TOKEN",
        ],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "communication",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-google-calendar",
    },
    // ── knowledge ─────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "context7",
        description: "Up-to-date library documentation via Context7 (HTTP)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://mcp.context7.com/mcp",
        },
        category: "knowledge",
        homepage: "https://context7.com",
    },
    RegistryEntry {
        name: "puppeteer",
        description: "Headless browser automation: navigate, screenshot, and scrape",
        command: "npx -y @modelcontextprotocol/server-puppeteer",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "knowledge",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-puppeteer",
    },
    RegistryEntry {
        name: "fetch",
        description: "Fetch any HTTP URL and return its contents",
        command: "npx -y @modelcontextprotocol/server-fetch",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "knowledge",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-fetch",
    },
    RegistryEntry {
        name: "wikipedia",
        description: "Search and retrieve Wikipedia articles",
        command: "npx -y @modelcontextprotocol/server-wikipedia",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "knowledge",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-wikipedia",
    },
    // ── code ──────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "sequential-thinking",
        description: "Structured multi-step reasoning and problem decomposition",
        command: "npx -y @modelcontextprotocol/server-sequential-thinking",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "code",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-sequential-thinking",
    },
    RegistryEntry {
        name: "semgrep",
        description: "Static analysis and security scanning via Semgrep",
        command: "npx -y @semgrep/mcp-server",
        required_env: &["SEMGREP_APP_TOKEN"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "code",
        homepage: "https://www.npmjs.com/package/@semgrep/mcp-server",
    },
    RegistryEntry {
        name: "playwright",
        description: "Cross-browser end-to-end test automation via Playwright",
        command: "npx -y @modelcontextprotocol/server-playwright",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "code",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-playwright",
    },
    // ── productivity ──────────────────────────────────────────────────────────
    RegistryEntry {
        name: "notion",
        description: "Read and write Notion pages, databases, and workspaces",
        command: "npx -y @modelcontextprotocol/server-notion",
        required_env: &["NOTION_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "productivity",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-notion",
    },
    RegistryEntry {
        name: "google-drive",
        description: "Browse, read, and search Google Drive files",
        command: "npx -y @modelcontextprotocol/server-gdrive",
        required_env: &[
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_REFRESH_TOKEN",
        ],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "productivity",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-gdrive",
    },
    RegistryEntry {
        name: "google-sheets",
        description: "Read and write Google Sheets spreadsheets",
        command: "npx -y @modelcontextprotocol/server-google-sheets",
        required_env: &[
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_REFRESH_TOKEN",
        ],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "productivity",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-google-sheets",
    },
    RegistryEntry {
        name: "airtable",
        description: "Query and update Airtable bases and tables",
        command: "npx -y @airtable/mcp-server",
        required_env: &["AIRTABLE_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "productivity",
        homepage: "https://www.npmjs.com/package/@airtable/mcp-server",
    },
    // ── finance ───────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "stripe",
        description: "Stripe payments, customers, invoices, and subscriptions",
        command: "npx -y @stripe/mcp-server",
        required_env: &["STRIPE_SECRET_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "finance",
        homepage: "https://www.npmjs.com/package/@stripe/mcp-server",
    },
    // ── ai-tools ──────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "openai",
        description: "OpenAI GPT models and embeddings via the OpenAI API",
        command: "npx -y @openai/mcp-server",
        required_env: &["OPENAI_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "ai-tools",
        homepage: "https://www.npmjs.com/package/@openai/mcp-server",
    },
    // ── monitoring ────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "datadog",
        description: "Datadog metrics, logs, dashboards, and monitors",
        command: "npx -y @datadog/mcp-server",
        required_env: &["DD_API_KEY", "DD_APP_KEY"],
        optional_env: &["DD_SITE"],
        transport: Transport::Stdio,
        category: "monitoring",
        homepage: "https://www.npmjs.com/package/@datadog/mcp-server",
    },
    RegistryEntry {
        name: "pagerduty",
        description: "PagerDuty incidents, schedules, and on-call management",
        command: "npx -y @modelcontextprotocol/server-pagerduty",
        required_env: &["PAGERDUTY_TOKEN"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "monitoring",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-pagerduty",
    },
    // ── data ──────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "bigquery",
        description: "Run queries on Google BigQuery datasets",
        command: "npx -y @modelcontextprotocol/server-bigquery",
        required_env: &["GOOGLE_APPLICATION_CREDENTIALS", "BIGQUERY_PROJECT"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "data",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-bigquery",
    },
    RegistryEntry {
        name: "snowflake",
        description: "Query Snowflake data warehouses",
        command: "npx -y @modelcontextprotocol/server-snowflake",
        required_env: &["SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD"],
        optional_env: &["SNOWFLAKE_DATABASE", "SNOWFLAKE_WAREHOUSE"],
        transport: Transport::Stdio,
        category: "data",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-snowflake",
    },
    // ── vector-db ─────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "pinecone",
        description: "Pinecone vector database for semantic search and embeddings",
        command: "npx -y @modelcontextprotocol/server-pinecone",
        required_env: &["PINECONE_API_KEY"],
        optional_env: &["PINECONE_ENVIRONMENT"],
        transport: Transport::Stdio,
        category: "vector-db",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-pinecone",
    },
    RegistryEntry {
        name: "qdrant",
        description: "Qdrant vector search engine",
        command: "npx -y @modelcontextprotocol/server-qdrant",
        required_env: &[],
        optional_env: &["QDRANT_URL", "QDRANT_API_KEY"],
        transport: Transport::Stdio,
        category: "vector-db",
        homepage: "https://www.npmjs.com/package/@modelcontextprotocol/server-qdrant",
    },
    // ── security ──────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "1password",
        description: "1Password secrets and vault item lookup (CLI required)",
        command: "npx -y @1password/mcp-server",
        required_env: &["OP_SERVICE_ACCOUNT_TOKEN"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "security",
        homepage: "https://www.npmjs.com/package/@1password/mcp-server",
    },
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the registry entry for the given name, or `None` if not found.
///
/// Lookup is case-insensitive and checks exact name matches only.
#[must_use]
pub fn lookup(name: &str) -> Option<&'static RegistryEntry> {
    let lower = name.to_lowercase();
    REGISTRY
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(&lower))
}

/// Search the registry by matching `query` against name, description, and category.
///
/// The comparison is case-insensitive substring matching. Results are returned
/// in registry definition order.
#[must_use]
pub fn search(query: &str) -> Vec<&'static RegistryEntry> {
    let lower = query.to_lowercase();
    REGISTRY
        .iter()
        .filter(|e| {
            e.name.to_lowercase().contains(&lower)
                || e.description.to_lowercase().contains(&lower)
                || e.category.to_lowercase().contains(&lower)
        })
        .collect()
}

/// Return all registry entries in definition order.
#[must_use]
pub fn all() -> &'static [RegistryEntry] {
    REGISTRY
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_non_empty_slice() {
        // GIVEN: the static registry
        // WHEN: all() is called
        // THEN: the result contains at least 40 entries
        assert!(
            all().len() >= 40,
            "Expected at least 40 entries, got {}",
            all().len()
        );
    }

    #[test]
    fn lookup_known_name_returns_entry() {
        // GIVEN: a server known to be in the registry
        // WHEN: looking up by exact name
        // THEN: the correct entry is returned
        let entry = lookup("tavily").expect("tavily must be in registry");
        assert_eq!(entry.name, "tavily");
        assert_eq!(entry.category, "search");
        assert!(entry.required_env.contains(&"TAVILY_API_KEY"));
    }

    #[test]
    fn lookup_is_case_insensitive() {
        // GIVEN: the registry has "github"
        // WHEN: looking up with uppercase letters
        // THEN: the entry is still found
        assert!(lookup("GitHub").is_some());
        assert!(lookup("GITHUB").is_some());
    }

    #[test]
    fn lookup_unknown_name_returns_none() {
        // GIVEN: a name that does not exist in the registry
        // WHEN: looking it up
        // THEN: None is returned
        assert!(lookup("definitely-not-a-real-mcp-server").is_none());
    }

    #[test]
    fn search_by_category_returns_matching_entries() {
        // GIVEN: the registry contains multiple "database" category entries
        // WHEN: searching for "database"
        // THEN: all entries with category == "database" are included in the results
        //       (search also matches on name/description so results may include more)
        let results = search("database");
        assert!(
            results.len() >= 2,
            "Expected at least 2 entries matching 'database', got {}",
            results.len()
        );
        // All dedicated database-category servers must be present.
        let database_entries: Vec<_> = all().iter().filter(|e| e.category == "database").collect();
        for db_entry in database_entries {
            assert!(
                results.iter().any(|r| r.name == db_entry.name),
                "database-category entry '{}' missing from search results",
                db_entry.name
            );
        }
    }

    #[test]
    fn search_by_description_term_returns_matching_entries() {
        // GIVEN: entries with "memory" in their descriptions
        // WHEN: searching "memory"
        // THEN: at least the memory server is returned
        let results = search("memory");
        assert!(
            results.iter().any(|e| e.name == "memory"),
            "expected 'memory' entry in search results"
        );
    }

    #[test]
    fn search_empty_query_returns_all() {
        // GIVEN: an empty query matches every entry
        // WHEN: searching ""
        // THEN: all entries are returned
        assert_eq!(search("").len(), all().len());
    }

    #[test]
    fn context7_has_http_transport() {
        // GIVEN: context7 is an HTTP-only server
        // WHEN: looking it up
        // THEN: its transport is Http with a non-empty default URL
        let entry = lookup("context7").expect("context7 must be in registry");
        match entry.transport {
            Transport::Http { default_url } => assert!(!default_url.is_empty()),
            Transport::Stdio => panic!("expected Http transport for context7"),
        }
    }

    #[test]
    fn all_stdio_entries_have_non_empty_command() {
        // GIVEN: every stdio entry must have a launchable command
        // WHEN: iterating all entries
        // THEN: none have an empty command string
        for entry in all() {
            if let Transport::Stdio = entry.transport {
                assert!(
                    !entry.command.is_empty(),
                    "{} has Stdio transport but empty command",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn registry_names_are_unique() {
        // GIVEN: names must be unique for lookup to be unambiguous
        let mut seen = std::collections::HashSet::new();
        for entry in all() {
            assert!(
                seen.insert(entry.name),
                "duplicate name in registry: {}",
                entry.name
            );
        }
    }
}
