// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Static curated registry of popular MCP servers.
//!
//! Provides compile-time metadata for well-known MCP servers so commands
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
//! assert!(all.len() >= 20);
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
    // ── search ──────────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "tavily",
        description: "Web search and content extraction via the Tavily AI search API",
        command: "npx -y tavily-mcp@0.2.22",
        required_env: &["TAVILY_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://github.com/tavily-ai/tavily-mcp",
    },
    RegistryEntry {
        name: "brave-search",
        description: "Web, news, image and local search using the Brave Search API",
        command: "npx -y @brave/brave-search-mcp-server@2.1.4",
        required_env: &["BRAVE_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://github.com/brave/brave-search-mcp-server",
    },
    RegistryEntry {
        name: "exa",
        description: "Neural web search and content crawling via Exa AI",
        command: "npx -y exa-mcp-server@3.4.1",
        required_env: &["EXA_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://github.com/exa-labs/exa-mcp-server",
    },
    RegistryEntry {
        name: "perplexity",
        description: "AI-powered research search via Perplexity API",
        command: "npx -y @perplexity-ai/mcp-server@1.3.0",
        required_env: &["PERPLEXITY_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "search",
        homepage: "https://github.com/perplexityai/modelcontextprotocol",
    },
    // ── filesystem ──────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "filesystem",
        description: "Read, write, and navigate the local file system (append the allowed directories)",
        command: "npx -y @modelcontextprotocol/server-filesystem@2026.8.31",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "filesystem",
        homepage: "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
    },
    // ── database ────────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "postgres",
        description: "Query, explain and tune PostgreSQL databases",
        command: "uvx postgres-mcp@0.3.0",
        required_env: &["DATABASE_URI"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://github.com/crystaldba/postgres-mcp",
    },
    RegistryEntry {
        name: "mysql",
        description: "Query MySQL and MariaDB databases",
        command: "npx -y @benborla29/mcp-server-mysql@2.0.9",
        required_env: &["MYSQL_HOST", "MYSQL_USER", "MYSQL_PASS", "MYSQL_DB"],
        optional_env: &["MYSQL_PORT"],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://github.com/benborla/mcp-server-mysql",
    },
    RegistryEntry {
        name: "redis",
        description: "Interact with Redis key-value stores",
        command: "uvx redis-mcp-server@0.5.1",
        required_env: &[],
        optional_env: &["REDIS_HOST", "REDIS_PORT", "REDIS_PWD", "REDIS_DB"],
        transport: Transport::Stdio,
        category: "database",
        homepage: "https://github.com/redis/mcp-redis",
    },
    // ── dev-tools ───────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "github",
        description: "GitHub repos, issues, PRs, code search, and Actions (GitHub-hosted)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://api.githubcopilot.com/mcp/",
        },
        category: "dev-tools",
        homepage: "https://github.com/github/github-mcp-server",
    },
    RegistryEntry {
        name: "gitlab",
        description: "GitLab projects, issues, merge requests, and pipelines (GitLab-hosted, OAuth)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://gitlab.com/api/v4/mcp",
        },
        category: "dev-tools",
        homepage: "https://docs.gitlab.com/user/gitlab_duo/model_context_protocol/mcp_server/",
    },
    RegistryEntry {
        name: "linear",
        description: "Linear issues, projects, and cycles (Linear-hosted, OAuth)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://mcp.linear.app/mcp",
        },
        category: "dev-tools",
        homepage: "https://linear.app/docs/mcp",
    },
    RegistryEntry {
        name: "sentry",
        description: "Sentry issues, errors, and releases (Sentry-hosted, OAuth)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://mcp.sentry.dev/mcp",
        },
        category: "dev-tools",
        homepage: "https://github.com/getsentry/sentry-mcp",
    },
    RegistryEntry {
        name: "atlassian",
        description: "Jira and Confluence issues, pages, and search (Atlassian-hosted, OAuth)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://mcp.atlassian.com/v1/mcp",
        },
        category: "dev-tools",
        homepage: "https://github.com/atlassian/atlassian-mcp-server",
    },
    RegistryEntry {
        name: "asana",
        description: "Asana tasks, projects, and workspaces (Asana-hosted, OAuth)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://mcp.asana.com/sse",
        },
        category: "dev-tools",
        homepage: "https://developers.asana.com/docs/using-asanas-mcp-server",
    },
    // ── cloud ───────────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "aws",
        description: "AWS resource management through the AWS CLI command surface",
        command: "uvx awslabs.aws-api-mcp-server@1.5.6",
        required_env: &[],
        optional_env: &["AWS_PROFILE", "AWS_REGION"],
        transport: Transport::Stdio,
        category: "cloud",
        homepage: "https://github.com/awslabs/mcp/tree/main/src/aws-api-mcp-server",
    },
    RegistryEntry {
        name: "cloudflare-workers",
        description: "Cloudflare Workers bindings: KV, D1, R2, and Workers (Cloudflare-hosted, OAuth)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://bindings.mcp.cloudflare.com/mcp",
        },
        category: "cloud",
        homepage: "https://github.com/cloudflare/mcp-server-cloudflare",
    },
    // ── memory ──────────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "memory",
        description: "Persistent knowledge-graph memory for agents",
        command: "npx -y @modelcontextprotocol/server-memory@2026.8.31",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "memory",
        homepage: "https://github.com/modelcontextprotocol/servers/tree/main/src/memory",
    },
    // ── communication ───────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "slack",
        description: "Read channels, threads, and search Slack workspaces (community server)",
        command: "npx -y slack-mcp-server@1.3.0",
        required_env: &["SLACK_MCP_XOXP_TOKEN"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "communication",
        homepage: "https://github.com/korotovsky/slack-mcp-server",
    },
    // ── knowledge ───────────────────────────────────────────────────────────────────
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
        name: "fetch",
        description: "Fetch any HTTP URL and return its contents as markdown",
        command: "uvx mcp-server-fetch@2026.8.18",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "knowledge",
        homepage: "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
    },
    // ── code ────────────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "sequential-thinking",
        description: "Structured multi-step reasoning and problem decomposition",
        command: "npx -y @modelcontextprotocol/server-sequential-thinking@2026.8.31",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "code",
        homepage: "https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking",
    },
    RegistryEntry {
        name: "semgrep",
        description: "Static analysis and security scanning via Semgrep",
        command: "uvx semgrep-mcp@0.9.0",
        required_env: &[],
        optional_env: &["SEMGREP_APP_TOKEN"],
        transport: Transport::Stdio,
        category: "code",
        homepage: "https://github.com/semgrep/mcp",
    },
    RegistryEntry {
        name: "playwright",
        description: "Browser automation via Playwright: navigate, click, fill, and snapshot pages",
        command: "npx -y @playwright/mcp@0.0.83 --headless --isolated",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "code",
        homepage: "https://github.com/microsoft/playwright-mcp",
    },
    // ── productivity ────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "notion",
        description: "Read and write Notion pages and databases (Notion-hosted, OAuth)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://mcp.notion.com/mcp",
        },
        category: "productivity",
        homepage: "https://developers.notion.com/docs/mcp",
    },
    RegistryEntry {
        name: "airtable",
        description: "Query and update Airtable bases and tables (community server)",
        command: "npx -y airtable-mcp-server@1.14.0",
        required_env: &["AIRTABLE_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "productivity",
        homepage: "https://github.com/domdomegg/airtable-mcp-server",
    },
    // ── finance ─────────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "stripe",
        description: "Stripe payments, customers, invoices, and subscriptions (Stripe-hosted, restricted API key)",
        command: "",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Http {
            default_url: "https://mcp.stripe.com",
        },
        category: "finance",
        homepage: "https://docs.stripe.com/mcp",
    },
    // ── vector-db ───────────────────────────────────────────────────────────────────
    RegistryEntry {
        name: "pinecone",
        description: "Pinecone vector database: indexes, search, and documentation",
        command: "npx -y @pinecone-database/mcp@0.3.0",
        required_env: &["PINECONE_API_KEY"],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "vector-db",
        homepage: "https://github.com/pinecone-io/pinecone-mcp",
    },
    RegistryEntry {
        name: "qdrant",
        description: "Qdrant vector search engine: store and find memories",
        command: "uvx mcp-server-qdrant@0.8.1",
        required_env: &["QDRANT_URL", "COLLECTION_NAME"],
        optional_env: &["QDRANT_API_KEY"],
        transport: Transport::Stdio,
        category: "vector-db",
        homepage: "https://github.com/qdrant/mcp-server-qdrant",
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
        // THEN: the result contains at least 20 entries
        assert!(
            all().len() >= 20,
            "Expected at least 20 entries, got {}",
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
