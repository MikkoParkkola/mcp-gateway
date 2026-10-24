// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MIK-8513 CONTENT.2 falsifier: semver installs and verifies but is not an MCP server.
static CATALOG: &[ServerCatalogEntry] = &[
    ServerCatalogEntry {
        name: "starts-time",
        description: "MIK-8513 live-check testdata",
        command: "uvx mcp-server-time@2026.8.18",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "testdata",
        homepage: "https://example.invalid",
        auth: Auth::None,
        reach: Reach::Bounded,
        setup: Setup::Ready,
    },
    ServerCatalogEntry {
        name: "not-mcp-semver",
        description: "MIK-8513 live-check testdata",
        command: "npx -y semver@7.6.3",
        required_env: &[],
        optional_env: &[],
        transport: Transport::Stdio,
        category: "testdata",
        homepage: "https://example.invalid",
        auth: Auth::None,
        reach: Reach::Bounded,
        setup: Setup::Ready,
    },
];
