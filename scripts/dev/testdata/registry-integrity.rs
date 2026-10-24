// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MIK-8513 CONTENT.1 falsifier: memory's recorded digest is deliberately wrong.
static CATALOG: &[ServerCatalogEntry] = &[
    ServerCatalogEntry {
        name: "wrong-digest-memory",
        description: "MIK-8513 live-check testdata",
        command: "npx -y @modelcontextprotocol/server-memory@1.0.0",
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
        name: "right-digest-time",
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
];
