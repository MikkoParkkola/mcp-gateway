// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Negative control for check-registry-packages.py: every entry here is pinned
// but must fail the live lookup (404 package, deprecated version, missing PyPI
// release, 404 URL). The live workflow requires this file to fail.
static REGISTRY: &[RegistryEntry] = &[
    RegistryEntry {
        name: "missing-npm",
        command: "npx -y @anthropic/mcp-server-tavily@1.0.0",
    },
    RegistryEntry {
        name: "deprecated-npm",
        command: "npx -y @modelcontextprotocol/server-github@2025.4.8",
    },
    RegistryEntry {
        name: "missing-pypi",
        command: "uvx mcp-server-time@9999.1.1",
    },
    RegistryEntry {
        name: "missing-url",
        command: "",
        transport: Transport::Http {
            default_url: "https://mcp.context7.com/does-not-exist-mik-7787",
        },
    },
];
