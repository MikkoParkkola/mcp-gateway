class McpGateway < Formula
  desc "Universal MCP Gateway - Single-port multiplexing with Meta-MCP for ~95% context token savings"
  homepage "https://github.com/MikkoParkkola/mcp-gateway"
  url "https://github.com/MikkoParkkola/mcp-gateway/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "PLACEHOLDER"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "mcp-gateway", shell_output("#{bin}/mcp-gateway --version")
  end
end
