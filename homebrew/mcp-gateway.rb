class McpGateway < Formula
  desc "Universal MCP Gateway with Meta-MCP for ~95% context token savings"
  homepage "https://github.com/MikkoParkkola/mcp-gateway"
  version "2.0.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/MikkoParkkola/mcp-gateway/releases/download/v#{version}/mcp-gateway-darwin-arm64"
      sha256 "fedc8bad3b7665a647f21829db4401134338174ab265309725fc83d29b969073"

      def install
        bin.install "mcp-gateway-darwin-arm64" => "mcp-gateway"
      end
    end

    on_intel do
      url "https://github.com/MikkoParkkola/mcp-gateway/releases/download/v#{version}/mcp-gateway-darwin-x86_64"
      sha256 "1e5cc08385ed089872d551e353a1f6f363e1d4dcc72883eb88eb6b49e5df9a84"

      def install
        bin.install "mcp-gateway-darwin-x86_64" => "mcp-gateway"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/MikkoParkkola/mcp-gateway/releases/download/v#{version}/mcp-gateway-linux-x86_64"
      sha256 "14ab97806bae3a5ec5466812ceef74b273a176394e640b6695b3e23d8c37b0b3"

      def install
        bin.install "mcp-gateway-linux-x86_64" => "mcp-gateway"
      end
    end
  end

  def caveats
    <<~EOS
      To start mcp-gateway, create a config file:
        mcp-gateway --config /path/to/servers.yaml

      Example config at:
        https://github.com/MikkoParkkola/mcp-gateway#configuration
    EOS
  end

  test do
    assert_match "mcp-gateway", shell_output("#{bin}/mcp-gateway --version")
  end
end
