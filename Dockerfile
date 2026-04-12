# =============================================================================
# MCP Gateway - Multi-stage Docker Build
# =============================================================================
# Build:  docker build -t mcp-gateway:latest .
# Run:    docker run -p 39400:39400 -v ./gateway.yaml:/config.yaml:ro mcp-gateway:latest --config /config.yaml
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build
# ---------------------------------------------------------------------------
FROM rust:1.94-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency layer caching.
# A dummy src/main.rs lets `cargo build` download and compile dependencies
# without invalidating the cache when only source code changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Copy real source and build
COPY src ./src
COPY benches ./benches
RUN touch src/main.rs && cargo build --release

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r -g 1001 gateway && \
    useradd -r -u 1001 -g gateway -s /usr/sbin/nologin gateway

# Copy binary from builder
COPY --from=builder /app/target/release/mcp-gateway /usr/local/bin/mcp-gateway

# Create directories for config and capabilities (mount points)
RUN mkdir -p /etc/mcp-gateway /capabilities && \
    chown -R gateway:gateway /etc/mcp-gateway /capabilities

USER gateway

# Default port (matches gateway default)
EXPOSE 39400

# Health check using the built-in /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --spider -q http://localhost:39400/health || exit 1

ENTRYPOINT ["mcp-gateway"]
CMD ["--config", "/config.yaml"]
