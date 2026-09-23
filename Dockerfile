# =============================================================================
# MCP Gateway - Multi-stage Docker Build
# =============================================================================
# Build:  docker build --target runtime -t mcp-gateway:latest .
# Run:    docker run -p 127.0.0.1:39400:39400 \
#           -e MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND=true \
#           -v ./gateway.yaml:/config.yaml:ro mcp-gateway:latest \
#           --config /config.yaml --host 0.0.0.0
#         The container must bind 0.0.0.0 or the published port reaches nothing;
#         publishing to 127.0.0.1 keeps that off-host. See docs/DEPLOYMENT.md.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build
# ---------------------------------------------------------------------------
FROM rust:1.98-slim AS builder

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
COPY crates ./crates
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Copy real source and build
COPY src ./src
COPY benches ./benches
COPY benchmarks ./benchmarks
COPY capabilities ./capabilities
RUN touch src/main.rs && cargo build --release

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

LABEL io.modelcontextprotocol.server.name="io.github.MikkoParkkola/mcp-gateway"

# Debian ships security updates into the apt archives continuously, but the
# `debian:trixie-slim` image they are published against is rebuilt far less
# often. While that base image's digest sits still, this layer's cache key sits
# still with it, so a rebuild restores the upgrade from cache instead of running
# it: the image keeps whatever package versions were current the day the layer
# was first built, and the trivy gate in docker.yml reports CVEs that
# `apt-get upgrade` would already have fixed. Pass a per-build value here to
# move the cache key and force the upgrade to re-run against today's archives.
ARG APT_CACHE_BUST=local

RUN echo "apt cache bust: ${APT_CACHE_BUST}" \
    && apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. `-m` is load-bearing: without it a system account gets no home
# directory, and the gateway resolves the task store, the skill registry and the
# chain checkpoint store under $HOME. The task store treats an uncreatable parent
# as a fatal configuration error, so an image without this exits 1 on startup
# before it reads any config, whatever the operator mounts.
RUN groupadd -r -g 1001 gateway && \
    useradd -r -u 1001 -g gateway -m -d /home/gateway -s /usr/sbin/nologin gateway

# Copy binary from builder
COPY --from=builder /app/target/release/mcp-gateway /usr/local/bin/mcp-gateway

# License files must travel with the image (mixed, per-file licensing; the
# runnable gateway is PolyForm Noncommercial 1.0.0 — commercial use needs a
# license). Verified in CI by scripts/ci/verify-artifact-licenses.sh.
COPY LICENSE LICENSE-MIT LICENSE-NONCOMMERCIAL LICENSES.md NOTICE.md COMMERCIAL.md /usr/share/doc/mcp-gateway/

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

# ---------------------------------------------------------------------------
# Stage 3: Runtime + stdio backend runtimes (`:latest-full`)
# ---------------------------------------------------------------------------
FROM runtime AS runtime-full

ARG APT_CACHE_BUST=local

USER root

RUN echo "apt cache bust: ${APT_CACHE_BUST}" \
    && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gnupg \
    openssh-client \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /tmp/nodesource.key \
    && test "$(gpg --show-keys --with-colons /tmp/nodesource.key | grep -c '^pub:')" = 1 \
    && gpg --show-keys --with-colons /tmp/nodesource.key \
       | grep -qx 'fpr:::::::::6F71F525282841EEDAF851B42F59B5F99B1BE0B4:' \
    && gpg --dearmor -o /usr/share/keyrings/nodesource.gpg /tmp/nodesource.key \
    && rm -f /tmp/nodesource.key \
    && printf '%s\n' 'Types: deb' 'URIs: https://deb.nodesource.com/node_24.x' 'Suites: nodistro' \
       'Components: main' 'Signed-By: /usr/share/keyrings/nodesource.gpg' \
       > /etc/apt/sources.list.d/nodesource.sources \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version | grep -q '^v24\.' \
    && npm --version >/dev/null

# NodeSource ships whichever npm it bundled that day; the pin makes the tree
# scanned below a version this repo chose. Do not "simplify" it away.
RUN npm install -g npm@12.0.2 \
    && test "$(npm --version)" = "12.0.2"

# npm protects its own vendored tree; these are unpacked over it, not installed.
RUN cd /tmp && mkdir npm-patch && cd npm-patch \
    && for spec in brace-expansion@5.0.9 ip-address@10.3.1 tar@7.5.21; do \
         name="${spec%@*}"; ver="${spec##*@}"; \
         dest="/usr/lib/node_modules/npm/node_modules/${name}"; \
         npm pack --silent "${spec}" >/dev/null || exit 1; \
         rm -rf "${dest}"; \
         mkdir -p "${dest}"; \
         tar -xzf "${name}-${ver}.tgz" -C "${dest}" --strip-components=1 || exit 1; \
         got="$(node -p "require('${dest}/package.json').version")"; \
         test "${got}" = "${ver}" || { echo "npm patch failed: ${name} is ${got}, wanted ${ver}" >&2; exit 1; }; \
       done \
    && cd / && rm -rf /tmp/npm-patch

COPY --from=ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc /uv /uvx /usr/local/bin/

RUN mkdir -p /home/gateway/.cache/uv /home/gateway/.npm && \
    chown -R gateway:gateway /home/gateway/.cache /home/gateway/.npm

USER gateway
