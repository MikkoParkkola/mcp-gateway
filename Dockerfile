# =============================================================================
# MCP Gateway - Multi-stage Docker Build
# =============================================================================
# Build:  docker build --target runtime -t mcp-gateway:latest .
# Run:    docker run -p 127.0.0.1:39400:39400 \
#           -e MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND=true \
#           -e MCP_GATEWAY_SERVER__CLEARTEXT_HTTP=host_local_publish \
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

# Liveness only: /health fails whenever any backend is down, which is not a
# reason to call the container unhealthy. The address, not `localhost`: on a
# 0.0.0.0 bind with no public_url the Host gate admits only numeric hosts.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --spider -q http://127.0.0.1:39400/livez || exit 1

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
# Every tarball is checked against the sha512 pinned here (the registry's
# `dist.integrity`) before use, so the registry cannot swap the bytes. Compare
# the strings as written: a decoded compare can miss an edit in the last char.
# Past npm itself, npm protects its own vendored tree; the rest are unpacked
# over it, not installed.
RUN cd /tmp && mkdir npm-patch && cd npm-patch \
    && pins="npm@12.0.2:sha512-uIXokLlBj6FpNUTQX1PmT5pz7BlIN9QlixX+zdaSNHsd0qUXsbDLr50xzY6Sw7cJVr0uzHKDOle0swmPW/p5Qw== \
brace-expansion@5.0.9:sha512-ScQ4IuvIEF1TMlP7Zt+vjJ//9zlPb2SDcxWxM3bk8s6t6GGdJ7KO1dCcTidOPJKePW30LE/2cT7wCyPho9/Wxg== \
ip-address@10.3.1:sha512-1e9d3kb97NHJTIJDZW9rKqW2h6+dFa50Dy0fpPSMQp2ADje5gvKsXmdiK6dwY5t76TaTt5+P5N1Y/LoToIxP6g== \
tar@7.5.21:sha512-XdhtCvlMywwxpCW8YEq3lOXBJpUPTR2OHHcwLPO3HwsJqOHa2Ok/oJ7ruGzp+JrKoRPVCzJwAdEjqLW/vNRPHA==" \
    && for pin in ${pins}; do \
         spec="${pin%%:*}"; want="${pin#*:}"; \
         npm pack --silent "${spec}" >/dev/null || exit 1; \
         got="$(node -p "'sha512-' + require('crypto').createHash('sha512').update(require('fs').readFileSync('${spec%@*}-${spec##*@}.tgz')).digest('base64')")" || exit 1; \
         test "${got}" = "${want}" || { echo "npm integrity mismatch: ${spec} is ${got}, pinned ${want}" >&2; exit 1; }; \
       done \
    && npm install -g ./npm-12.0.2.tgz \
    && test "$(npm --version)" = "12.0.2" \
    && for pin in ${pins}; do \
         spec="${pin%%:*}"; name="${spec%@*}"; ver="${spec##*@}"; \
         test "${name}" = npm && continue; \
         dest="/usr/lib/node_modules/npm/node_modules/${name}"; \
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
