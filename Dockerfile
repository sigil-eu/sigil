# SPDX-License-Identifier: EUPL-1.2
# Copyright (c) 2026 Benjamin Küttner <benjamin.kuettner@icloud.com>
# Multi-stage Rust build — final image is ~8MB (musl static binary, no runtime)

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.82-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY . .

RUN cargo build --release --bin sigil-mcp-server \
    && strip target/release/sigil-mcp-server

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.20

# Non-root user — sovereign by default
RUN addgroup -S sigil && adduser -S sigil -G sigil

COPY --from=builder /build/target/release/sigil-mcp-server /usr/local/bin/sigil-mcp-server

USER sigil

# MCP stdio transport: container stdin/stdout is the protocol channel
# Optionally mount an audit log volume:
#   docker run -v /host/audit:/audit -e SIGIL_AUDIT_LOG=/audit/sigil.log sigil-mcp-server
ENV SIGIL_OFFLINE=true \
    SIGIL_MIN_SEVERITY=High

LABEL org.opencontainers.image.title="sigil-mcp-server" \
      org.opencontainers.image.description="SIGIL — Sovereign Identity-Gated Interaction Layer. Security middleware for AI agent tool calls. EUPL-1.2." \
      org.opencontainers.image.source="https://github.com/sigil-eu/sigil-rs" \
      org.opencontainers.image.licenses="EUPL-1.2" \
      org.opencontainers.image.version="0.1.5"

ENTRYPOINT ["/usr/local/bin/sigil-mcp-server"]
