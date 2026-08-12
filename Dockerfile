# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.94.1
ARG ALPINE_VERSION=3.23

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,id=crabnet-cargo-registry,target=/usr/local/cargo/registry \
    cargo fetch --locked

COPY src ./src
RUN --mount=type=cache,id=crabnet-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=crabnet-target,target=/build/target \
    CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_PANIC=abort \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    cargo build --locked --release && \
    cp target/release/crabnet /tmp/crabnet

FROM alpine:${ALPINE_VERSION} AS runtime

# Crabnet invokes these tools to inspect and manage routes, forwarding, and NAT.
RUN apk add --no-cache iproute2 nftables procps

COPY --from=builder /tmp/crabnet /usr/local/bin/crabnet

# The UDP listen port is configurable; 51820 is Crabnet's default.
EXPOSE 51820/udp

# Crabnet handles SIGINT and uses it to restore owned network state cleanly.
STOPSIGNAL SIGINT

ENTRYPOINT ["/usr/local/bin/crabnet"]
