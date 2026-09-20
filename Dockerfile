# Multi-stage build for zenohd with grpc_hook support
FROM rust:bookworm AS builder

# Install protobuf compiler and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    cmake \
    clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build zenohd binary with grpc_hook feature
RUN cargo build --release -p zenohd --features grpc_hook

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zenohd /usr/local/bin/zenohd
COPY DEFAULT_CONFIG.json5 /etc/zenoh/zenohd.json5

EXPOSE 7447/tcp 7447/udp

ENTRYPOINT ["/usr/local/bin/zenohd"]
CMD ["-c", "/etc/zenoh/zenohd.json5"]
