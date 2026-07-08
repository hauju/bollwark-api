FROM rust:1.91-slim-trixie AS builder

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    ca-certificates pkg-config build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/bollwark

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY tests ./tests

RUN cargo build --release --locked

FROM debian:trixie-slim

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ENV LISTEN_ADDR=0.0.0.0:3000

WORKDIR /usr/local/app

COPY --from=builder /usr/src/bollwark/target/release/bollwark /usr/local/bin/bollwark
COPY static ./static

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/bollwark"]
