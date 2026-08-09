# syntax=docker/dockerfile:1

# ---------- builder ----------
FROM rust:1.91-slim-trixie AS builder

# build-essential is required: rusqlite is built with the `bundled` feature,
# which compiles SQLite from C source.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    ca-certificates pkg-config build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/bollwark

COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The workspace members under crates/ are integration libraries, not part of
# the server — but cargo loads every member's manifest before it will build
# anything, so omitting them fails the build outright rather than merely
# skipping them. `--bin bollwark` still builds only the server.
COPY crates ./crates

RUN cargo build --release --locked --bin bollwark

# ---------- runtime ----------
FROM debian:trixie-slim

# curl is here only so the container-level HEALTHCHECK below can work;
# debian-slim ships neither curl nor wget. Drop it (and the HEALTHCHECK)
# if you probe /healthz at the orchestrator level instead.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 bollwark \
    && useradd --system --uid 10001 --gid bollwark --no-create-home bollwark

WORKDIR /app

COPY --from=builder /usr/src/bollwark/target/release/bollwark /usr/local/bin/bollwark
COPY static /app/static

# Mount point for the optional SQLite files (SITE_DB_PATH, ADMIN_DB_PATH) and
# any operator-provisioned GeoIP database. Created with the runtime user's
# ownership so a named volume inherits it on first use.
RUN install -d -o bollwark -g bollwark /data
VOLUME ["/data"]

# STATIC_DIR must be absolute: it is otherwise resolved against the process CWD.
ENV LISTEN_ADDR=0.0.0.0:3000 \
    STATIC_DIR=/app/static \
    RUST_LOG=info

USER bollwark:bollwark

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/bollwark"]
