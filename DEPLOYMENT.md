# Deploying Bollwark

Self-hosting guide for the container image. For what every environment
variable does — score weights, tier thresholds, file formats — see
**[CONFIGURATION.md](./CONFIGURATION.md)**, which is the source of truth. This
document only covers running the thing.

## One command

```bash
docker run -d --name bollwark -p 3000:3000 ghcr.io/hauju/bollwark:latest
```

That gets you a working PoW captcha service on port 3000 with every default
in place. It is deliberately useless for anything but a smoke test, because
without `ADMIN_TOKEN` you cannot register a site (`POST /v1/sites` returns
`404` — there is no anonymous provisioning). The real minimum:

```bash
docker run -d --name bollwark -p 3000:3000 \
  -e ADMIN_TOKEN="$(openssl rand -hex 32)" \
  -e SITE_DB_PATH=/data/sites.db \
  -v bollwark-data:/data \
  ghcr.io/hauju/bollwark:latest
```

Check it: `curl localhost:3000/healthz` → `ok`.

Register a site and embed the widget — see [README.md](./README.md#quickstart)
and [INTEGRATION.md](./INTEGRATION.md).

## Compose quickstart

[`docker-compose.yml`](./docker-compose.yml) in this repo is a single-service
file with a named volume for `/data` and every optional variable present but
commented out.

```bash
curl -O https://raw.githubusercontent.com/hauju/rust-captcha/main/docker-compose.yml
# uncomment ADMIN_TOKEN (and SITE_DB_PATH if you want sites to survive restarts)
docker compose up -d
docker compose logs -f
```

To build from a checkout instead of pulling, swap `image:` for `build: .`.

## Image

| | |
|---|---|
| Registry | `ghcr.io/hauju/bollwark` |
| Tags | `latest` (main), `1.2.3` / `1.2` / `1` (version tags), `sha-<commit>` |
| Platforms | `linux/amd64`, `linux/arm64` |
| Base | `debian:trixie-slim` |
| User | non-root, uid/gid `10001` |
| Port | `3000` |
| Data dir | `/data` |

Pin a version tag in production. `latest` moves on every push to main.

Two paths are baked in and you should not need to override them:
`STATIC_DIR=/app/static` (absolute — it resolves against the process CWD
otherwise, and a relative value breaks the widget) and
`LISTEN_ADDR=0.0.0.0:3000`.

### Healthcheck

The image ships a `HEALTHCHECK` that curls `/healthz`. `curl` is installed in
the runtime stage for exactly this reason — `debian-slim` has neither curl nor
wget, and the alternative was a distroless image where no in-container probe
is possible. If you probe at the orchestrator level instead (Kubernetes, a
load balancer, Coolify), point it at `GET /healthz`; it returns `200 ok` and
is the intended liveness probe.

`/healthz` only proves the process is alive *inside* the container. It cannot
see a broken TLS cert on the reverse proxy in front of it — see the warning
under [Reverse proxy](#reverse-proxy).

## Environment variables

Required for a useful deployment:

| Variable | Why |
|---|---|
| `ADMIN_TOKEN` | Gates `POST /v1/sites` and `/v1/admin/*`. Unset ⇒ those routes 404. Generate with `openssl rand -hex 32`. |

Strongly recommended:

| Variable | Why |
|---|---|
| `SITE_DB_PATH` | e.g. `/data/sites.db`. Without it sites are in-memory only and every restart invalidates every integrator's `secret_key`. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowlist for `GET /v1/puzzle`. Unset means any origin can fetch puzzles for your site keys. |
| `TRUSTED_PROXIES` | Required behind a reverse proxy — see below. |

Optional, each inert until configured: `ADMIN_DB_PATH` (validation dashboard +
decision log; **requires `ADMIN_TOKEN` or the server refuses to start**),
`GEOIP_DB_PATH`, `IP_REPUTATION_FILE`, `TLS_FINGERPRINT_HEADER`,
`LOAD_LADDER`, `PUZZLE_ALGORITHM` and the difficulty knobs, `LOG_FORMAT=json`.
All of them, with defaults and semantics, are in
[CONFIGURATION.md](./CONFIGURATION.md).

## Reverse proxy

Bollwark speaks plain HTTP and expects TLS to terminate in front of it.

**Set `TRUSTED_PROXIES` to the CIDRs of your proxies.** This is not optional
hygiene — it is what makes per-IP scoring work at all. The service resolves
the client IP by walking `X-Forwarded-For` right-to-left until it hits an
address outside the trusted list; with `TRUSTED_PROXIES` unset it uses the
immediate peer, which behind a proxy means *every visitor scores as the same
IP*. That collapses the rate signal and will trip `IP_HARD_LIMIT` for your
whole population. The same list gates the TLS-fingerprint header
(`TLS_FINGERPRINT_HEADER`, e.g. Cloudflare's `cf-ja4`), so a direct client
cannot spoof it.

```
TRUSTED_PROXIES=172.16.0.0/12,10.0.0.0/8
```

Forward `X-Forwarded-For` and `X-Forwarded-Proto` from the proxy. Nothing else
is required: the service is **cookie-free** — it never sets or reads a cookie —
so there is no session affinity, `SameSite`, or credentials handling to
configure, and cross-origin embeds work without any of it.

**TLS certificate warning.** If your proxy manages Let's Encrypt certs
(Traefik, Caddy, Coolify), a failed ACME renewal can silently fall back to a
self-signed cert. The app keeps reporting healthy while browsers refuse to
load `captcha-widget.js` and every embed on every customer site breaks.
`scripts/check-public-endpoint.sh` (also wired up as
`.github/workflows/monitor.yml`, `just monitor`) verifies the **public** URL
with full chain validation. Point it at your domain.

## Persistence

The store is in-memory with optional SQLite write-through. What that means
concretely:

**Lost on restart, always:**

- Active challenges. Anyone mid-solve gets an "expired challenge" on verify.
  The bundled widget re-fetches, so the visible impact is a re-solve, not a
  hard failure. Restarts are cheap; deploy freely.
- Per-IP and per-site rate-window counters (60s windows). A restart briefly
  resets the rate signal to zero for everyone.

**Persisted, if you configure it:**

- `SITE_DB_PATH` → registered sites (site_key, secret_key, allowed_origins).
  Sites are kept in memory and written through to SQLite, then reloaded at
  boot. Set this or your integrators' secrets die with the container.
- `ADMIN_DB_PATH` → the decision log behind `/v1/admin/*` and the dashboard at
  `/static/admin.html`. Pruned by `LOG_RETENTION_HOURS` (default 72).

Both belong on the `/data` volume. `/data` is created in the image owned by
uid `10001`, so a **named volume** inherits the right ownership automatically.
If you bind-mount a host directory instead, the host's ownership wins and the
non-root process will fail to write — `chown 10001:10001` the host directory
first.

### Single replica only

Run one instance. Challenges and rate counters live in that process's memory,
so a second replica does not see the first one's challenges: a visitor whose
`/v1/puzzle` and `/v1/verify` land on different replicas fails verification,
and per-IP rate limits are divided by the replica count. There is no shared
backend today — the `Store` trait exists so one can be added, and a Redis
implementation is tracked separately. Scale vertically until then.

## Coolify

1. **New Resource → Docker Image**, image `ghcr.io/hauju/bollwark:latest`
   (pin a version tag for production).
2. **Port**: `3000`. Coolify's Traefik terminates TLS and proxies to it.
3. **Health check**: path `/healthz`, port `3000`, expect `200`.
4. **Storage**: add a persistent volume mounted at `/data`.
5. **Environment**: at minimum `ADMIN_TOKEN` and `SITE_DB_PATH=/data/sites.db`.
   Add `TRUSTED_PROXIES` covering Coolify's Docker network (typically
   `10.0.0.0/8,172.16.0.0/12`) so client IPs resolve past Traefik.
6. Set up the external TLS monitor described above. Coolify's Traefik is
   exactly the ACME-fallback case that `/healthz` cannot detect.

For redeploy-on-push, Coolify's webhook works the same way the maintainer's
own pipeline uses it (see the `deploy` job in
`.github/workflows/bollwark.yml`).

## Upgrading

```bash
docker compose pull && docker compose up -d
```

Expect the challenge/rate-counter reset described above. Sites and the
decision log survive if they are on the `/data` volume.
