#!/usr/bin/env bash
#
# External health + TLS-certificate monitor for the PUBLIC bollwark endpoint.
#
# Runs from OUTSIDE the deployment (CI cron, or your laptop) so it sees what a
# browser sees through Coolify's Traefik proxy — which the in-container
# `/healthz` Docker healthcheck cannot. The failure this exists to catch:
# Traefik falling back to its default self-signed certificate (ACME/Let's
# Encrypt issuance failed), which makes browsers refuse `captcha-widget.js` and
# silently breaks every integrator's embed while the app itself looks healthy.
#
# Checks, against the public URL with FULL TLS verification (no `-k`):
#   1. Each path in MONITOR_PATHS returns 2xx over a valid cert chain. curl
#      without `-k` fails on a self-signed / expired / incomplete chain exactly
#      like a browser.
#   2. The leaf cert is not self-signed / the Traefik default, and is not
#      expiring within EXPIRY_DAYS (proactive warning before it breaks).
#
# Exit 0 = healthy, 1 = problem. If MONITOR_WEBHOOK is set, a problem also posts
# an alert (Slack- and Discord-compatible) before exiting non-zero.
#
# If MONITOR_ADMIN_TOKEN is set, a problem ALSO declares an outage window via
# POST /v1/admin/outages, which is what lets the widget's client-failover path
# work for this class of failure. The app's own heartbeat can only attest gaps
# where the *process* was gone; a broken cert in front of a perfectly healthy
# process leaves no trace it can see. This monitor is the only component that
# observes the outage from where it actually happens — the browser's side —
# so it is the one that has to report it. See src/failover/mod.rs.
#
# Usage:
#   scripts/check-public-endpoint.sh [URL]
#
# Env:
#   MONITOR_URL      Base URL to check (default https://api.bollwark.eu).
#                    The [URL] argument, if given, overrides it.
#   MONITOR_PATHS    Space-separated paths to fetch. Defaults to the service
#                    set below. Override it for a host that isn't running the
#                    service — the marketing site at bollwark.eu has no
#                    /healthz, so it is monitored as MONITOR_PATHS=/.
#   EXPIRY_DAYS      Warn if the cert expires within this many days (default 14).
#   MONITOR_WEBHOOK  Optional Slack/Discord-compatible webhook for alerts.
#   MONITOR_ADMIN_TOKEN
#                    Optional ADMIN_TOKEN. When set and a check fails, declare
#                    an outage window so failover claims are honored. Requires
#                    FAILOVER_ENABLED on the server.
#   MONITOR_INTERVAL_SECS
#                    Length of the declared window (default 900). Should be at
#                    least this monitor's cron cadence, so consecutive failing
#                    runs produce overlapping windows with no gap between them.
#   MONITOR_ADMIN_URL
#                    Where to POST the declaration. Defaults to MONITOR_URL,
#                    but during a TLS failure that URL is exactly what's broken
#                    — point this at an internal address that bypasses the
#                    proxy (e.g. http://127.0.0.1:3000) so the declaration can
#                    still land.
set -euo pipefail

URL="${1:-${MONITOR_URL:-https://api.bollwark.eu}}"
URL="${URL%/}"
EXPIRY_DAYS="${EXPIRY_DAYS:-14}"

# `/v1/widget.js` is the URL every current embed loads, so it is the one whose
# TLS failure breaks customers; the `/static/` pair is still checked because
# older embeds point there and it is a permanent path. Deliberately not
# checking a hashed `/assets/<hash>/…` URL: the hash changes every time the
# bundle does, so any pinned one would rot into a false alarm.
MONITOR_PATHS="${MONITOR_PATHS:-/healthz /v1/widget.js /static/captcha-widget.js /static/captcha-widget.css}"

host="${URL#https://}"; host="${host#http://}"; host="${host%%/*}"
port=443

fails=()

echo "▶ Monitoring ${URL} (host ${host}, warn if cert expires < ${EXPIRY_DAYS}d)"

# 1) Reachability + valid TLS chain for each public asset (browser-equivalent).
for path in $MONITOR_PATHS; do
    if out=$(curl --fail --show-error --silent --location --max-time 15 \
                  -o /dev/null -w '%{http_code}' "${URL}${path}" 2>&1); then
        echo "  ✓ ${path} → HTTP ${out}"
    else
        code=$?
        hint=""
        case $code in
            60|35|51|58|59|66|77|80|82|83) hint=" — TLS/cert failure (invalid or self-signed cert)";;
            28) hint=" — timeout (host unreachable or proxy down)";;
            6)  hint=" — DNS did not resolve";;
            7)  hint=" — connection refused";;
            22) hint=" — non-2xx HTTP status";;
        esac
        echo "  ✗ ${path} → curl exit ${code}: ${out}"
        fails+=("${path}: curl ${code}${hint}")
    fi
done

# 2) Certificate identity + expiry (precise diagnostic + proactive warning).
leaf=$(echo | openssl s_client -connect "${host}:${port}" -servername "${host}" 2>/dev/null \
       | openssl x509 2>/dev/null || true)
if [[ -z "$leaf" ]]; then
    echo "  ✗ could not retrieve a TLS certificate from ${host}:${port}"
    fails+=("cert: could not retrieve certificate from ${host}:${port}")
else
    subject=$(printf '%s\n' "$leaf" | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject=//')
    issuer=$(printf '%s\n' "$leaf" | openssl x509 -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    notafter=$(printf '%s\n' "$leaf" | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    echo "  · subject: ${subject}"
    echo "  · issuer:  ${issuer}"
    echo "  · expires: ${notafter}"

    if [[ "$issuer" == *"TRAEFIK DEFAULT CERT"* || "$subject" == "$issuer" ]]; then
        echo "  ✗ self-signed / Traefik default certificate"
        fails+=("cert: self-signed / Traefik default — re-issue the Let's Encrypt cert in Coolify (ACME)")
    fi
    if ! printf '%s\n' "$leaf" | openssl x509 -checkend $((EXPIRY_DAYS * 86400)) -noout >/dev/null 2>&1; then
        echo "  ✗ certificate expires within ${EXPIRY_DAYS} days (or has already expired)"
        fails+=("cert: expires within ${EXPIRY_DAYS}d (notAfter=${notafter})")
    fi
fi

if [[ ${#fails[@]} -eq 0 ]]; then
    echo "✅ ${URL} healthy"
    exit 0
fi

echo "❌ ${URL} has ${#fails[@]} problem(s):"
printf '   - %s\n' "${fails[@]}"

# Declare an outage so the widget's failover claims are honored for it. Only
# meaningful for the "app healthy, edge broken" class of failure, which is
# precisely the class the server cannot attest for itself.
#
# Best-effort and deliberately non-fatal: if the declaration doesn't land, the
# result is that failover stays closed — the same behavior as before this
# existed. It must never mask the monitor's own failure exit.
if [[ -n "${MONITOR_ADMIN_TOKEN:-}" ]]; then
    admin_url="${MONITOR_ADMIN_URL:-$URL}"
    admin_url="${admin_url%/}"
    window="${MONITOR_INTERVAL_SECS:-900}"
    if out=$(curl --silent --show-error --max-time 10 \
                  -H 'Content-Type: application/json' \
                  -H "Authorization: Bearer ${MONITOR_ADMIN_TOKEN}" \
                  -d "{\"duration_secs\":${window}}" \
                  -w '\n%{http_code}' \
                  "${admin_url}/v1/admin/outages" 2>&1); then
        code=$(printf '%s' "$out" | tail -n1)
        if [[ "$code" == "200" ]]; then
            echo "→ declared a ${window}s outage window (failover claims will be honored)"
        else
            echo "→ outage declaration rejected (HTTP ${code}) — is FAILOVER_ENABLED set?"
        fi
    else
        echo "→ outage declaration failed to reach ${admin_url} (non-fatal)"
    fi
fi

# Optional alert. Slack reads "text", Discord reads "content" — send both keys
# so one payload works for either. Best-effort; never masks the failure exit.
if [[ -n "${MONITOR_WEBHOOK:-}" ]]; then
    lines=$(printf '• %s\\n' "${fails[@]}")
    msg="🚨 bollwark monitor: ${URL} is unhealthy\\n${lines}"
    payload=$(printf '{"text":"%s","content":"%s"}' "$msg" "$msg")
    if curl --silent --max-time 10 -H 'Content-Type: application/json' \
            -d "$payload" "$MONITOR_WEBHOOK" >/dev/null 2>&1; then
        echo "→ alert posted to MONITOR_WEBHOOK"
    else
        echo "→ MONITOR_WEBHOOK post failed (non-fatal)"
    fi
fi

exit 1
