#!/usr/bin/env bash
#
# External health + TLS-certificate monitor for the PUBLIC rust-captcha endpoint.
#
# Runs from OUTSIDE the deployment (CI cron, or your laptop) so it sees what a
# browser sees through Coolify's Traefik proxy — which the in-container
# `/healthz` Docker healthcheck cannot. The failure this exists to catch:
# Traefik falling back to its default self-signed certificate (ACME/Let's
# Encrypt issuance failed), which makes browsers refuse `captcha-widget.js` and
# silently breaks every integrator's embed while the app itself looks healthy.
#
# Checks, against the public URL with FULL TLS verification (no `-k`):
#   1. /healthz, /static/captcha-widget.js, /static/captcha-widget.css each
#      return 2xx over a valid cert chain. curl without `-k` fails on a
#      self-signed / expired / incomplete chain exactly like a browser.
#   2. The leaf cert is not self-signed / the Traefik default, and is not
#      expiring within EXPIRY_DAYS (proactive warning before it breaks).
#
# Exit 0 = healthy, 1 = problem. If MONITOR_WEBHOOK is set, a problem also posts
# an alert (Slack- and Discord-compatible) before exiting non-zero.
#
# Usage:
#   scripts/check-public-endpoint.sh [URL]
#
# Env:
#   MONITOR_URL      Base URL to check (default https://captcha.oxidt.com).
#                    The [URL] argument, if given, overrides it.
#   EXPIRY_DAYS      Warn if the cert expires within this many days (default 14).
#   MONITOR_WEBHOOK  Optional Slack/Discord-compatible webhook for alerts.
set -euo pipefail

URL="${1:-${MONITOR_URL:-https://captcha.oxidt.com}}"
URL="${URL%/}"
EXPIRY_DAYS="${EXPIRY_DAYS:-14}"

host="${URL#https://}"; host="${host#http://}"; host="${host%%/*}"
port=443

fails=()

echo "▶ Monitoring ${URL} (host ${host}, warn if cert expires < ${EXPIRY_DAYS}d)"

# 1) Reachability + valid TLS chain for each public asset (browser-equivalent).
for path in /healthz /static/captcha-widget.js /static/captcha-widget.css; do
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

# Optional alert. Slack reads "text", Discord reads "content" — send both keys
# so one payload works for either. Best-effort; never masks the failure exit.
if [[ -n "${MONITOR_WEBHOOK:-}" ]]; then
    lines=$(printf '• %s\\n' "${fails[@]}")
    msg="🚨 rust-captcha monitor: ${URL} is unhealthy\\n${lines}"
    payload=$(printf '{"text":"%s","content":"%s"}' "$msg" "$msg")
    if curl --silent --max-time 10 -H 'Content-Type: application/json' \
            -d "$payload" "$MONITOR_WEBHOOK" >/dev/null 2>&1; then
        echo "→ alert posted to MONITOR_WEBHOOK"
    else
        echo "→ MONITOR_WEBHOOK post failed (non-fatal)"
    fi
fi

exit 1
