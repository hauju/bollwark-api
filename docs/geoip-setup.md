# GeoIP setup (internal ops guide)

How to enable the dashboard's **country breakdown** by wiring up a MaxMind
GeoLite2 database. This is operator-facing — for the env-var reference see
[`CONFIGURATION.md`](../CONFIGURATION.md); this doc is the practical "get it
running + keep it fresh" runbook.

> **What it does:** when enabled, the decision-log writer stamps each puzzle
> row with the visitor's ISO country code (e.g. `US`, `DE`), looked up offline,
> and the dashboard's **Analytics → Countries** panel fills in. It's
> observability only — geo does **not** feed bot scoring.

---

## 1. Prerequisites

Geo enrichment rides on the validation dashboard. The GeoIP database is only
loaded when the dashboard log is enabled, i.e. **both** of these are set:

| Var | Why |
|---|---|
| `ADMIN_DB_PATH` | The SQLite decision log that holds the `country` column. |
| `ADMIN_TOKEN`   | Bearer for `/v1/admin/*`; the server refuses to boot with `ADMIN_DB_PATH` set but no token. |

If `GEOIP_DB_PATH` is set but `ADMIN_DB_PATH` is **not**, geo silently does
nothing — there's no decision log to stamp.

---

## 2. Get the database

The `.mmdb` is **not bundled** — MaxMind's license requires you to download it
under your own account. It's free.

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>.
2. Generate a **license key** (Account → Manage License Keys).
3. Grab **GeoLite2-Country** (`GeoLite2-City` also works — we only read the
   country field). Two ways:

### Option A — manual (quick start)

Account portal → *Download Databases* → **GeoLite2 Country** → GZIP →
extract the `.mmdb`:

```bash
tar -xzf GeoLite2-Country_*.tar.gz --strip-components=1 -C /var/lib/geoip \
  --wildcards '*/GeoLite2-Country.mmdb'
```

### Option B — `geoipupdate` (recommended for keeping it fresh)

```bash
# macOS:  brew install geoipupdate
# Debian: apt-get install geoipupdate
```

Config (`/etc/GeoIP.conf`, or `/usr/local/etc/GeoIP.conf` via brew):

```
AccountID  YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-Country
DatabaseDirectory /var/lib/geoip
```

```bash
geoipupdate -v        # downloads/refreshes into DatabaseDirectory
```

---

## 3. Wire it up

Point `GEOIP_DB_PATH` at the file, alongside the dashboard vars:

```bash
ADMIN_DB_PATH=/var/lib/bollwark/admin.db
ADMIN_TOKEN=<openssl rand -hex 32>
GEOIP_DB_PATH=/var/lib/geoip/GeoLite2-Country.mmdb
```

Then **restart** the service.

---

## 4. Verify

On boot you should see one of:

```
INFO  Geo enrichment enabled (GeoIP db=/var/lib/geoip/GeoLite2-Country.mmdb)
WARN  GEOIP_DB_PATH=… : <error> — geo enrichment disabled
```

Check the analytics endpoint exposes the field (empty array until traffic
flows through with geo on):

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:3000/v1/admin/analytics?hours=24" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['countries'])"
```

Then open `/static/admin.html` → **Analytics** tab → the **Countries** panel.

---

## 5. How it behaves (operational semantics)

- **Stamped at write time, on the logged IP.** The lookup runs in the
  decision-log writer thread on the IP as stored — which, with
  `ANONYMIZE_LOG_IP=true` (the default), is the /24 (IPv4) or /48 (IPv6)
  prefix. A network prefix still resolves country-level, so accuracy is
  unaffected. Zero cost on the request hot path.
- **Only new rows get a country.** The code is denormalized into the row at
  insert time. Enabling geo (or swapping the `.mmdb`) only affects rows logged
  *afterward*; existing rows keep `country = NULL`.
- **Unknown → NULL.** Private/reserved IPs (`127.0.0.1`, `10.x`, `192.168.x`)
  and addresses not in the database resolve to NULL and are simply absent from
  the Countries panel. Expect an empty panel in local dev.
- **Fail-soft.** A missing or corrupt `.mmdb` logs a `WARN` and disables
  enrichment — it never blocks boot.
- **Retention applies.** The `country` column lives in the decision log, so
  `LOG_RETENTION_HOURS` (default 72h) prunes it along with everything else.

---

## 6. Keeping the database fresh

GeoLite2 is republished **twice a week** (Tuesdays & Fridays). Stale geo data
just means a few mis-attributed IPs — not an outage — so weekly is fine.

> ⚠️ **There is no hot-reload.** Unlike the IP-reputation file (which has an
> fs-watcher), the `.mmdb` is read **once at boot**. After `geoipupdate`
> rewrites the file you must **restart the service** to pick it up.

Example weekly cron (update, then restart):

```cron
# Sundays 03:00 — refresh GeoLite2 and restart the captcha service
0 3 * * 0  geoipupdate && systemctl restart bollwark
```

---

## 7. Docker

Mount the database read-only and pass the path:

```yaml
services:
  captcha:
    image: bollwark
    environment:
      ADMIN_DB_PATH: /data/admin.db
      ADMIN_TOKEN:   ${ADMIN_TOKEN}
      GEOIP_DB_PATH: /geoip/GeoLite2-Country.mmdb
    volumes:
      - ./data:/data
      - /var/lib/geoip:/geoip:ro
```

Since there's no hot-reload, re-create the container after updating the file
(`docker compose up -d --force-recreate captcha`).

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `…geo enrichment disabled` WARN at boot | Wrong path, file missing, or not a valid `.mmdb`. Check `ls -l $GEOIP_DB_PATH`. |
| Boot shows neither the enabled INFO nor the WARN | `ADMIN_DB_PATH` isn't set — the dashboard (and therefore geo) is off entirely. |
| Countries panel empty despite enabled | No traffic logged *since* enabling, or all traffic is local/private IPs (→ NULL). Generate real traffic and wait for the 3s poll. |
| Old rows have no country, new ones do | Expected — country is stamped at write time, not backfilled. |
| Updated the `.mmdb` but counts didn't change | No hot-reload — restart the service. |
| `country` codes look wrong for known IPs | Stale database — run `geoipupdate` and restart. |

---

## 9. Privacy / GDPR notes

Built to be **defensible and data-minimizing**, but the final compliance
determination is the data controller's (you), not the code's.

- **Offline — nothing leaves the box.** The lookup is a local mmdb walk; no IP
  is sent to any third party, so no international-transfer (Art. 44+) concern,
  unlike a cloud geo API.
- **Runs on the truncated IP** (default posture) and **stores only a 2-letter
  code** — the country code alone isn't personal data. Data minimization,
  Art. 5(1)(c).
- **Retention-limited** via `LOG_RETENTION_HOURS`. Storage limitation,
  Art. 5(1)(e).
- **Caveat — separate purpose.** The anti-bot legitimate interest (Art. 6(1)(f))
  covers *scoring*. Geo is analytics, not enforcement, so cover it in your
  legitimate-interest assessment and name it in your privacy notice / Art. 30
  records.
- **Caveat — `ANONYMIZE_LOG_IP=false`.** Then geo (and the whole log) runs on
  full IPs — a bigger footprint. The "clean" framing only holds in the default
  anonymize-on config.
- **Licensing (not GDPR).** GeoLite2 carries MaxMind's
  [EULA](https://www.maxmind.com/en/geolite2/eula) — attribution and a
  requirement to use reasonably current data. Keeping `geoipupdate` on a
  schedule satisfies the latter.

---

## 10. Related env vars

| Var | Default | Role here |
|---|---|---|
| `GEOIP_DB_PATH` | _unset_ | Path to the `.mmdb`. Off when unset. |
| `ADMIN_DB_PATH` | _unset_ | Decision log holding the `country` column. **Required** for geo. |
| `ADMIN_TOKEN` | _unset_ | Dashboard bearer. Required when `ADMIN_DB_PATH` is set. |
| `ANONYMIZE_LOG_IP` | `true` | Truncates the logged IP the lookup runs on. Leave on. |
| `LOG_RETENTION_HOURS` | `72` | Prunes the `country` column along with each row. |
