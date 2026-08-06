# Integration Guide

This guide shows the full flow for adding bollwark to a real application:

1. Run the CAPTCHA service.
2. Register your application as a site.
3. Embed the browser widget in your form.
4. Forward the opaque widget token from your backend.
5. Verify the token server-to-server before accepting the form.

## 1. Run the Service

For local development:

```bash
export ADMIN_TOKEN=$(openssl rand -hex 32)
export SITE_DB_PATH=tmp/sites.db
cargo run
```

The service listens on `http://localhost:3000` by default.

`ADMIN_TOKEN` protects site provisioning and admin APIs. `SITE_DB_PATH` persists registered sites so restarts do not invalidate your `secret_key`.

For production, also set a stable bind address and run behind TLS:

```bash
LISTEN_ADDR=127.0.0.1:3000
ADMIN_TOKEN=<long-random-secret>
SITE_DB_PATH=/var/lib/bollwark/sites.db
```

## 2. Register a Site

Call `POST /v1/sites` once for each application or environment.

```bash
curl -s -X POST http://localhost:3000/v1/sites \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-production-app"}' | jq
```

Response:

```json
{
  "site_key": "00000000-0000-0000-0000-000000000000",
  "secret_key": "hex-encoded-secret",
  "allowed_origins": [],
  "policy": {}
}
```

Use the keys this way:

| Key | Where it goes |
|---|---|
| `site_key` | Public frontend HTML, inside the widget |
| `secret_key` | Private backend config only |

Never expose `secret_key` to the browser.

### Optional: restrict browser origins

Pass an `allowed_origins` array to limit which origins can request puzzles for
this `site_key`:

```bash
curl -s -X POST http://localhost:3000/v1/sites \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-app","allowed_origins":["https://app.example.com"]}' | jq
```

Each entry is a full web origin — `http(s)://host[:port]`, no path or trailing
slash (up to 32 entries; values are lowercased and validated, a bad entry
returns `400`). When the list is non-empty, `GET /v1/puzzle` returns `403` to a
browser whose `Origin` header isn't on the list. Requests with **no** `Origin`
header (same-origin embeds, server-to-server calls) always pass.

This is **tenant hygiene, not bot defense**: it stops a third party from
embedding your public `site_key` on their own page and burning your quota or
polluting your stats. It is *not* a security control — a non-browser client can
forge the `Origin` header, so the real trust boundary stays the `secret_key` at
`/v1/verify`. Change the list later without rotating the secret via
`PUT /v1/admin/sites/{site_key}/origins` with the same `allowed_origins` body.

### Optional: tune the thresholds for this site

By default every site is scored with the server's env-var thresholds. Pass a
`policy` to override any of them for this `site_key` alone — useful when one
instance protects forms with different risk profiles (a contact form and a
login endpoint want very different bands):

```bash
curl -s -X POST http://localhost:3000/v1/sites \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name":"login",
        "policy":{"tier_hard_pow_min":25,"tier_block_min":60,"verify_block_min":30}
      }' | jq
```

Omitted fields inherit the server value (and keep tracking it if the operator
changes it later), so a policy only ever states what differs. Change it later
with `PUT /v1/admin/sites/{site_key}/policy` — the body replaces the stored
policy wholesale, so `{}` clears every override. See **Per-site policy** in
`CONFIGURATION.md` for the full field list and the validation rules.

## 3. Embed the Widget

Add the widget container and one script tag to the form you want to protect.

```html
<form action="/signup" method="post">
  <label>
    Email
    <input type="email" name="email" required>
  </label>

  <div data-sitekey="<SITE_KEY>"></div>

  <button type="submit">Create account</button>
</form>

<script src="https://api.bollwark.eu/v1/widget.js"></script>
```

> Examples here use `https://api.bollwark.eu`, the hosted endpoint. Self-hosting? Substitute your own host throughout — nothing below is specific to ours.

`/v1/widget.js` is the entry point, and the only URL you should ever hardcode. It loads the stylesheet, the PoW worker and the Argon2 bundle itself, from a content-hashed directory pinned to that exact widget build — so a deploy can never leave you with a new widget talking to a worker your browser cached last month. The entry point is cached for 5 minutes; everything it pulls is cached for a year and never mutates.

Because the script is served from `https://api.bollwark.eu`, the widget uses that origin for `GET /v1/puzzle` and its assets automatically. Nothing else to configure.

If you bundle or proxy the script from your own app origin instead, set `data-server-url` explicitly:

```html
<div
  data-sitekey="<SITE_KEY>"
  data-server-url="https://api.bollwark.eu"
></div>
```

<details>
<summary>Older embeds using <code>/static/captcha-widget.js</code></summary>

The previous embed — a `<link>` for `/static/captcha-widget.css` plus a `<script>` for `/static/captcha-widget.js` — keeps working and is not going away. It just doesn't get the version pinning: those paths are unversioned, so the widget and worker are cached independently. Moving over is deleting the `<link>` and repointing the `<script>` at `/v1/widget.js`. If you keep your own `<link>`, the widget detects it and won't inject a second one.

</details>

### Widget Modes

The widget has two modes selected via `data-mode`:

- **`data-mode="default"`** (used when the attribute is omitted): the checkbox row and brand footer always render. The visible UX is uniform across pass tiers — visitors always see the same "I'm not a robot" → spinner → "Verified" sequence. On low-risk visitors (`invisible_pass`) the widget auto-runs the spinner without a click; on higher tiers it waits for a click. This is the simplest integration — no other wiring required.
- **`data-mode="invisible"`**: the widget renders no chrome at all for the `invisible_pass` tier — PoW runs in the background and the `captcha-token` field is injected silently when the visitor submits. If the server escalates the tier, the widget falls back to its visible UI on demand:
  - `invisible_pass` → no UI, silent PoW.
  - `checkbox` / `hard_pow` → checkbox appears, visitor clicks.
  - `block` → **the widget renders nothing**. Your page must listen for the `bollwark:puzzle` event to surface a failure UX (an inline message, a redirect, or anything else). Without a listener the block is silent and the visitor sees nothing happen. The widget logs a one-shot `console.warn` in this case to flag missed wiring during development.

```html
<div id="captcha" data-sitekey="<SITE_KEY>" data-mode="invisible"></div>
<script>
  document.getElementById("captcha").addEventListener("bollwark:puzzle", (e) => {
    // e.detail = { ok, tier, difficulty?, error? }
    if (!e.detail.ok) {
      // tier === "block" for HTTP 429; null on network/fetch errors.
      showSignupBlockedMessage(e.detail.tier);
    }
  });
</script>
```

The `bollwark:puzzle` event fires in default mode too if you want to drive your own UI alongside the widget — it bubbles, so a listener on a parent element works.

### Theme

The widget's appearance follows `data-theme`:

- **`data-theme="auto"`** (used when the attribute is omitted): follows the visitor's OS via `prefers-color-scheme` — light on a light OS, dark on a dark one.
- **`data-theme="light"`** / **`data-theme="dark"`**: force a fixed palette. Use this to match a host whose theme is fixed regardless of the OS (e.g. an always-dark dashboard).

```html
<div data-sitekey="<SITE_KEY>" data-theme="dark"></div>
```

The widget writes a hidden form field named `captcha-token` whose value is a single **opaque token** (a hex string). It already carries everything `/v1/verify` needs — the challenge id, the PoW nonce, the honeypot, and behavioural telemetry. Your backend treats it as a black box: read the field and forward it verbatim. There is nothing to parse.

```
a3f1c0...    # opaque; do not parse or depend on its contents
```

> Dwell time is **not** carried in the token. The server derives it from the challenge's issuance timestamp, so a bot can't claim a longer time-on-page than actually elapsed.

## 4. Verify on Your Backend

Your form handler should reject the submission if:

- `captcha-token` is missing or empty.
- `/v1/verify` does not return HTTP 200.
- `/v1/verify` returns `{ "success": false }`.

Forward the token verbatim:

```bash
curl -s -X POST https://api.bollwark.eu/v1/verify \
  -H "Authorization: Bearer <SECRET_KEY>" \
  -H "Content-Type: application/json" \
  -d '{ "token": "<captcha-token value>" }'
```

> **Server-to-server callers** that build the request without the widget can send the explicit fields instead of `token`: `challenge_id` plus `nonce`, with optional `honeypot` and `behavior`.

Successful response:

```json
{ "success": true, "failover": false }
```

Failed response:

```json
{ "success": false, "failover": false }
```

Challenges are single-use. A second submit with the same `challenge_id` will fail.

### The `failover` field

`failover: true` means `success` was granted **without a solved puzzle**, because the captcha service was attestably unreachable when the visitor loaded your form. It's off unless the operator enabled client failover (see `CONFIGURATION.md`).

If you don't care, keep reading `success` alone — you get availability during outages by default. If you do, this is the hook for accept-but-flag:

```js
if (!result.success) return res.status(400).send("CAPTCHA failed");
if (result.failover) {
  // Verified only in the weak sense: the service was down, so no proof of
  // work was possible. The honeypot and behavioural signals were still
  // checked. Reasonable responses: accept but queue for review, tighten a
  // downstream rate limit, or require email confirmation before acting.
  logger.warn({ userId }, "captcha failover — accepted without proof of work");
}
```

## 4b. When the captcha service is down

Two failure modes the `failover` field does **not** cover, because in both of them there's no verify response to read.

**The widget script never loads.** A TLS, DNS, or CDN failure on `/v1/widget.js` means no widget code runs at all — so it can't fall back on your behalf. Only your page can detect this:

```html
<script src="https://api.bollwark.eu/v1/widget.js"
        onerror="captchaUnavailable()"></script>
<script>
  // Also guard the case where the script loads but never initialises.
  const t = setTimeout(captchaUnavailable, 8000);
  document.querySelector('.bollwark-widget')
    ?.addEventListener('bollwark:puzzle', () => clearTimeout(t));

  function captchaUnavailable() {
    // Your call: allow the submit (and flag it server-side), or disable it
    // with an explanation. Silently leaving the form unsubmittable is the
    // one option to avoid.
    document.querySelector('#signup button[type=submit]').disabled = false;
  }
</script>
```

**Your backend can't reach `/v1/verify`.** A connection error or timeout is not a failed verification — it's an unknown. Decide deliberately, and don't let it read as `success: false` by accident:

```js
let result;
try {
  result = await verifyCaptcha(token);
} catch (err) {
  // Fail open or closed — a real choice, not a default. Fail closed is safer
  // for account creation or payments; fail open is usually right for a
  // contact form, where blocking every visitor is the worse outcome.
  logger.error({ err }, "captcha verify unreachable");
  if (FAIL_CLOSED) return res.status(503).send("Try again shortly");
  result = { success: true, failover: true };
}
```

The widget also emits `bollwark:puzzle` with `detail.failover === true` when it enters failover mode, and `detail.recovered === true` if the service comes back and it upgrades to a real solved token in place.

## 5. Backend Example: Express

```js
app.post("/signup", express.urlencoded({ extended: false }), async (req, res) => {
  const token = req.body["captcha-token"];
  if (!token) {
    return res.status(400).send("CAPTCHA failed");
  }

  const verifyResp = await fetch("https://api.bollwark.eu/v1/verify", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.BOLLWARK_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  });

  if (!verifyResp.ok) {
    return res.status(400).send("CAPTCHA failed");
  }

  const result = await verifyResp.json();
  if (!result.success) {
    return res.status(400).send("CAPTCHA failed");
  }

  // CAPTCHA passed. Continue with your real signup logic.
  res.send("ok");
});
```

## 6. Backend Example: Rust

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct VerifyResponse {
    success: bool,
}

/// `token` is the opaque value of the hidden `captcha-token` field, forwarded
/// verbatim — no parsing.
async fn verify_captcha(token: &str) -> anyhow::Result<bool> {
    if token.is_empty() {
        return Ok(false);
    }

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.bollwark.eu/v1/verify")
        .bearer_auth(std::env::var("BOLLWARK_SECRET_KEY")?)
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(false);
    }

    let result: VerifyResponse = resp.json().await?;
    Ok(result.success)
}
```

## 7. Cross-Origin Setup

If your app runs at `https://app.example.com` and bollwark runs at `https://api.bollwark.eu`, set:

```bash
CORS_ALLOWED_ORIGINS="https://app.example.com"
```

This allows the browser widget to fetch puzzles and static worker assets.

The service is cookie-free, so cross-origin embeds need no `SameSite` or credentials handling.

## 8. Production Checklist

Before using this in a real application:

- Set `ADMIN_TOKEN` to a long random value.
- Set `SITE_DB_PATH` so registered sites survive restarts.
- Store `secret_key` only in backend secrets/config.
- Put the service behind HTTPS.
- Set `CORS_ALLOWED_ORIGINS` to your app origin.
- Decide whether to enable IP reputation (`IP_REPUTATION_FILE`) and TLS fingerprinting (`TLS_FINGERPRINT_HEADER` + `TRUSTED_PROXIES`). Both self-gate on their own config and stay off until set; enabling either gives stronger scoring but adds a fingerprinting signal, so update your DPIA accordingly. The service is otherwise cookie-free and runs every signal under legitimate interest with data minimization.
- Configure `TRUSTED_PROXIES` if you rely on `X-Forwarded-For` or TLS fingerprint headers.
- Keep `/v1/verify`, `/v1/sites`, and `/v1/admin/*` server-to-server only.
- Monitor `puzzle_decision` and `verify_decision` logs before tightening thresholds.

Optional dashboard:

```bash
ADMIN_DB_PATH=/var/lib/bollwark/decisions.db
ADMIN_TOKEN=<same-admin-token>
```

Then open:

```text
https://api.bollwark.eu/static/admin.html
```

## 9. Error Handling

Common responses:

| Case | Response | What to do |
|---|---|---|
| Missing or bad `site_key` | `400` from `/v1/puzzle` | Check frontend config |
| Origin not on the site's allowlist | `403` from `/v1/puzzle` | Add the embedding origin via `allowed_origins`, or leave the allowlist empty to allow any origin. |
| High-risk puzzle request (`block` tier) | `429` from `/v1/puzzle` | Show a retry/error state or fall back to your own moderation path. |
| Missing verify auth | `401` from `/v1/verify` | Check backend `secret_key` |
| Challenge expired | `410` from `/v1/verify` | Ask user to retry the form |
| Replayed challenge | `404` from `/v1/verify` (single-use: the challenge is removed on the first successful verify) | Ask user to retry; do not accept the form |
| Valid PoW but blocked risk score | `{ "success": false }` | Reject or queue for manual review |

## 10. Local Test Harness

Run the service, then open:

```text
http://localhost:3000/static/testsite.html
```

With `ADMIN_TOKEN` set, the test page prompts for it and registers a test site. In debug builds, you can skip the prompt for local/e2e testing:

```bash
DEV_DISABLE_ADMIN_AUTH=1 SITE_DB_PATH=tmp/sites.db cargo run
```

Do not use `DEV_DISABLE_ADMIN_AUTH=1` in production. Release builds ignore it.
