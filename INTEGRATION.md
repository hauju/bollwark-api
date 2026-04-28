# Integration Guide

This guide shows the full flow for adding rust-captcha to a real application:

1. Run the CAPTCHA service.
2. Register your application as a site.
3. Embed the browser widget in your form.
4. Parse the widget token in your backend.
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
SITE_DB_PATH=/var/lib/rust-captcha/sites.db
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
  "secret_key": "hex-encoded-secret"
}
```

Use the keys this way:

| Key | Where it goes |
|---|---|
| `site_key` | Public frontend HTML, inside the widget |
| `secret_key` | Private backend config only |

Never expose `secret_key` to the browser.

## 3. Embed the Widget

Add the stylesheet, widget container, and script to the form you want to protect.

```html
<link rel="stylesheet" href="https://captcha.example.com/static/captcha-widget.css">

<form action="/signup" method="post">
  <label>
    Email
    <input type="email" name="email" required>
  </label>

  <div data-sitekey="<SITE_KEY>"></div>

  <button type="submit">Create account</button>
</form>

<script src="https://captcha.example.com/static/captcha-widget.js"></script>
```

When the script is loaded from `https://captcha.example.com`, the widget automatically uses that origin for `GET /v1/puzzle` and worker assets.

If you bundle or proxy the script from your own app origin, set `data-server-url` explicitly:

```html
<div
  data-sitekey="<SITE_KEY>"
  data-server-url="https://captcha.example.com"
></div>
```

The widget writes a hidden form field named `captcha-token`. Its value is a JSON string:

```json
{
  "challenge_id": "00000000-0000-0000-0000-000000000000",
  "nonce": 123456,
  "time_on_page_ms": 4200,
  "behavior": {
    "mouse_moves": 12,
    "touches": 0,
    "interactions": 3,
    "first_interaction_ms": 800,
    "webdriver": false
  }
}
```

Your backend must parse this field and forward the values to `/v1/verify`.

## 4. Verify on Your Backend

Your form handler should reject the submission if:

- `captcha-token` is missing.
- `captcha-token` is not valid JSON.
- `/v1/verify` does not return HTTP 200.
- `/v1/verify` returns `{ "success": false }`.

Request:

```bash
curl -s -X POST https://captcha.example.com/v1/verify \
  -H "Authorization: Bearer <SECRET_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_id": "00000000-0000-0000-0000-000000000000",
    "nonce": 123456,
    "time_on_page_ms": 4200,
    "behavior": {
      "mouse_moves": 12,
      "touches": 0,
      "interactions": 3,
      "first_interaction_ms": 800,
      "webdriver": false
    }
  }'
```

Successful response:

```json
{ "success": true }
```

Failed response:

```json
{ "success": false }
```

Challenges are single-use. A second submit with the same `challenge_id` will fail.

## 5. Backend Example: Express

```js
app.post("/signup", express.urlencoded({ extended: false }), async (req, res) => {
  let token;
  try {
    token = JSON.parse(req.body["captcha-token"] || "null");
  } catch {
    return res.status(400).send("CAPTCHA failed");
  }

  if (!token || !token.challenge_id || token.nonce === undefined) {
    return res.status(400).send("CAPTCHA failed");
  }

  const verifyResp = await fetch("https://captcha.example.com/v1/verify", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.RUST_CAPTCHA_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      challenge_id: token.challenge_id,
      nonce: token.nonce,
      honeypot: token.honeypot,
      time_on_page_ms: token.time_on_page_ms,
      behavior: token.behavior,
    }),
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
struct CaptchaToken {
    challenge_id: uuid::Uuid,
    nonce: u64,
    honeypot: Option<String>,
    time_on_page_ms: Option<u64>,
    behavior: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct VerifyResponse {
    success: bool,
}

async fn verify_captcha(token_json: &str) -> anyhow::Result<bool> {
    let token: CaptchaToken = serde_json::from_str(token_json)?;

    let client = reqwest::Client::new();
    let resp = client
        .post("https://captcha.example.com/v1/verify")
        .bearer_auth(std::env::var("RUST_CAPTCHA_SECRET_KEY")?)
        .json(&serde_json::json!({
            "challenge_id": token.challenge_id,
            "nonce": token.nonce,
            "honeypot": token.honeypot,
            "time_on_page_ms": token.time_on_page_ms,
            "behavior": token.behavior,
        }))
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

If your app runs at `https://app.example.com` and rust-captcha runs at `https://captcha.example.com`, set:

```bash
CORS_ALLOWED_ORIGINS="https://app.example.com"
```

This allows the browser widget to fetch puzzles and static worker assets.

To enable the trust-cookie risk signal cross-origin, also set:

```bash
COOKIE_SIGNING_SECRET=<long-random-secret>
COOKIE_SAMESITE=None
COOKIE_SECURE=true
```

`COOKIE_SAMESITE=None` requires HTTPS. The service refuses to start with `COOKIE_SAMESITE=None` and `COOKIE_SECURE=false`.

## 8. Production Checklist

Before using this in a real application:

- Set `ADMIN_TOKEN` to a long random value.
- Set `SITE_DB_PATH` so registered sites survive restarts.
- Store `secret_key` only in backend secrets/config.
- Put the service behind HTTPS.
- Set `CORS_ALLOWED_ORIGINS` to your app origin.
- Set `COOKIE_SIGNING_SECRET`, `COOKIE_SAMESITE=None`, and `COOKIE_SECURE=true` if you want cross-origin trust cookies.
- Configure `TRUSTED_PROXIES` if you rely on `X-Forwarded-For` or TLS fingerprint headers.
- Keep `/v1/verify`, `/v1/sites`, and `/v1/admin/*` server-to-server only.
- Monitor `puzzle_decision` and `verify_decision` logs before tightening thresholds.

Optional dashboard:

```bash
ADMIN_DB_PATH=/var/lib/rust-captcha/decisions.db
ADMIN_TOKEN=<same-admin-token>
```

Then open:

```text
https://captcha.example.com/static/admin.html
```

## 9. Error Handling

Common responses:

| Case | Response | What to do |
|---|---|---|
| Missing or bad `site_key` | `400` from `/v1/puzzle` | Check frontend config |
| High-risk puzzle request | `429` from `/v1/puzzle` | Show a retry/error state or fall back to your own moderation path |
| Missing verify auth | `401` from `/v1/verify` | Check backend `secret_key` |
| Challenge expired | `410` from `/v1/verify` | Ask user to retry the form |
| Replayed challenge | `404` or `409` from `/v1/verify` | Ask user to retry; do not accept the form |
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
