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

### Optional: start in monitor mode

If you're putting this in front of an existing form and want to see what it
would do before it does it, register the site with `"mode": "monitor"`. Every
verdict is scored and logged as usual, but no visitor is ever refused — a
Block-tier request gets a max-difficulty puzzle instead of a `429`, and a
verify-time block returns `success: true`.

```bash
-d '{"name":"contact-form","policy":{"mode":"monitor"}}'
```

Watch `GET /v1/admin/stats` (`outcomes.verify_monitored`) for a week, then
`PUT .../policy` with `{"mode":"enforce"}`. The scoring is identical in both
modes, so nothing about the numbers changes when you flip it.

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

### Accessibility

The widget is operable without a mouse. The checkbox is reachable by <kbd>Tab</kbd> and activated with <kbd>Space</kbd> or <kbd>Enter</kbd>, carries `role="checkbox"` with an `aria-checked` value that tracks verification, and shows a focus outline. State changes ("Solving challenge…", "Verified", "Verification failed") and the block/failover messages are announced through live regions rather than being visual-only, and the widget's container is tagged with the resolved `lang` so translated text is pronounced correctly.

Nothing is required of you to get this — but if you restyle the widget, keep a visible `:focus` indicator on `.rc-captcha-checkbox`. `e2e/tests/a11y.spec.ts` covers the whole keyboard path, including a full form submission with no mouse events at all.

> Keyboard and screen-reader use carries **no scoring penalty**. The behavioural signal's "no pointer movement" penalty only applies to submissions that also show at most one interaction — the isolated synthetic click it was written to catch. Anyone navigating by keyboard produces an interaction per keystroke, Tab and scroll, so they score zero on it.

### Language

The widget ships translated. Bundled locales: **en, de, fr, es, it, nl**. English is the fallback, applied per string — a locale that is missing one entry falls back for that entry alone.

The locale is picked from the first source that names a bundled language, most explicit first:

1. **`data-lang`** on the widget container — an explicit override, and the only way to pin a language different from the page's.
2. **`<html lang>`** — the page already declares what language it's in.
3. **`navigator.language`** — the visitor's browser preference, for pages that declare no language.

`<html lang>` deliberately outranks the browser: a widget sitting inside a German form should read German even for a visitor whose browser is set to English. Regional tags resolve to their base language (`de-AT` → `de`), and an unrecognised tag falls through to the next source rather than straight to English.

Most integrations need nothing — a page with `<html lang="de">` gets a German widget automatically. Override only when the widget's language should differ from the document's:

```html
<div data-sitekey="<SITE_KEY>" data-lang="fr"></div>
```

The widget also sets `lang` on its own container so screen readers pronounce the translated text correctly.

**Adding a language:** the strings live in one `TRANSLATIONS` table at the top of `static/captcha-widget.js` — eleven entries, no build step. `de` is maintained by the project; `fr`/`es`/`it`/`nl` follow the conventional phrasing other CAPTCHA widgets established but have not had a native review, so corrections are welcome. The `data-debug` panel is intentionally English — it's a developer tool.

The widget writes a hidden form field named `captcha-token` whose value is a single **opaque token** (a hex string). It already carries everything `/v1/verify` needs — the challenge id, the PoW nonce, the honeypot, and behavioural telemetry. Your backend treats it as a black box: read the field and forward it verbatim. There is nothing to parse.

```
a3f1c0...    # opaque; do not parse or depend on its contents
```

> Dwell time is **not** carried in the token. The server derives it from the challenge's issuance timestamp, so a bot can't claim a longer time-on-page than actually elapsed.

### Single-page apps: when nothing posts a form

The flow above assumes a real form submission. If your form is a React/Vue/Svelte/Dioxus component that calls an API instead, the widget still works and still writes `captcha-token` into the enclosing `<form>` — nothing posts it, so you read the value out and send it yourself.

Three things differ:

1. **Mount the widget after the component renders.** The script's auto-init runs once at `DOMContentLoaded`; a form inside a modal or a route that mounts later was never on the page then. Call `window.Bollwark.scan()` after your component mounts — it tags what it mounts, so re-running is a no-op rather than a second widget.
2. **Read the token at submit time**, not at mount: `document.querySelector('input[name="captcha-token"]').value`. The widget rewrites that field on submit so the behavioural counters reflect the visitor's actual interaction.
3. **Keep the `<div data-sitekey>` inside a `<form>` element.** The widget walks up to the nearest form to inject its hidden field; with no form ancestor there is nowhere to write the token. The form never has to be *submitted* — it just has to exist.

```js
// after your component mounts
window.Bollwark && window.Bollwark.scan();

// at submit
const el = document.querySelector('input[name="captcha-token"]');
await api.signup({ email, captchaToken: el ? el.value : "" });
```

Your backend then calls `/v1/verify` with that string exactly as below — the token is opaque either way, and nothing about the server side changes.

> **Cross-origin**: the widget fetches its puzzle from wherever the script came from. If that's a different origin to your app (the usual case), that origin must list yours in `CORS_ALLOWED_ORIGINS`, or `GET /v1/puzzle` is blocked by the browser before the widget ever renders.

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
