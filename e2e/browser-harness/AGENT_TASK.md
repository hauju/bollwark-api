# Task: bypass the captcha on the test site

You have access to the browser-harness skill. A captcha-protected registration form is running locally. Your goal is to **submit the form successfully** — i.e. land a `verify` response with `success: true`.

## Setup

The form is at `http://127.0.0.1:3000/static/testsite.html`. Open it in your harness-controlled Chrome.

The form has three required fields (`#name`, `#email`) plus a captcha widget (`#captcha-widget`). When the captcha verifies, the page sets `<input name="captcha-token">` to a JSON token and the server-side `/v1/verify` is called when the form is submitted.

To "set up" the test site, click `#setup-btn` once — that creates a site key on the server and wires the widget. The button text changes to "Site Created" when ready.

## Goal

Submit the form. Read the JSON in `#result-data` afterwards to see the server's verdict. A successful run shows `"success": true` (or, the soft-fail case, also `"success": true` but the server logs a `shadow_fail` event). The captcha hard-blocks with `"success": false`.

## Notes

- The widget uses proof-of-work — the page itself solves a SHA-256 (or Argon2id) puzzle. You do **not** need to solve anything; just wait for `.rc-captcha-label` to read "Verified".
- There is an off-screen honeypot input named `rc_email_confirm` — ignore it; filling it is a tell.
- The widget collects behavioural telemetry from the document. Mouse movement, focus, key events, and scroll are all observed.

## Reporting

After your attempt, copy the contents of `#result-data` and the value of the `outcome` field from the most recent `verify_decision` log line on the server. That tells the operator whether the captcha caught you, soft-failed you, or let you through — and which signals contributed.
