# Vendored browser libraries

## argon2.umd.min.js

- **Source**: [hash-wasm](https://github.com/Daninet/hash-wasm) v4.12.0 — `dist/argon2.umd.min.js`.
- **License**: MIT (Dani Biro). Header preserved at the top of the file.
- **Why vendored**: loaded by `captcha-worker.js` via `importScripts("vendor/argon2.umd.min.js")` when the server issues an Argon2id challenge. Vendoring avoids a runtime CDN dependency and any CSP `script-src` headaches on the host site.
- **Re-fetch**:
  ```sh
  curl -fsSL -o static/vendor/argon2.umd.min.js \
    https://cdn.jsdelivr.net/npm/hash-wasm@4.12.0/dist/argon2.umd.min.js
  ```
