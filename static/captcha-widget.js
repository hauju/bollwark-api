// RustCaptcha Widget — SHA-256 proof-of-work with risk-tier-aware UI.

(function () {
  "use strict";

  const SCRIPT_SRC = document.currentScript && document.currentScript.src;
  const DEFAULT_SERVER_URL = inferServerUrl(SCRIPT_SRC);

  function inferServerUrl(scriptSrc) {
    if (!scriptSrc) return "";
    try {
      const url = new URL(scriptSrc, window.location.href);
      return url.origin === window.location.origin ? "" : url.origin;
    } catch (_) {
      return "";
    }
  }

  function isCrossOrigin(url) {
    try {
      return new URL(url, window.location.href).origin !== window.location.origin;
    } catch (_) {
      return false;
    }
  }

  // Hex-encode a UTF-8 JSON payload into the opaque token the form host
  // forwards to /v1/verify. Hex (not base64) matches the server's existing
  // token conventions and decodes with the same `hex` crate.
  function encodeToken(payload) {
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  // ── CaptchaWidget Class ──

  /**
   * RustCaptcha widget.
   *
   * Modes (`data-mode` attribute / `mode` option):
   *
   *   "default" — always renders the checkbox + brand footer chrome.
   *     The visible UX is uniform across pass tiers: visitors always see
   *     the same "I'm not a robot" → spinner → "Verified" sequence. On
   *     `invisible_pass` the widget auto-runs the spinner; on `checkbox`
   *     / `hard_pow` it waits for a click. The visitor can't tell which
   *     tier the server picked, which is intentional.
   *
   *   "invisible" — renders no chrome until/unless the tier requires
   *     user interaction:
   *       invisible_pass → silent PoW + onVerify; no UI ever rendered.
   *       checkbox / hard_pow → checkbox UI appears; user clicks.
   *       block → widget renders nothing. The embedder MUST listen for
   *         the `rustcaptcha:puzzle` event (detail.ok=false) to surface
   *         a failure UX — otherwise the block is silent and the user
   *         sees nothing happen. A console.warn fires once on block to
   *         flag missed wiring during development.
   *
   * Event: `rustcaptcha:puzzle` (CustomEvent on the container, bubbles)
   *   detail = { ok, tier, difficulty?, error? }
   *     ok=true  → puzzle issued (or invisible-pass solving in the bg).
   *     ok=false → 429 (block) or fetch error; `tier="block"` for 429.
   */
  class CaptchaWidget {
    constructor(container, options) {
      this.container = container;
      this.siteKey = options.sitekey;
      this.serverUrl = options.serverUrl || DEFAULT_SERVER_URL;
      this.debug = options.debug === "true" || options.debug === true;
      // "invisible" defers all visible UI until the tier requires it.
      // Mirrors hCaptcha size=invisible / reCAPTCHA v3 → v2 fallback.
      this.mode = options.mode === "invisible" ? "invisible" : "default";
      this.onVerify = options.onVerify || null;

      this.state = "idle";
      this.worker = null;
      this.workerBlobUrl = null;
      this.solveStartTime = null;
      this.puzzle = null;
      this.tier = null;
      this._uiRendered = false;
      this.pageLoadAt = Date.now(); // ms since epoch; feeds the time-on-page signal at verify time

      // Behavioural telemetry: counters for the verify-time `behavior` blob.
      // We only count, never record paths or content — privacy and bandwidth.
      this._behavior = {
        mouse_moves: 0,
        touches: 0,
        interactions: 0,
        first_interaction_ms: null,
        // navigator.webdriver is set by CDP-driven Chromium (Playwright,
        // Puppeteer, Selenium, browser-harness in default mode). Captured
        // at mount because some stealth patches restore it later.
        webdriver: typeof navigator !== "undefined" && navigator.webdriver === true,
      };
      this._behaviorListeners = [];
      this._installBehaviorListeners();

      this._render();
      this._initFlow();
    }

    _installBehaviorListeners() {
      const opts = { passive: true, capture: true };
      const noteInteraction = () => {
        this._behavior.interactions++;
        if (this._behavior.first_interaction_ms === null) {
          this._behavior.first_interaction_ms = Date.now() - this.pageLoadAt;
        }
      };
      const onMouseMove = () => {
        this._behavior.mouse_moves++;
      };
      const onTouchStart = () => {
        this._behavior.touches++;
        if (this._behavior.first_interaction_ms === null) {
          this._behavior.first_interaction_ms = Date.now() - this.pageLoadAt;
        }
      };

      const bind = (target, type, handler) => {
        target.addEventListener(type, handler, opts);
        this._behaviorListeners.push(() =>
          target.removeEventListener(type, handler, opts)
        );
      };

      bind(document, "mousemove", onMouseMove);
      bind(document, "touchstart", onTouchStart);
      bind(document, "click", noteInteraction);
      bind(document, "keydown", noteInteraction);
      bind(document, "scroll", noteInteraction);
      bind(window, "focus", noteInteraction);
    }

    _teardownBehaviorListeners() {
      for (const off of this._behaviorListeners) off();
      this._behaviorListeners = [];
    }

    // Fetch the puzzle eagerly so we know the tier before any user interaction.
    // For `invisible_pass`, this also kicks off the auto-solve.
    async _initFlow() {
      if (!this.siteKey) return; // testsite delays setting siteKey; reset() will retry
      try {
        const puzzle = await this._fetchPuzzle();
        this.puzzle = puzzle;
        this.tier = puzzle.tier;
        this._dispatchPuzzleEvent({
          ok: true,
          tier: puzzle.tier,
          difficulty: puzzle.difficulty,
        });

        // Invisible mode renders nothing for `invisible_pass` — just runs
        // PoW silently and fires onVerify. Any other tier needs user
        // interaction (a checkbox click), so promote to the full visible UI.
        if (this.mode === "invisible" && this.tier === "invisible_pass") {
          this._runVerify();
        } else {
          this._promoteToInteractiveUI();
          this._applyInfoUrls(puzzle.info_urls);
          this._renderForTier();
        }
      } catch (err) {
        const blocked = err.status === 429;
        this.tier = blocked ? "block" : null;
        this.state = "failed";
        this._dispatchPuzzleEvent({
          ok: false,
          tier: this.tier,
          error: err.message,
        });

        // Invisible mode hands block-tier UX to the embedder via the
        // `rustcaptcha:puzzle` event — they decide whether to show an
        // inline message, redirect, or do nothing. The console.warn is a
        // one-shot dev-time hint: if the embedder forgot to wire the
        // listener, the page would otherwise look like nothing happened.
        if (this.mode === "invisible") {
          console.warn(
            "[RustCaptcha] invisible-mode " +
              (blocked ? "block (HTTP 429)" : "fetch error") +
              " — widget rendered no UI. Listen for the `rustcaptcha:puzzle` " +
              "event (detail.ok=false) on the container to surface a failure UX."
          );
          return;
        }

        // 429 (block) returns a JSON body with operator-overridden info
        // URLs even when rejecting — surface them now so the brand corner
        // points at the right Privacy/Terms even in block-tier.
        if (err.infoUrls) this._applyInfoUrls(err.infoUrls);
        this._renderBlocked(blocked ? "Verification unavailable" : err.message);
      }
    }

    _dispatchPuzzleEvent(detail) {
      this.container.dispatchEvent(
        new CustomEvent("rustcaptcha:puzzle", { detail, bubbles: true })
      );
    }

    // ── UI Rendering ──

    // Honeypot + (optionally) the visible UI. In invisible mode the visible
    // UI is deferred until `_promoteToInteractiveUI()` — the widget runs
    // silently for the `invisible_pass` tier and only materialises a
    // checkbox if the server escalates.
    _render() {
      this.container.innerHTML = "";
      this.container.classList.remove("rc-captcha");
      this._uiRendered = false;
      this._brandLinks = null;

      // Honeypot: invisible input a naive form-spamming bot fills.
      // The name MUST NOT contain semantic tokens like email/name/phone/
      // address — Chrome/Safari/password managers ignore autocomplete="off"
      // for those and autofill the hidden field with the user's real data,
      // tripping the honeypot for every legitimate user. Randomize per
      // instance so autofill heuristics can't memorize the name either.
      this.honeypot = document.createElement("input");
      this.honeypot.type = "text";
      this.honeypot.name = "rc_" + Math.random().toString(36).slice(2, 10);
      this.honeypot.autocomplete = "new-password";
      this.honeypot.tabIndex = -1;
      this.honeypot.setAttribute("aria-hidden", "true");
      this.honeypot.style.cssText =
        "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;";
      this.container.appendChild(this.honeypot);

      if (this.mode !== "invisible") {
        this._promoteToInteractiveUI();
      }
    }

    // Build the visible widget chrome: checkbox row, status line, debug
    // panel, brand footer. Idempotent — safe to call after `_render()`
    // promotes invisibly.
    _promoteToInteractiveUI() {
      if (this._uiRendered) return;
      this._uiRendered = true;

      this.container.classList.add("rc-captcha");

      this.row = document.createElement("div");
      this.row.className = "rc-captcha-row";

      this.checkbox = document.createElement("div");
      this.checkbox.className = "rc-captcha-checkbox";
      this.checkbox.addEventListener("click", () => this._onCheckboxClick());

      this.label = document.createElement("span");
      this.label.className = "rc-captcha-label";
      this.label.textContent = "I'm not a robot";

      this.row.appendChild(this.checkbox);
      this.row.appendChild(this.label);
      // Insert before the honeypot so visible flow goes row → status →
      // debug → footer, with the honeypot tucked anywhere off-screen.
      this.container.insertBefore(this.row, this.honeypot);

      this.statusEl = document.createElement("div");
      this.statusEl.className = "rc-captcha-status";
      this.container.appendChild(this.statusEl);

      if (this.debug) {
        this.detailsEl = document.createElement("div");
        this.detailsEl.className = "rc-captcha-details";
        this.container.appendChild(this.detailsEl);
      }

      // Brand corner: clickable name → about, with tiny Privacy / Terms
      // links stacked beneath. Mirrors the reCAPTCHA / hCaptcha pattern.
      // Sits at the right edge of the checkbox row (pushed over by
      // `margin-left:auto`) so "RustCaptcha" rides the same line as the
      // checkbox and the legal links hang just below it. `_renderBlocked`
      // hides only the checkbox + label, never the brand, so this stays
      // visible across every tier — invisible-pass, checkbox, and the 429
      // block path included — which is exactly when the user is most
      // likely to want "why am I seeing this?". Hrefs default to the
      // bundled /static/*.html and are patched by `_applyInfoUrls` once
      // the puzzle response (or 429 body) arrives with operator overrides.
      const brand = document.createElement("span");
      brand.className = "rc-captcha-brand";
      const linkBase = this.serverUrl || "";
      this._brandLinks = {};
      const brandLink = document.createElement("a");
      brandLink.className = "rc-captcha-brand-name";
      brandLink.href = linkBase + "/static/about.html";
      brandLink.target = "_blank";
      brandLink.rel = "noopener noreferrer";
      brandLink.textContent = "RustCaptcha";
      this._brandLinks.about = brandLink;
      const brandLinks = document.createElement("span");
      brandLinks.className = "rc-captcha-brand-links";
      [
        ["Privacy", "/static/privacy.html", "privacy"],
        ["Terms", "/static/terms.html", "terms"],
      ].forEach(([text, path, key], i) => {
        if (i > 0) brandLinks.appendChild(document.createTextNode(" · "));
        const a = document.createElement("a");
        a.href = linkBase + path;
        a.textContent = text;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        brandLinks.appendChild(a);
        this._brandLinks[key] = a;
      });
      brand.appendChild(brandLink);
      brand.appendChild(brandLinks);
      this.row.appendChild(brand);

      this._updateUI();
    }

    // Patch the brand-corner hrefs from operator-overridden URLs supplied
    // by the server (puzzle response or 429 body). Per-field: an unset
    // override leaves the bundled `/static/*.html` link untouched.
    _applyInfoUrls(infoUrls) {
      if (!infoUrls || !this._brandLinks) return;
      if (infoUrls.about) this._brandLinks.about.href = infoUrls.about;
      if (infoUrls.privacy && this._brandLinks.privacy) {
        this._brandLinks.privacy.href = infoUrls.privacy;
      }
      if (infoUrls.terms && this._brandLinks.terms) {
        this._brandLinks.terms.href = infoUrls.terms;
      }
    }

    // Branch the visible UI based on the tier the server assigned.
    _renderForTier() {
      // Default mode shows the same checkbox UI for every pass tier so
      // the visitor can't tell whether the server escalated. The only
      // behavioural difference: invisible_pass auto-runs the worker;
      // checkbox / hard_pow wait for a click.
      this.row.style.display = "";
      this._updateUI();
      if (this.tier === "invisible_pass") this._runVerify();
    }

    _renderBlocked(message) {
      // Hide the interactive checkbox + label, but keep the row — the
      // brand corner lives inside it now, and the Privacy / Terms links
      // must survive the block path (the "always a route to why am I
      // seeing this?" guarantee).
      if (this.checkbox) this.checkbox.style.display = "none";
      if (this.label) this.label.style.display = "none";
      if (this.statusEl) this.statusEl.textContent = message;
    }

    _updateUI() {
      // Invisible mode pre-promotion: no visible UI exists yet. Skip.
      if (!this._uiRendered) return;
      this.checkbox.className = "rc-captcha-checkbox";
      if (this.state === "verified") this.checkbox.classList.add("verified");
      else if (this.state === "failed") this.checkbox.classList.add("failed");
      else if (this.state === "solving") this.checkbox.classList.add("solving");

      const labels = {
        idle: "I'm not a robot",
        solving: "Solving challenge...",
        verified: "Verified",
        failed: "Verification failed",
      };
      this.label.textContent = labels[this.state] || "";

      if (this.state === "idle") {
        this.statusEl.textContent = "Click to verify";
      } else if (this.state === "solving") {
        this.statusEl.textContent = "";
      } else {
        this.statusEl.textContent = "";
      }

      if (this.debug && this.detailsEl) this._renderDetails();
    }

    _renderDetails() {
      if (!this.detailsEl) return;
      const rows = [];
      if (this.tier) rows.push(this._detailRow("Tier", this.tier));
      if (this.puzzle) rows.push(this._detailRow("Difficulty", this.puzzle.difficulty));
      if (this._powProgress !== undefined) {
        rows.push(this._detailRow("PoW hashes", this._powProgress.toLocaleString()));
      }
      if (this._solveTime !== undefined) {
        rows.push(this._detailRow("PoW time", this._solveTime.toFixed(1) + "s"));
      }
      this.detailsEl.innerHTML = rows.join("");
    }

    _detailRow(label, value) {
      return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value">${value}</span></div>`;
    }

    // ── Click & verify ──

    _onCheckboxClick() {
      if (this.state !== "idle" && this.state !== "failed") return;
      this._runVerify();
    }

    async _runVerify() {
      if (!this.puzzle) {
        if (this.statusEl) this.statusEl.textContent = "Error: no puzzle available";
        return;
      }
      try {
        this.state = "solving";
        this._updateUI();

        const solution = await this._solvePow(this.puzzle);
        this._injectToken(this.puzzle.challenge_id, solution.nonce);

        this.state = "verified";
        // _updateUI() is a no-op when no chrome is mounted (invisible-mode
        // invisible_pass), so this safely covers every tier × mode combo.
        this._updateUI();

        if (this.onVerify) {
          this.onVerify({
            challenge_id: this.puzzle.challenge_id,
            nonce: solution.nonce,
            tier: this.tier,
          });
        }
      } catch (err) {
        console.error("RustCaptcha error:", err);
        this.state = "failed";
        if (this.statusEl) this.statusEl.textContent = "Error: " + err.message;
        this._updateUI();
      }
    }

    // ── PoW ──

    async _fetchPuzzle() {
      const url = `${this.serverUrl}/v1/puzzle?site_key=${this.siteKey}`;
      // Cookie-free service — no credentials to send. Omitting them keeps the
      // request non-credentialed so the server's wildcard `Access-Control-
      // Allow-Origin: *` (the default when CORS_ALLOWED_ORIGINS is unset) is
      // valid; `credentials: "include"` would force browsers to reject `*`.
      const resp = await fetch(url, { credentials: "omit" });
      if (!resp.ok) {
        const body = await resp.text();
        // 429 carries a structured BlockedResponse JSON with `info_urls`
        // so the widget can patch the brand corner before rendering the
        // blocked state. Fall back gracefully if the body isn't JSON.
        let parsed = null;
        try {
          parsed = JSON.parse(body);
        } catch (_) {
          /* body wasn't JSON — non-block error from upstream proxy etc. */
        }
        const err = new Error(`Puzzle fetch failed (${resp.status}): ${body}`);
        err.status = resp.status;
        err.infoUrls = parsed && parsed.info_urls ? parsed.info_urls : null;
        throw err;
      }
      return resp.json();
    }

    _solvePow(puzzle) {
      return new Promise((resolve, reject) => {
        this.solveStartTime = performance.now();
        this._powProgress = 0;

        this._createWorker()
          .then((worker) => {
            this.worker = worker;

            this.worker.onmessage = (e) => {
              if (e.data.type === "progress") {
                this._powProgress = e.data.nonce;
                this._updateUI();
              } else if (e.data.type === "solved") {
                this._solveTime = (performance.now() - this.solveStartTime) / 1000;
                this._powProgress = e.data.nonce;
                this._destroyWorker();
                resolve({ nonce: e.data.nonce });
              } else if (e.data.type === "error") {
                this._destroyWorker();
                reject(new Error(e.data.message));
              }
            };

            this.worker.onerror = (err) => {
              this._destroyWorker();
              reject(new Error("Worker error: " + err.message));
            };

            this.worker.postMessage({
              prefix: puzzle.prefix,
              difficulty: puzzle.difficulty,
              algorithm: puzzle.algorithm,
            });
          })
          .catch(reject);
      });
    }

    async _createWorker() {
      const workerUrl = this.serverUrl + "/static/captcha-worker.js";
      if (!isCrossOrigin(workerUrl)) {
        return new Worker(workerUrl);
      }

      const resp = await fetch(workerUrl, { credentials: "omit" });
      if (!resp.ok) {
        throw new Error(`Worker fetch failed (${resp.status})`);
      }
      const vendorUrl = this.serverUrl + "/static/vendor/argon2.umd.min.js";
      const source = (await resp.text()).replace(
        /importScripts\(["']vendor\/argon2\.umd\.min\.js["']\)/g,
        `importScripts(${JSON.stringify(vendorUrl)})`
      );
      this.workerBlobUrl = URL.createObjectURL(
        new Blob([source], { type: "text/javascript" })
      );
      return new Worker(this.workerBlobUrl);
    }

    _destroyWorker() {
      if (this.worker) {
        this.worker.terminate();
        this.worker = null;
      }
      if (this.workerBlobUrl) {
        URL.revokeObjectURL(this.workerBlobUrl);
        this.workerBlobUrl = null;
      }
    }

    // ── Form Integration ──

    _injectToken(challengeId, nonce) {
      const form = this.container.closest("form");
      if (!form) return;

      let input = form.querySelector('input[name="captcha-token"]');
      if (!input) {
        input = document.createElement("input");
        input.type = "hidden";
        input.name = "captcha-token";
        form.appendChild(input);
      }

      this._challengeId = challengeId;
      this._nonce = nonce;
      this._tokenInput = input;
      this._refreshTokenInput();

      // Refresh the token at submit time so the behavior counters reflect
      // actual user interaction — not the moment the worker happened to
      // finish solving the PoW. Critical for invisible_pass tier where PoW
      // completes before any user interaction. (Dwell time is derived
      // server-side from the challenge timestamp, so it isn't carried here.)
      if (!this._submitListenerInstalled) {
        const handler = () => this._refreshTokenInput();
        form.addEventListener("submit", handler, { capture: true });
        this._submitListenerInstalled = true;
      }
    }

    _refreshTokenInput() {
      if (!this._tokenInput) return;
      const payload = {
        challenge_id: this._challengeId,
        nonce: this._nonce,
        behavior: { ...this._behavior },
      };
      const honeypotValue = this.honeypot ? this.honeypot.value : "";
      if (honeypotValue) payload.honeypot = honeypotValue;
      // Hex-encode the JSON so the form host treats it as an opaque token and
      // forwards it verbatim — it never needs to parse the contents.
      this._tokenInput.value = encodeToken(payload);
    }

    // ── Public Methods ──

    reset() {
      this._destroyWorker();
      this._teardownBehaviorListeners();
      this.state = "idle";
      this.puzzle = null;
      this.tier = null;
      this._uiRendered = false;
      this._brandLinks = null;
      this.pageLoadAt = Date.now();
      this._powProgress = undefined;
      this._solveTime = undefined;
      this._behavior = {
        mouse_moves: 0,
        touches: 0,
        interactions: 0,
        first_interaction_ms: null,
        webdriver: typeof navigator !== "undefined" && navigator.webdriver === true,
      };
      this._installBehaviorListeners();
      this._render();
      this._initFlow();
    }

    getResult() {
      return { state: this.state, tier: this.tier };
    }
  }

  // ── Public API ──

  window.RustCaptcha = {
    render(container, options) {
      return new CaptchaWidget(container, options);
    },
    _instances: [],
  };

  // ── Auto-Init ──

  // Scan the DOM for `[data-sitekey]` containers and mount a widget on each.
  // Idempotent: we tag mounted nodes so re-runs (after async script load in
  // an SPA, or a subsequent `RustCaptcha.scan()`) don't double-mount.
  function autoInit() {
    document.querySelectorAll("[data-sitekey]").forEach((el) => {
      if (el.dataset.rustcaptchaMounted === "1") return;
      const widget = new CaptchaWidget(el, {
        sitekey: el.dataset.sitekey,
        serverUrl: el.dataset.serverUrl || "",
        debug: el.dataset.debug,
        mode: el.dataset.mode,
      });
      el.dataset.rustcaptchaMounted = "1";
      window.RustCaptcha._instances.push(widget);
    });
  }
  window.RustCaptcha.scan = autoInit;

  // SPA-friendly bootstrap: if `DOMContentLoaded` has already fired by the
  // time this script lands (typical when injected dynamically by a Dioxus
  // / React / Vue app after first paint), the listener would never run. Fall
  // through to an immediate scan in that case.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", autoInit);
  } else {
    autoInit();
  }
})();
