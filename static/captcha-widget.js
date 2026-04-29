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

  // ── CaptchaWidget Class ──

  /**
   * RustCaptcha widget.
   *
   * Modes (`data-mode` attribute / `mode` option):
   *
   *   "default" — always renders the checkbox + brand footer chrome.
   *     `invisible_pass` shows a "Verified silently" pill; higher tiers
   *     require the visitor to click the checkbox or solve a visual.
   *
   *   "invisible" — renders no chrome until/unless the tier requires
   *     user interaction:
   *       invisible_pass → silent PoW + onVerify; no UI ever rendered.
   *       checkbox / hard_pow → checkbox UI appears; user clicks.
   *       visual → image-text UI appears; user types the answer.
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
    // For `invisible_pass`, this also kicks off the silent solve.
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
        // interaction (a click, an image-text answer), so promote to the
        // full visible UI.
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
    // checkbox / visual challenge if the server escalates.
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

      // Brand footer: clickable name → about, tiny Privacy / Terms links
      // beneath. Mirrors the reCAPTCHA / hCaptcha pattern. Lives in its
      // own persistent footer (not inside `row`) so it stays visible
      // across every tier state — invisible-pass, visual challenge, and
      // block included — which is exactly when the user is most likely
      // to want "why am I seeing this?". Hrefs default to the bundled
      // /static/*.html and are patched by `_applyInfoUrls` once the
      // puzzle response (or 429 body) arrives with operator overrides.
      this.footer = document.createElement("div");
      this.footer.className = "rc-captcha-footer";
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
      this.footer.appendChild(brand);
      this.container.appendChild(this.footer);

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
      // Visual challenge: server returned an image-text captcha. Hide the
      // checkbox row and render the image + input UI; the user reads the
      // characters and types the answer instead of running PoW.
      if (this.puzzle && this.puzzle.kind === "image") {
        this._renderVisualChallenge();
        return;
      }
      if (this.tier === "invisible_pass") {
        this.row.style.display = "none";
        this.label.textContent = "Verifying…";
        this.statusEl.textContent = "Running silent verification";
        this._runVerify();
      } else {
        // checkbox / hard_pow / unknown future tier → user clicks to solve
        this.row.style.display = "";
        this._updateUI();
      }
    }

    // Render the image-text challenge UI: a captcha PNG, a text input,
    // and a submit button. The user types what they see; on submit the
    // widget stores the answer in the form-bound hidden input so the
    // host page can forward it to /v1/verify exactly like the PoW path.
    _renderVisualChallenge() {
      this.row.style.display = "none";
      this.statusEl.textContent = "";

      // Idempotent: tear down a previous visual UI if `reset()` cycled us.
      if (this._visualEl) {
        this._visualEl.remove();
        this._visualEl = null;
      }

      const wrap = document.createElement("div");
      wrap.className = "rc-captcha-visual";

      const prompt = document.createElement("div");
      prompt.className = "rc-captcha-visual-prompt";
      prompt.textContent = "Type the characters you see:";

      const img = document.createElement("img");
      img.className = "rc-captcha-visual-image";
      img.alt = "captcha";
      img.src = this.puzzle.image;

      const form = document.createElement("form");
      form.className = "rc-captcha-visual-form";
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        this._onVisualSubmit();
      });

      const input = document.createElement("input");
      input.type = "text";
      input.className = "rc-captcha-visual-input";
      input.autocomplete = "off";
      input.autocapitalize = "off";
      input.spellcheck = false;
      input.maxLength = 16;
      input.placeholder = "ABCDE";

      const button = document.createElement("button");
      button.type = "submit";
      button.className = "rc-captcha-visual-button";
      button.textContent = "Verify";

      form.appendChild(input);
      form.appendChild(button);

      wrap.appendChild(prompt);
      wrap.appendChild(img);
      wrap.appendChild(form);

      // Insert before the status element so debug details stay at the bottom.
      this.container.insertBefore(wrap, this.statusEl);
      this._visualEl = wrap;
      this._visualInput = input;
      this._visualButton = button;
      input.focus();
    }

    _onVisualSubmit() {
      if (!this.puzzle || !this._visualInput) return;
      const answer = this._visualInput.value.trim();
      if (!answer) {
        this.statusEl.textContent = "Please type the characters above.";
        return;
      }
      this._textAnswer = answer;
      this.state = "verified";
      this._visualButton.disabled = true;
      this._visualInput.disabled = true;
      this.statusEl.textContent = "Submitting answer…";
      this._injectToken(this.puzzle.challenge_id, 0);
      if (this.onVerify) {
        this.onVerify({
          challenge_id: this.puzzle.challenge_id,
          text_answer: answer,
          tier: this.tier,
        });
      }
    }

    _renderBlocked(message) {
      this.row.style.display = "none";
      if (this.statusEl) this.statusEl.textContent = message;
      if (this.label) this.label.textContent = "Blocked";
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
        if (this.tier === "invisible_pass") {
          // Default mode renders the "Verified silently" pill. Invisible
          // mode has no UI to update — the onVerify callback / submit-time
          // token injection is the only signal the embedder sees.
          if (this.label) this.label.textContent = "Verified";
          if (this.statusEl) this.statusEl.textContent = "Verified silently";
        } else {
          this._updateUI();
        }

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
      const resp = await fetch(url, { credentials: "include" });
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

      // Refresh the token at submit time so `time_on_page_ms` and the
      // behavior counters reflect actual user interaction — not the
      // moment the worker happened to finish solving the PoW. Critical
      // for invisible_pass tier where PoW completes before any user
      // interaction.
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
        time_on_page_ms: Date.now() - this.pageLoadAt,
        behavior: { ...this._behavior },
      };
      if (this._textAnswer) payload.text_answer = this._textAnswer;
      const honeypotValue = this.honeypot ? this.honeypot.value : "";
      if (honeypotValue) payload.honeypot = honeypotValue;
      this._tokenInput.value = JSON.stringify(payload);
    }

    // ── Public Methods ──

    reset() {
      this._destroyWorker();
      this._teardownBehaviorListeners();
      if (this._visualEl) {
        this._visualEl.remove();
        this._visualEl = null;
        this._visualInput = null;
        this._visualButton = null;
      }
      this._textAnswer = null;
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

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-sitekey]").forEach((el) => {
      const widget = new CaptchaWidget(el, {
        sitekey: el.dataset.sitekey,
        serverUrl: el.dataset.serverUrl || "",
        debug: el.dataset.debug,
        mode: el.dataset.mode,
      });
      window.RustCaptcha._instances.push(widget);
    });
  });
})();
