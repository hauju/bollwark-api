// Bollwark Widget — Argon2id / SHA-256 proof-of-work with risk-tier-aware UI.

(function () {
  "use strict";

  const SCRIPT_SRC = document.currentScript && document.currentScript.src;
  const DEFAULT_SERVER_URL = inferServerUrl(SCRIPT_SRC);

  // Rewritten by the server when this file is served from `/v1/widget.js`, to
  // the immutable content-hashed asset directory (`/assets/<hash>`). Left as
  // the literal placeholder when the file is served verbatim — from the
  // legacy `/static/` path, from inside `/assets/<hash>/` itself, or from a
  // copy the integrator bundled into their own build. See src/api/assets.rs.
  const ASSET_BASE = "__BOLLWARK_ASSET_BASE__";
  const ASSET_BASE_SUBSTITUTED = ASSET_BASE.charAt(0) === "/";

  // Backoff before concluding the service is unreachable and falling back to a
  // failover claim. Two retries — enough to ride out a blip or a single failed
  // connection, short enough that a real outage costs the visitor ~1.2s rather
  // than a hung form.
  const FAILOVER_RETRY_DELAYS_MS = [300, 900];

  // How often a widget in failover mode re-checks whether the service is back.
  // On success it upgrades to a real solved token in place, so a visitor who
  // sat through the tail of an outage submits a genuine proof of work.
  const FAILOVER_RECOVERY_POLL_MS = 15000;

  function inferServerUrl(scriptSrc) {
    if (!scriptSrc) return "";
    try {
      const url = new URL(scriptSrc, window.location.href);
      return url.origin === window.location.origin ? "" : url.origin;
    } catch (_) {
      return "";
    }
  }

  // Where to load the worker, the vendored Argon2 bundle and the stylesheet
  // from, as a path appended to `serverUrl`.
  //
  // The substituted case is the common one and needs no inference. Otherwise
  // we prefer this script's own directory, so a copy served out of
  // `/assets/<hash>/` keeps loading its own siblings rather than silently
  // falling back to the unversioned tree and re-opening the skew window the
  // hashing exists to close.
  //
  // That inference is only valid when the script came from the captcha origin
  // itself. An integrator who bundles `captcha-widget.js` into their own app
  // and points it at us with `data-server-url` has a script URL that says
  // nothing about our layout, and joining their bundle path onto our origin
  // would 404 — those fall back to `/static`, which is exactly where a
  // separately-downloaded copy's siblings are.
  function resolveAssetBase(scriptSrc, serverUrl) {
    if (ASSET_BASE_SUBSTITUTED) return ASSET_BASE;
    if (scriptSrc) {
      try {
        const script = new URL(scriptSrc, window.location.href);
        const server = new URL(serverUrl || window.location.origin, window.location.href);
        if (script.origin === server.origin) {
          return script.pathname.replace(/\/[^/]*$/, "");
        }
      } catch (_) {
        /* fall through */
      }
    }
    return "/static";
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

  // ── Environment probes ──
  //
  // Both reduce to a single boolean before leaving the browser: we report the
  // environment *class*, never the underlying strings, so the behavior blob
  // gains no fingerprinting entropy. Both are trivially patched out by a
  // determined bot — like `navigator.webdriver`, they exist to raise the floor
  // against the cheap long tail, not to catch stealth tooling. (Verified:
  // current Playwright leaves none of these traces.)

  // Globals injected by automation drivers. ChromeDriver installs `cdc_`-
  // prefixed properties with a build-specific suffix; the rest are legacy
  // Selenium / PhantomJS / Nightmare markers. Absence proves nothing, but
  // presence is near-conclusive — and it survives `navigator.webdriver`
  // being scrubbed, which is the case worth catching.
  const AUTOMATION_MARKERS = [
    "__webdriver_evaluate",
    "__webdriver_script_fn",
    "__webdriver_script_func",
    "__webdriver_unwrapped",
    "__selenium_evaluate",
    "__selenium_unwrapped",
    "__fxdriver_evaluate",
    "__fxdriver_unwrapped",
    "_Selenium_IDE_Recorder",
    "_phantom",
    "callPhantom",
    "__nightmare",
    "domAutomation",
    "domAutomationController",
  ];

  function detectAutomation() {
    try {
      const hasCdcKey = (obj) =>
        Object.getOwnPropertyNames(obj).some(
          (k) => k.indexOf("cdc_") === 0 || k.indexOf("$cdc_") === 0
        );
      if (hasCdcKey(window) || hasCdcKey(document)) return true;
      return AUTOMATION_MARKERS.some((m) => m in window || m in document);
    } catch {
      return false;
    }
  }

  // Coarse "windowless environment" hints. Deliberately only the three checks
  // that don't misfire on real-world oddities: in-app WebViews and Chromium
  // forks break the popular `window.chrome` / `navigator.plugins` heuristics,
  // and those carry far too much genuine traffic to risk. Modern headless
  // modes defeat all of this, which is why the server scores it below the
  // shadow threshold on its own.
  function detectHeadless() {
    try {
      if (/HeadlessChrome/.test(navigator.userAgent || "")) return true;
      // A real browser window always reports non-zero outer dimensions.
      if (window.outerWidth === 0 && window.outerHeight === 0) return true;
      if (!navigator.languages || navigator.languages.length === 0) return true;
      return false;
    } catch {
      return false;
    }
  }

  // Snapshot at mount — some stealth patches restore these later.
  function probeEnvironment() {
    return {
      // navigator.webdriver is set by CDP-driven Chromium (Playwright,
      // Puppeteer, Selenium, browser-harness in default mode).
      webdriver: typeof navigator !== "undefined" && navigator.webdriver === true,
      automation: detectAutomation(),
      headless: detectHeadless(),
    };
  }

  // ── CaptchaWidget Class ──

  /**
   * Bollwark widget.
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
   *         the `bollwark:puzzle` event (detail.ok=false) to surface
   *         a failure UX — otherwise the block is silent and the user
   *         sees nothing happen. A console.warn fires once on block to
   *         flag missed wiring during development.
   *
   * Theme (`data-theme` attribute / `theme` option):
   *   "auto" (default) — follows the visitor's OS via prefers-color-scheme.
   *   "light" / "dark" — force a fixed palette, e.g. so an embedder can
   *     match a host whose theme differs from the OS setting.
   *
   * Event: `bollwark:puzzle` (CustomEvent on the container, bubbles)
   *   detail = { ok, tier, difficulty?, error? }
   *     ok=true  → puzzle issued (or invisible-pass solving in the bg).
   *     ok=false → 429 (block) or fetch error; `tier="block"` for 429.
   */
  class CaptchaWidget {
    constructor(container, options) {
      this.container = container;
      this.siteKey = options.sitekey;
      this.serverUrl = options.serverUrl || DEFAULT_SERVER_URL;
      // Per-instance, not module-level: `data-server-url` can differ per
      // widget, and it is what decides whether this script's own path is a
      // usable hint for where our sibling assets live.
      this.assetBase = resolveAssetBase(SCRIPT_SRC, this.serverUrl);
      this.debug = options.debug === "true" || options.debug === true;
      // "invisible" defers all visible UI until the tier requires it.
      // Mirrors hCaptcha size=invisible / reCAPTCHA v3 → v2 fallback.
      this.mode = options.mode === "invisible" ? "invisible" : "default";
      // Theme: "auto" (default) follows the visitor's OS via
      // prefers-color-scheme; "light"/"dark" force a fixed palette so an
      // embedder can match a host whose theme differs from the OS.
      this.theme = options.theme === "light" || options.theme === "dark"
        ? options.theme
        : "auto";
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
        ...probeEnvironment(),
      };
      this._behaviorListeners = [];
      this._installBehaviorListeners();

      // Pre-expiry challenge refresh (see _schedulePuzzleRefresh). Deferred
      // while the tab is hidden — background timers are throttled anyway —
      // and fired as soon as the tab becomes visible again.
      this._refreshTimer = null;
      this._refreshPending = false;
      // True once the service has been declared unreachable and the widget is
      // emitting a failover claim instead of a solved token.
      this._failover = false;
      this._onVisibilityChange = () => {
        if (!document.hidden && this._refreshPending) {
          this._refreshPending = false;
          this._refreshPuzzle();
        }
      };
      document.addEventListener("visibilitychange", this._onVisibilityChange);

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
        const puzzle = await this._fetchPuzzleWithRetry();
        this.puzzle = puzzle;
        this.tier = puzzle.tier;
        this._schedulePuzzleRefresh();
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
        // Unreachable after retries: emit a failover claim so the form the
        // widget guards stays submittable. The claim proves nothing on its
        // own — the server honors it only against its own attested outage
        // record — so this is a request to fail open, not a decision to.
        if (CaptchaWidget._isUnreachable(err)) {
          this._enterFailover(err);
          return;
        }

        const blocked = err.status === 429;
        this.tier = blocked ? "block" : null;
        this.state = "failed";
        this._dispatchPuzzleEvent({
          ok: false,
          tier: this.tier,
          error: err.message,
        });

        // Invisible mode hands block-tier UX to the embedder via the
        // `bollwark:puzzle` event — they decide whether to show an
        // inline message, redirect, or do nothing. The console.warn is a
        // one-shot dev-time hint: if the embedder forgot to wire the
        // listener, the page would otherwise look like nothing happened.
        if (this.mode === "invisible") {
          console.warn(
            "[Bollwark] invisible-mode " +
              (blocked ? "block (HTTP 429)" : "fetch error") +
              " — widget rendered no UI. Listen for the `bollwark:puzzle` " +
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
        new CustomEvent("bollwark:puzzle", { detail, bubbles: true })
      );
    }

    // ── Failover ──
    //
    // The service is unreachable, so there is no challenge to solve and no
    // proof of work to produce. Emit a claim saying exactly that and let the
    // form submit; the server decides whether to honor it against its own
    // record of having been down (see src/failover/mod.rs). If failover is
    // disabled server-side, or no outage is attested, the submit is rejected
    // there — the widget's job is only to stop being a silent hard blocker.
    _enterFailover(err) {
      this._failover = true;
      this.tier = null;
      // "verified" is the state the rest of the widget uses for "this form is
      // good to submit". The distinction the embedder needs is on the event
      // and, authoritatively, in the server's `failover: true` response — not
      // in widget-local state.
      this.state = "verified";
      this._injectFailoverToken();

      this._dispatchPuzzleEvent({
        ok: false,
        failover: true,
        tier: null,
        error: err && err.message,
      });

      if (this.mode !== "invisible") {
        this._promoteToInteractiveUI();
        this._renderForTier();
        if (this.statusEl) {
          this.statusEl.textContent = "Verification unavailable — continuing";
        }
      }

      this._scheduleFailoverRecovery();
    }

    // Poll for recovery. A visitor who loaded the form during an outage may
    // still be filling it in when the service returns; upgrading to a real
    // token means their submit carries genuine proof of work instead of
    // spending the site's (rate-capped) failover budget.
    _scheduleFailoverRecovery() {
      this._clearPuzzleRefresh();
      this._refreshTimer = setTimeout(async () => {
        this._refreshTimer = null;
        if (!this._failover) return;
        if (document.hidden) {
          this._scheduleFailoverRecovery();
          return;
        }
        try {
          const puzzle = await this._fetchPuzzle();
          this.puzzle = puzzle;
          const solution = await this._solvePow(puzzle);
          this._failover = false;
          this._injectToken(puzzle.challenge_id, solution.nonce);
          if (this.statusEl) this.statusEl.textContent = "";
          this._updateUI();
          this._schedulePuzzleRefresh();
          this._dispatchPuzzleEvent({
            ok: true,
            recovered: true,
            tier: puzzle.tier,
            difficulty: puzzle.difficulty,
          });
        } catch (_) {
          // Still down (or a fresh block-tier decision on recovery) — keep the
          // failover token in place and check back.
          this._scheduleFailoverRecovery();
        }
      }, FAILOVER_RECOVERY_POLL_MS);
    }

    // Install the hidden input carrying a failover claim. Mirrors
    // `_injectToken`, including the submit-time refresh, so the behaviour
    // counters in the claim reflect the visitor's actual interaction — that
    // blob is collected locally and survives the outage, and is the only real
    // evidence the server still gets to score on this path.
    _injectFailoverToken() {
      const form = this.container.closest("form");
      if (!form) return;

      let input = form.querySelector('input[name="captcha-token"]');
      if (!input) {
        input = document.createElement("input");
        input.type = "hidden";
        input.name = "captcha-token";
        form.appendChild(input);
      }
      this._tokenInput = input;
      this._refreshTokenInput();

      if (!this._submitListenerInstalled) {
        const handler = () => this._refreshTokenInput();
        form.addEventListener("submit", handler, { capture: true });
        this._submitListenerInstalled = true;
      }
    }

    // ── UI Rendering ──

    // Honeypot + (optionally) the visible UI. In invisible mode the visible
    // UI is deferred until `_promoteToInteractiveUI()` — the widget runs
    // silently for the `invisible_pass` tier and only materialises a
    // checkbox if the server escalates.
    _render() {
      this._ensureStylesheet();
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

    // Load `captcha-widget.css` from the same asset base as the worker, so a
    // single `<script src=".../v1/widget.js">` is the whole embed and the
    // stylesheet is version-locked to the script that expects it.
    //
    // Integrators who still hand-write the `<link>` — every embed predating
    // the entry point — are left alone: injecting a second identical
    // stylesheet would be harmless but pointless, and skipping keeps their
    // load order and any overrides they layered on top intact.
    _ensureStylesheet() {
      const existing = document.querySelector(
        'link[rel="stylesheet"][href*="captcha-widget.css"]'
      );
      if (existing) return;

      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = this.serverUrl + this.assetBase + "/captcha-widget.css";
      document.head.appendChild(link);
    }

    // Build the visible widget chrome: checkbox row, status line, debug
    // panel, brand footer. Idempotent — safe to call after `_render()`
    // promotes invisibly.
    _promoteToInteractiveUI() {
      if (this._uiRendered) return;
      this._uiRendered = true;

      this.container.classList.add("rc-captcha");
      this.container.setAttribute("data-rc-theme", this.theme);

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
      // `margin-left:auto`) so "Bollwark" rides the same line as the
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
      brandLink.textContent = "Bollwark";
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
        console.error("Bollwark error:", err);
        this.state = "failed";
        if (this.statusEl) this.statusEl.textContent = "Error: " + err.message;
        this._updateUI();
      }
    }

    // ── PoW ──

    // Whether a puzzle-fetch failure means "this service is unreachable"
    // (→ failover is appropriate) or "this service answered and said no"
    // (→ it must not be).
    //
    // A 429 is a deliberate block-tier decision and a 4xx is an integration
    // fault (unknown site_key, disallowed origin) — minting a failover claim
    // for either would be papering over a working, correct refusal. Only a
    // 5xx or a fetch that never got a response at all (DNS, TLS, connection
    // refused, CORS preflight failure) counts as unreachable.
    //
    // Note the failure mode this cannot see: if `captcha-widget.js` itself
    // fails to load, no widget code runs, so there is nothing here to fall
    // back. That case is the embedder's to handle — see the `script.onerror`
    // pattern in INTEGRATION.md.
    static _isUnreachable(err) {
      return !err.status || err.status >= 500;
    }

    // Fetch with a short backoff before declaring the service unreachable, so
    // a single transient blip doesn't drop an otherwise-healthy visitor onto
    // the fail-open path. Retries only what's worth retrying: a 429 or 4xx is
    // returned immediately.
    async _fetchPuzzleWithRetry() {
      let lastErr;
      for (let attempt = 0; attempt <= FAILOVER_RETRY_DELAYS_MS.length; attempt++) {
        try {
          return await this._fetchPuzzle();
        } catch (err) {
          lastErr = err;
          if (!CaptchaWidget._isUnreachable(err)) throw err;
          const delay = FAILOVER_RETRY_DELAYS_MS[attempt];
          if (delay === undefined) break;
          await new Promise((r) => setTimeout(r, delay));
        }
      }
      throw lastErr;
    }

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

    // ── Challenge refresh ──

    // Challenges expire after the server's CHALLENGE_TTL_SECS (default
    // 5 min), but the widget fetches one at mount — so without a refresh, a
    // visitor who dwells on the form longer than the TTL submits a token
    // pointing at an expired challenge and fails verification with no
    // recovery. Re-fetch shortly before expiry; if the PoW was already
    // solved, quietly re-solve so the injected token always references a
    // live challenge. The tier rendered at mount stays locked — only the
    // challenge data rotates.
    _schedulePuzzleRefresh() {
      this._clearPuzzleRefresh();
      if (!this.puzzle) return;
      // Prefer the server-stated lifetime: comparing `expires_at` against
      // the client clock breaks silently when that clock is skewed.
      let ttlMs =
        typeof this.puzzle.expires_in_secs === "number"
          ? this.puzzle.expires_in_secs * 1000
          : Date.parse(this.puzzle.expires_at) - Date.now();
      if (!isFinite(ttlMs) || ttlMs <= 0) ttlMs = 240000;
      // Absolute deadline for the challenge currently in the form. If a
      // refresh can't reach the server before this passes, the token we're
      // holding is dead and retrying it forever just fails the submit — that's
      // the point where failover becomes the better answer (see below).
      this._puzzleExpiresAt = Date.now() + ttlMs;
      // 60s before expiry, but never below half the TTL (short-TTL servers)
      // and never below a 5s floor (protects against a hot refresh loop).
      const delay = Math.max(ttlMs - 60000, ttlMs / 2, 5000);
      this._refreshTimer = setTimeout(() => this._refreshPuzzle(), delay);
    }

    _clearPuzzleRefresh() {
      if (this._refreshTimer) {
        clearTimeout(this._refreshTimer);
        this._refreshTimer = null;
      }
    }

    async _refreshPuzzle() {
      this._refreshTimer = null;
      if (this.state === "solving") {
        // A user-triggered solve is in flight; check back once it settles.
        this._refreshTimer = setTimeout(() => this._refreshPuzzle(), 5000);
        return;
      }
      if (document.hidden) {
        // Don't fetch or burn CPU re-solving in a background tab; the
        // visibilitychange handler resumes this the moment it's visible.
        this._refreshPending = true;
        return;
      }
      try {
        const puzzle = await this._fetchPuzzle();
        this.puzzle = puzzle;
        if (this.state === "verified") {
          // The token in the form references the old, about-to-expire
          // challenge. Re-solve in the background — state stays "verified",
          // so there's no visible churn — and swap the token in place.
          const solution = await this._solvePow(puzzle);
          this._injectToken(puzzle.challenge_id, solution.nonce);
        }
        this._schedulePuzzleRefresh();
      } catch (err) {
        // A visitor who was already on the page when the outage started: the
        // challenge in their form expires mid-outage, and every retry after
        // that submits a token the server will reject as expired. Once it's
        // actually dead, switch to a failover claim — this is the case the
        // server's grace tail exists for.
        if (
          CaptchaWidget._isUnreachable(err) &&
          this._puzzleExpiresAt &&
          Date.now() >= this._puzzleExpiresAt
        ) {
          this._enterFailover(err);
          return;
        }
        // Otherwise a blip or a block-tier 429: keep the current challenge
        // (it may still be valid for a while) and retry.
        this._refreshTimer = setTimeout(() => this._refreshPuzzle(), 60000);
      }
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
      const workerUrl = this.serverUrl + this.assetBase + "/captcha-worker.js";
      if (!isCrossOrigin(workerUrl)) {
        // Same-origin: the worker's own `importScripts("vendor/…")` resolves
        // relative to its URL, so it lands in the same asset directory we
        // loaded it from and the bundle stays internally consistent.
        return new Worker(workerUrl);
      }

      const resp = await fetch(workerUrl, { credentials: "omit" });
      if (!resp.ok) {
        throw new Error(`Worker fetch failed (${resp.status})`);
      }
      // Cross-origin: the worker runs from a blob URL, where a relative
      // `importScripts` would resolve against the blob and fail, so the
      // vendor path has to be absolutised against the same asset base.
      const vendorUrl = this.serverUrl + this.assetBase + "/vendor/argon2.umd.min.js";
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
      // In failover there is no challenge and no nonce to reference — the
      // claim names the site and when it was minted, and carries the same
      // browser-local evidence a normal token would.
      const payload = this._failover
        ? {
            failover: true,
            site_key: this.siteKey,
            issued_at: Date.now(),
            behavior: { ...this._behavior },
          }
        : {
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
      this._clearPuzzleRefresh();
      this._refreshPending = false;
      this._failover = false;
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
        ...probeEnvironment(),
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

  window.Bollwark = {
    render(container, options) {
      return new CaptchaWidget(container, options);
    },
    _instances: [],
  };

  // ── Auto-Init ──

  // Scan the DOM for `[data-sitekey]` containers and mount a widget on each.
  // Idempotent: we tag mounted nodes so re-runs (after async script load in
  // an SPA, or a subsequent `Bollwark.scan()`) don't double-mount.
  function autoInit() {
    document.querySelectorAll("[data-sitekey]").forEach((el) => {
      if (el.dataset.bollwarkMounted === "1") return;
      const widget = new CaptchaWidget(el, {
        sitekey: el.dataset.sitekey,
        serverUrl: el.dataset.serverUrl || "",
        debug: el.dataset.debug,
        mode: el.dataset.mode,
        theme: el.dataset.theme,
      });
      el.dataset.bollwarkMounted = "1";
      window.Bollwark._instances.push(widget);
    });
  }
  window.Bollwark.scan = autoInit;

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
