// RustCaptcha Widget — SHA-256 proof-of-work with risk-tier-aware UI.

(function () {
  "use strict";

  // ── CaptchaWidget Class ──

  class CaptchaWidget {
    constructor(container, options) {
      this.container = container;
      this.siteKey = options.sitekey;
      this.serverUrl = options.serverUrl || "";
      this.debug = options.debug === "true" || options.debug === true;
      this.onVerify = options.onVerify || null;

      this.state = "idle";
      this.worker = null;
      this.solveStartTime = null;
      this.puzzle = null;
      this.tier = null;
      this.pageLoadAt = Date.now(); // ms since epoch; feeds the time-on-page signal at verify time

      // Behavioural telemetry: counters for the verify-time `behavior` blob.
      // We only count, never record paths or content — privacy and bandwidth.
      this._behavior = {
        mouse_moves: 0,
        touches: 0,
        interactions: 0,
        first_interaction_ms: null,
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
        this._renderForTier();
      } catch (err) {
        const blocked = /\b429\b/.test(err.message);
        this.tier = blocked ? "block" : null;
        this.state = "failed";
        this._dispatchPuzzleEvent({
          ok: false,
          tier: this.tier,
          error: err.message,
        });
        this._renderBlocked(blocked ? "Verification unavailable" : err.message);
      }
    }

    _dispatchPuzzleEvent(detail) {
      this.container.dispatchEvent(
        new CustomEvent("rustcaptcha:puzzle", { detail, bubbles: true })
      );
    }

    // ── UI Rendering ──

    _render() {
      this.container.innerHTML = "";
      this.container.classList.add("rc-captcha");

      this.row = document.createElement("div");
      this.row.className = "rc-captcha-row";

      this.checkbox = document.createElement("div");
      this.checkbox.className = "rc-captcha-checkbox";
      this.checkbox.addEventListener("click", () => this._onCheckboxClick());

      this.label = document.createElement("span");
      this.label.className = "rc-captcha-label";
      this.label.textContent = "I'm not a robot";

      const brand = document.createElement("span");
      brand.className = "rc-captcha-brand";
      brand.innerHTML = "<strong>RustCaptcha</strong>PoW";

      this.row.appendChild(this.checkbox);
      this.row.appendChild(this.label);
      this.row.appendChild(brand);
      this.container.appendChild(this.row);

      // Honeypot: invisible input, off-screen, with a name that looks like a
      // real form field. A naive form-spamming bot fills every input and trips it.
      this.honeypot = document.createElement("input");
      this.honeypot.type = "text";
      this.honeypot.name = "rc_email_confirm";
      this.honeypot.autocomplete = "off";
      this.honeypot.tabIndex = -1;
      this.honeypot.setAttribute("aria-hidden", "true");
      this.honeypot.style.cssText =
        "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;";
      this.container.appendChild(this.honeypot);

      this.statusEl = document.createElement("div");
      this.statusEl.className = "rc-captcha-status";
      this.container.appendChild(this.statusEl);

      if (this.debug) {
        this.detailsEl = document.createElement("div");
        this.detailsEl.className = "rc-captcha-details";
        this.container.appendChild(this.detailsEl);
      }

      this._updateUI();
    }

    // Branch the visible UI based on the tier the server assigned.
    _renderForTier() {
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

    _renderBlocked(message) {
      this.row.style.display = "none";
      if (this.statusEl) this.statusEl.textContent = message;
      if (this.label) this.label.textContent = "Blocked";
    }

    _updateUI() {
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
        this.statusEl.textContent = "Error: no puzzle available";
        return;
      }
      try {
        this.state = "solving";
        this._updateUI();

        const solution = await this._solvePow(this.puzzle);
        this._injectToken(this.puzzle.challenge_id, solution.nonce);

        this.state = "verified";
        if (this.tier === "invisible_pass") {
          this.label.textContent = "Verified";
          this.statusEl.textContent = "Verified silently";
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
        this.statusEl.textContent = "Error: " + err.message;
        this._updateUI();
      }
    }

    // ── PoW ──

    async _fetchPuzzle() {
      const url = `${this.serverUrl}/v1/puzzle?site_key=${this.siteKey}`;
      const resp = await fetch(url);
      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`Puzzle fetch failed (${resp.status}): ${body}`);
      }
      return resp.json();
    }

    _solvePow(puzzle) {
      return new Promise((resolve, reject) => {
        this.solveStartTime = performance.now();
        this._powProgress = 0;

        const workerUrl = this.serverUrl + "/static/captcha-worker.js";
        this.worker = new Worker(workerUrl);

        this.worker.onmessage = (e) => {
          if (e.data.type === "progress") {
            this._powProgress = e.data.nonce;
            this._updateUI();
          } else if (e.data.type === "solved") {
            this._solveTime = (performance.now() - this.solveStartTime) / 1000;
            this._powProgress = e.data.nonce;
            this.worker.terminate();
            this.worker = null;
            resolve({ nonce: e.data.nonce });
          }
        };

        this.worker.onerror = (err) => {
          this.worker.terminate();
          this.worker = null;
          reject(new Error("Worker error: " + err.message));
        };

        this.worker.postMessage({
          prefix: puzzle.prefix,
          difficulty: puzzle.difficulty,
        });
      });
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
      const payload = {
        challenge_id: challengeId,
        nonce,
        time_on_page_ms: Date.now() - this.pageLoadAt,
        behavior: { ...this._behavior },
      };
      const honeypotValue = this.honeypot ? this.honeypot.value : "";
      if (honeypotValue) payload.honeypot = honeypotValue;
      input.value = JSON.stringify(payload);
    }

    // ── Public Methods ──

    reset() {
      if (this.worker) {
        this.worker.terminate();
        this.worker = null;
      }
      this._teardownBehaviorListeners();
      this.state = "idle";
      this.puzzle = null;
      this.tier = null;
      this.pageLoadAt = Date.now();
      this._powProgress = undefined;
      this._solveTime = undefined;
      this._behavior = {
        mouse_moves: 0,
        touches: 0,
        interactions: 0,
        first_interaction_ms: null,
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
      });
      window.RustCaptcha._instances.push(widget);
    });
  });
})();
