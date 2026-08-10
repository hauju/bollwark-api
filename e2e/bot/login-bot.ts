#!/usr/bin/env bun
/**
 * login-bot — a raw-HTTP adversary for the Bollwark demo login.
 *
 * No browser. It talks straight to the API the way a credential-stuffing bot
 * does: hammer `GET /v1/puzzle`, then (if it can) solve the proof-of-work and
 * `POST /v1/verify`. It exists to *show* the two walls a scripted attacker hits:
 *
 *   1. Verify wall  — even a correctly solved PoW is refused, because a raw
 *      script submits in milliseconds with no behavioural telemetry.
 *   2. Rate wall    — flooding the front door escalates the risk tier
 *      invisible_pass → checkbox → hard_pow → 429 Block.
 *
 * By default it provisions its own throwaway site with an aggressive demo
 * policy so both walls are visible fast. Point it at an existing site (e.g. the
 * one static/login.html shows) with --site-key / --secret to attack that
 * instead — the login page prints a ready-to-run command.
 *
 * Run from bollwark-api/e2e/:
 *   bun bot/login-bot.ts                          # self-provision + attack
 *   bun bot/login-bot.ts --profile naive          # send a bot User-Agent too
 *   bun bot/login-bot.ts --site-key <k> --secret <s>   # attack a specific site
 *
 * Provisioning needs ADMIN_TOKEN (pass --admin-token or set the env var), OR a
 * server started with DEV_DISABLE_ADMIN_AUTH=1 (the e2e/local default).
 */
import { createHash } from "node:crypto";
import { argon2id } from "hash-wasm";

// ── args ──────────────────────────────────────────────────────────────────

type Args = {
  base: string;
  siteKey?: string;
  secret?: string;
  adminToken?: string;
  requests: number;
  profile: "stealth" | "naive";
  delayMs: number;
  verify: boolean;
};

function parseArgs(argv: string[]): Args {
  const a: Args = {
    base: "http://127.0.0.1:3000",
    adminToken: process.env.BOLLWARK_ADMIN_TOKEN ?? process.env.ADMIN_TOKEN,
    requests: 80,
    profile: "stealth",
    delayMs: 0,
    verify: true,
  };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i + 1];
    switch (argv[i]) {
      case "--base": a.base = v; i++; break;
      case "--site-key": a.siteKey = v; i++; break;
      case "--secret": a.secret = v; i++; break;
      case "--admin-token": a.adminToken = v; i++; break;
      case "--requests": a.requests = Number(v); i++; break;
      case "--profile": a.profile = v === "naive" ? "naive" : "stealth"; i++; break;
      case "--delay": a.delayMs = Number(v); i++; break;
      case "--no-verify": a.verify = false; break;
      case "-h": case "--help":
        console.log(HELP); process.exit(0);
      default:
        console.error(`unknown arg: ${argv[i]}`); console.log(HELP); process.exit(1);
    }
  }
  a.base = a.base.replace(/\/$/, "");
  return a;
}

const HELP = `login-bot — raw-HTTP adversary for the Bollwark demo login

  --base <url>          API base (default http://127.0.0.1:3000)
  --site-key <uuid>     attack an existing site instead of self-provisioning
  --secret <hex>        that site's secret_key (needed for the verify stage)
  --admin-token <tok>   ADMIN_TOKEN for provisioning (or env BOLLWARK_ADMIN_TOKEN)
  --requests <n>        flood size for the rate stage (default 80)
  --profile <p>         stealth (browser headers) | naive (bot User-Agent)
  --delay <ms>          pause between flood requests (default 0)
  --no-verify           skip the PoW-solve + verify stage
  -h, --help`;

// ── colour ────────────────────────────────────────────────────────────────

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = (s: string) => c("2", s);
const bold = (s: string) => c("1", s);
const red = (s: string) => c("31", s);
const green = (s: string) => c("32", s);
const yellow = (s: string) => c("33", s);
const cyan = (s: string) => c("36", s);

function tierColor(tier: string): string {
  switch (tier) {
    case "invisible_pass": return green(tier);
    case "checkbox": return yellow(tier);
    case "hard_pow": return c("38;5;208", tier);
    case "block": case "blocked-429": return red(tier);
    default: return tier;
  }
}

// ── headers ───────────────────────────────────────────────────────────────

function headersFor(profile: Args["profile"]): Record<string, string> {
  if (profile === "naive") {
    // The tell every scraping library ships with. Scores +25 header-anomaly
    // on its own (UA_SUSPICIOUS), so it escalates almost immediately.
    return { "User-Agent": "python-requests/2.31.0" };
  }
  // A convincing desktop-Chrome fingerprint. Header anomaly = 0; the only
  // thing that can escalate this profile is the request rate.
  return {
    "User-Agent":
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
  };
}

// ── proof-of-work (SHA-256 only) ────────────────────────────────────────────

/** Mirror of the server's has_leading_zero_bits (puzzle/challenge.rs). */
function hasLeadingZeroBits(hash: Uint8Array, difficulty: number): boolean {
  let remaining = difficulty;
  for (const byte of hash) {
    if (remaining === 0) return true;
    if (remaining >= 8) {
      if (byte !== 0) return false;
      remaining -= 8;
    } else {
      const mask = (0xff << (8 - remaining)) & 0xff;
      return (byte & mask) === 0;
    }
  }
  return remaining === 0;
}

/**
 * Solve SHA-256(prefix_utf8 ++ nonce_le_u64) for `difficulty` leading zero
 * bits — exactly what the widget's worker does, but in one thread here.
 * Returns null if it can't within `maxTries`.
 */
function solveSha256(prefix: string, difficulty: number, maxTries = 50_000_000): number | null {
  const prefixBytes = Buffer.from(prefix, "utf8");
  const buf = Buffer.allocUnsafe(prefixBytes.length + 8);
  prefixBytes.copy(buf, 0);
  for (let nonce = 0; nonce < maxTries; nonce++) {
    buf.writeBigUInt64LE(BigInt(nonce), prefixBytes.length);
    if (hasLeadingZeroBits(createHash("sha256").update(buf).digest(), difficulty)) return nonce;
  }
  return null;
}

type Argon2Params = { m_cost: number; t_cost: number; p_cost: number };

/**
 * Solve Argon2id(password=nonce_le_u64, salt=prefix_utf8) for `difficulty`
 * leading zero bits — mirrors the widget worker's solveArgon2id and the
 * server's compute_argon2id, via the same hash-wasm library the widget vendors.
 *
 * Bounded by wall-clock rather than tries: each hash allocates `m_cost` KiB and
 * takes tens of ms, so an escalated difficulty can be genuinely unaffordable —
 * which is the whole reason Argon2id is the default. Returns null on timeout.
 */
async function solveArgon2id(
  prefix: string,
  difficulty: number,
  params: Argon2Params,
  budgetMs = 60_000,
): Promise<{ nonce: number; hashes: number } | null> {
  const salt = new TextEncoder().encode(prefix);
  const password = new Uint8Array(8);
  const view = new DataView(password.buffer);
  const start = performance.now();
  for (let nonce = 0; ; nonce++) {
    view.setUint32(0, nonce >>> 0, true);
    view.setUint32(4, 0, true);
    const hash = await argon2id({
      password,
      salt,
      parallelism: params.p_cost,
      iterations: params.t_cost,
      memorySize: params.m_cost, // KiB
      hashLength: 32,
      outputType: "binary",
    });
    if (hasLeadingZeroBits(hash, difficulty)) return { nonce, hashes: nonce + 1 };
    if (performance.now() - start > budgetMs) return null;
  }
}

// ── API calls ───────────────────────────────────────────────────────────────

const DEMO_POLICY = {
  // A legible ladder driven purely by the per-IP rate signal (browser
  // headers): >10 reqs → +8 (checkbox), >20 → +15 (hard_pow), >50 → +30 (429).
  tier_checkbox_min: 8,
  tier_hard_pow_min: 15,
  tier_block_min: 30,
  // A submit in <2s with no behaviour blob scores >= 25 → verify-time Block.
  verify_shadow_min: 20,
  verify_block_min: 25,
  // Keep the base PoW cheap so the solve finishes inside the fast-submit band
  // for BOTH algorithms — SHA-256 is instant either way, but an Argon2id solve
  // at a high difficulty would run for many memory-hard seconds and slip past
  // the time-on-page signal. Low here, so "solved but still blocked" holds.
  default_difficulty: 4,
  max_difficulty: 16,
};

async function provision(a: Args): Promise<{ siteKey: string; secret: string }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (a.adminToken) headers.Authorization = `Bearer ${a.adminToken}`;
  const resp = await fetch(`${a.base}/v1/sites`, {
    method: "POST",
    headers,
    body: JSON.stringify({ name: "login-bot-target", policy: DEMO_POLICY }),
  });
  if (resp.status === 401 || resp.status === 404) {
    throw new Error(
      `provisioning refused (HTTP ${resp.status}). Pass --admin-token <ADMIN_TOKEN>, ` +
      `set BOLLWARK_ADMIN_TOKEN, or run the server with DEV_DISABLE_ADMIN_AUTH=1.`,
    );
  }
  if (!resp.ok) throw new Error(`provisioning failed: HTTP ${resp.status} ${await resp.text()}`);
  const d = (await resp.json()) as { site_key: string; secret_key: string };
  return { siteKey: d.site_key, secret: d.secret_key };
}

type Puzzle = {
  challenge_id: string;
  algorithm: string | Record<string, unknown>;
  prefix: string;
  difficulty: number;
  tier: string;
};

async function getPuzzle(a: Args, siteKey: string): Promise<{ status: number; puzzle?: Puzzle }> {
  const resp = await fetch(`${a.base}/v1/puzzle?site_key=${siteKey}`, { headers: headersFor(a.profile) });
  if (resp.status === 429) return { status: 429 };
  if (!resp.ok) return { status: resp.status };
  return { status: resp.status, puzzle: (await resp.json()) as Puzzle };
}

async function verify(a: Args, secret: string, challengeId: string, nonce: number): Promise<{ success: boolean; failover: boolean }> {
  const resp = await fetch(`${a.base}/v1/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${secret}` },
    // Explicit fields, no behaviour blob — the server-to-server shape a bot uses.
    body: JSON.stringify({ challenge_id: challengeId, nonce }),
  });
  if (!resp.ok) throw new Error(`verify HTTP ${resp.status} ${await resp.text()}`);
  return (await resp.json()) as { success: boolean; failover: boolean };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ── stages ──────────────────────────────────────────────────────────────────

/** Solve one puzzle and submit it as fast as a script can — the verify wall. */
async function verifyStage(a: Args, siteKey: string, secret: string) {
  console.log(bold("\n▍ Stage 1 — solve the PoW and verify (the behavioural wall)"));
  const { status, puzzle } = await getPuzzle(a, siteKey);
  if (!puzzle) {
    console.log(dim(`  couldn't fetch a clean puzzle (HTTP ${status}) — skipping.`));
    return;
  }

  const argon = typeof puzzle.algorithm === "object"
    ? (puzzle.algorithm as { argon2id?: Argon2Params }).argon2id
    : undefined;
  const algoLabel = argon
    ? `argon2id(m=${argon.m_cost} t=${argon.t_cost} p=${argon.p_cost})`
    : String(puzzle.algorithm);
  console.log(`  puzzle: tier=${tierColor(puzzle.tier)} difficulty=${puzzle.difficulty} algorithm=${algoLabel}`);

  // Solve the PoW — the two algorithms differ only in cost, not in whether the
  // resulting token clears verify-time scoring.
  let nonce: number;
  const t0 = performance.now();
  if (puzzle.algorithm === "sha256") {
    const n = solveSha256(puzzle.prefix, puzzle.difficulty);
    if (n === null) {
      console.log(red(`  gave up solving after 50M tries (difficulty ${puzzle.difficulty} too high).`));
      return;
    }
    nonce = n;
    console.log(`  solved (sha256): nonce=${nonce} in ${Math.round(performance.now() - t0)}ms — submitting`);
  } else if (argon) {
    console.log(dim("  solving argon2id — memory-hard, so orders of magnitude slower than SHA-256…"));
    const r = await solveArgon2id(puzzle.prefix, puzzle.difficulty, argon);
    if (r === null) {
      const ms = Math.round(performance.now() - t0);
      console.log(red(`  gave up after ${ms}ms — argon2id at difficulty ${puzzle.difficulty} is too expensive to brute-force here.`));
      console.log(dim("     That cost wall IS the point of argon2id: each tier escalation multiplies the"));
      console.log(dim("     attacker's memory + CPU per solve. The rate wall below still applies."));
      return;
    }
    nonce = r.nonce;
    const ms = Math.round(performance.now() - t0);
    console.log(`  solved (argon2id): nonce=${nonce} after ${r.hashes} hashes in ${ms}ms (~${(ms / r.hashes).toFixed(0)}ms/hash) — submitting`);
  } else {
    console.log(dim(`  unrecognised algorithm ${algoLabel} — skipping the solve.`));
    return;
  }

  const solveMs = Math.round(performance.now() - t0);
  const v = await verify(a, secret, puzzle.challenge_id, nonce);
  if (!v.success) {
    console.log("  → /v1/verify: " + red("success=false ⇒ BLOCKED"));
    console.log(dim("     A valid proof-of-work still failed: submitted fast with no behavioural"));
    console.log(dim("     telemetry, so the verify-time score crossed the block band."));
  } else if (solveMs > 2000) {
    console.log("  → /v1/verify: " + yellow(`success=true${v.failover ? " (failover)" : ""}`));
    console.log(dim(`     Got through: the honest solve took ${solveMs}ms, past the fast-submit bands, so`));
    console.log(dim("     time-on-page scored 0. A no-behaviour bot beats the time signal by being slow —"));
    console.log(dim("     set VERIFY_REQUIRE_BEHAVIOR=1 to score the missing blob (+30) and still block it."));
  } else {
    console.log("  → /v1/verify: " + yellow(`success=true${v.failover ? " (failover)" : ""}`));
    console.log(dim("     Passed or shadow_fail (the server log distinguishes). Tighten verify_block_min,"));
    console.log(dim("     or set VERIFY_REQUIRE_BEHAVIOR=1, to hard-block a no-behaviour submit."));
  }
}

/** Flood the front door and watch the risk tier climb — the rate wall. */
async function rateStage(a: Args, siteKey: string) {
  console.log(bold(`\n▍ Stage 2 — flood GET /v1/puzzle ×${a.requests} (${a.profile} headers) — the rate wall`));
  console.log(dim("  printing only when the tier changes:\n"));
  let last = "";
  let blockedAt = 0;
  const seen: Record<string, number> = {};
  let i = 0;
  for (; i < a.requests; i++) {
    const { status, puzzle } = await getPuzzle(a, siteKey);
    const tier = status === 429 ? "block" : puzzle?.tier ?? `http-${status}`;
    seen[tier] = (seen[tier] ?? 0) + 1;
    if (tier !== last) {
      const n = String(i + 1).padStart(3);
      const diff = puzzle ? ` diff=${puzzle.difficulty}` : "";
      const code = status === 429 ? red("429") : status === 200 ? green("200") : yellow(String(status));
      console.log(`  #${n}  ${code}  ${tierColor(tier).padEnd(useColor ? 24 : 14)}${dim(diff)}`);
      last = tier;
    }
    if (status === 429) { blockedAt = i + 1; break; }
    if (a.delayMs) await sleep(a.delayMs);
  }

  console.log("");
  if (blockedAt) {
    console.log(green(`  ✔ Bollwark returned 429 Block after ${blockedAt} requests from this IP.`));
    console.log(dim("    Further requests stay blocked until the 60s rate window rolls off."));
  } else {
    const reached = Object.keys(seen).filter((t) => t !== "invisible_pass");
    console.log(yellow(`  Sent ${i} requests without a 429.`));
    console.log(dim(`    Reached: ${reached.length ? reached.join(", ") : "invisible_pass only"}.`));
    console.log(dim("    A clean-header flood on a strict login policy escalates to costly PoW but"));
    console.log(dim("    may not 429 — the verify wall (Stage 1) is what stops the actual submit."));
  }
}

// ── main ────────────────────────────────────────────────────────────────────

async function main() {
  const a = parseArgs(Bun.argv.slice(2));

  let siteKey = a.siteKey;
  let secret = a.secret;
  if (!siteKey) {
    console.log(cyan("Provisioning a throwaway target site with the demo policy…"));
    const p = await provision(a);
    siteKey = p.siteKey;
    secret = p.secret;
    console.log(dim(`  site_key=${siteKey}`));
  } else {
    console.log(cyan(`Attacking existing site ${siteKey}`));
  }

  console.log(dim(`  target=${a.base}  profile=${a.profile}`));

  if (a.verify) {
    if (secret) await verifyStage(a, siteKey, secret);
    else console.log(dim("\n▍ Stage 1 skipped — no --secret, so /v1/verify can't be called."));
  }

  await rateStage(a, siteKey);

  console.log(dim("\nNote: the per-IP rate counter is windowed (60s) and shared across sites, so"));
  console.log(dim("back-to-back runs start already-elevated. Wait ~60s for a fresh ladder.\n"));
}

main().catch((e) => {
  console.error(red(`\nbot error: ${e.message}`));
  process.exit(1);
});
