# login-bot — raw-HTTP adversary

A standalone bot that attacks the Bollwark demo login (`static/login.html`) the
way a credential-stuffing script does: **no browser**, straight HTTP against
`/v1/puzzle` and `/v1/verify`. It demonstrates the two walls a scripted
attacker hits.

This is the non-browser counterpart to `../tests/browser-harness-simulator.spec.ts`
(a driven-Chrome bot) and `../browser-harness/` (an LLM-driven one).

## Run

From `bollwark-api/e2e/`:

```bash
# 1. Start the server (local/dev — lets the bot provision a site without a token)
cd .. && DEV_DISABLE_ADMIN_AUTH=1 PUZZLE_ALGORITHM=sha256 cargo run

# 2. In another terminal, run the bot
cd e2e
just bot                                   # self-provision + attack
bun bot/login-bot.ts --profile naive       # send a bot User-Agent too
```

`--help` lists every flag.

### Against the demo login page

Open `http://127.0.0.1:3000/static/login.html`, click **Provision site**, and
copy the ready-made command it prints — it targets *that* site:

```bash
bun bot/login-bot.ts --base http://127.0.0.1:3000 --site-key <k> --secret <s>
```

That site uses a realistic login policy, so a clean-header flood escalates to
expensive PoW but may not 429 at the door — the **verify wall** is what stops
the submit. The self-provisioned run (no `--site-key`) uses an aggressive demo
policy so the 429 ladder is visible in ~50 requests.

## What it shows

| Stage | What happens | Signal that catches it |
|---|---|---|
| **1 · verify wall** | Solves the PoW correctly, submits fast with no behaviour blob | verify-time score (fast submit) → `success: false` |
| **2 · rate wall** | Floods `GET /v1/puzzle` | per-IP rate signal escalates `invisible_pass → checkbox → hard_pow → 429` |

Stage 1 solves **both algorithms**: SHA-256 (`node:crypto`) and Argon2id (via
the same `hash-wasm` the widget's worker uses). Argon2id is memory-hard, so the
bot prints the per-hash cost — the point being that escalating the tier makes
each solve progressively unaffordable. If a solve exceeds a 60s budget the bot
gives up and says so (a demonstration in itself); the rate wall then still runs.

Because a no-behaviour bot is only caught at verify by the *fast-submit* signal,
a slow Argon2id solve can slip past the time band and pass — the bot flags this
and points at `VERIFY_REQUIRE_BEHAVIOR=1`, which scores the missing blob and
hard-blocks it regardless of timing.

## Notes

- **Provisioning** needs `ADMIN_TOKEN` (pass `--admin-token`, or set
  `BOLLWARK_ADMIN_TOKEN`) unless the server runs with `DEV_DISABLE_ADMIN_AUTH=1`.
- **The per-IP rate counter is windowed (60s) and shared across sites**, so
  back-to-back runs start already-elevated. Wait ~60s for a clean ladder.
- Watch the server's decisions alongside it with
  `LOG_FORMAT=json … cargo run 2> run.jsonl` and
  `jq -c 'select(.event=="puzzle_decision") | {tier,score,outcome}' run.jsonl`.
