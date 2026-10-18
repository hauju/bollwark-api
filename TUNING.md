# Offline detection tuning

This implements the first improvement loop: propose bounded verify-score changes, evaluate them against independent labels, and produce a candidate for review. It does not call an LLM, change production configuration, tune puzzle difficulty or create a background job. Pure search/evaluation lives in `crates/bollwark-tuning`; the local adapter is `examples/tune_weights.rs`.

## Enable a justified data window

Training is off by default. On the API instance, after documenting the purpose, legal basis and necessary retention:

```sh
LOG_RETENTION_HOURS=72
TRAINING_RETENTION_HOURS=720
```

The retention window is counted from the original event, not from collection or feedback. Samples appear when the decision log is pruned. The maximum is 2160 hours (90 days); choose less when sufficient. Unset/zero purges existing samples on startup, including data from older versions. Backups and exports require their own deletion lifecycle. See [CONFIGURATION.md](CONFIGURATION.md#feedback-and-training-samples).

The dataset is pseudonymous, because integrators can link challenge IDs to submissions. No claim of automatic GDPR compliance follows from removing IP addresses. For hosted operation, see the controller-review checklist in the sibling dashboard repo's `docs/LIA-service-improvement.md`. The hosted mirror is optional and requires both `TRAINING_PULL_ENABLED=true` and a finite `TRAINING_RETENTION_HOURS`; it is not needed by this evaluator.

Collect trusted `spam` and `legit` feedback through the existing site-authenticated `/v1/feedback` API. Never label an unlabeled request from its score, block outcome or lack of completion. Synthetic data is useful to test the runner, not to establish production detection gains.

## Run an experiment locally

Create a baseline file containing the **actual deployed weights**. `{}` means the compiled defaults; use that only if those defaults generated the data. Record the effective verify block threshold for the intended rollout. Historical policy thresholds are not stored, so this experiment applies the configured `block_min` consistently rather than claiming to reconstruct old enforcement decisions.

Create a private config file (example dates and site IDs must be replaced). Fix the split and held-out site before looking at results:

```json
{
  "database": "/data/decisions.db",
  "baseline_weights": "/private/baseline-weights.json",
  "train_site": "11111111-1111-4111-8111-111111111111",
  "holdout_site": "22222222-2222-4222-8222-222222222222",
  "split_at": "2026-10-10T00:00:00Z",
  "retention_hours": 720,
  "block_min": 60,
  "max_false_positive_rate": 0.01,
  "min_per_class": 100
}
```

The two sites must differ and be authorized for this use. `split_at` must be UTC midnight inside the current retention window. Source retention is read from the database; the runner refuses disabled training or a longer local window. Old databases without that metadata must be upgraded first.

```sh
cargo run --locked --release --example tune_weights -- /private/tuning.json /private/tuning-run-001
```

The output directory must not exist. On Unix it is created with mode 0700. Treat the input config as private because it contains paths and site IDs. The runner uses one read-only SQLite transaction, not an exported JSONL dataset. A long-running read can hold WAL history, so schedule it outside busy periods and monitor disk usage.

- `report.json` is always written after a valid run, including rejected or insufficient-data experiments. It contains aggregate counts, policy, complete baseline/proposed weights and held-out results. No site/challenge IDs, sample rows, raw telemetry or database paths are emitted.
- `weights.json` is written **only** when both evaluation gates pass. It contains all weights, preserving unchanged puzzle/honeypot weights, and is accepted by `SIGNAL_WEIGHTS_FILE`.

For repeated work, invoke the same command on a schedule with a fresh output directory and a new predeclared future holdout. Scheduling is operator-managed; installing this code schedules nothing. A previous accepted candidate can become the next baseline only after a reviewed rollout and enough compatible new labeled data.

## Evaluation contract

The training partition contains older events from the training site, with labels also received before the split. It is the only partition used for search. Newer events from that site form the temporal holdout. Newer events from the separate site form the cross-site holdout; that site contributes no training rows.

Only labeled, submitted rows with complete behavior counters and replayable verify-score contributions are eligible. Unlabeled, incomplete, incompatible-baseline and invalid-PoW rows are excluded, not guessed. Existing scores are used to check reconstruction, never as labels. Raw features are reduced in memory to boolean signal activations before search.

Search changes ten verify weights in three bounded coordinate sweeps, trying ±5/10/15 points inside 50–150% of baseline. Honeypot, puzzle weights, thresholds, PoW and behavioral rules remain fixed. Dwell ordering is preserved, and noisy individual non-dwell signals must remain below the block threshold. This is a small local search, not a guarantee of finding the global optimum.

Each holdout must have at least the configured number of `spam` and `legit` labels (minimum configuration: 20 per class), strictly more spam blocks than baseline, no extra legitimate blocks, and a Wilson 95% upper bound on false-positive rate below the configured ceiling. At a 1% ceiling, 100 legitimate samples with zero failures are insufficient: roughly 381 are needed. The confidence calculation does not correct biased labels, correlated traffic, poisoned feedback or selection bias caused by earlier blocking.

## Review, shadow, rollout and erasure

An accepted report means **candidate for review**, not permission to deploy. Validate keyboard-only, touch/mobile, accessibility and slow-device flows; test each intended site's policy threshold. Replay cannot measure solve time or abandonment, and this version does not infer disability or device capability from telemetry.

Run the candidate on isolated/shadow traffic first, review the measured changes, then canary with a bounded observation period. `SIGNAL_WEIGHTS_FILE` is loaded at startup; preserve the exact baseline file for rollback. Do not silently apply a globally tuned file to sites whose policy/populations were not evaluated. Reusing an inspected holdout to select subsequent candidates invalidates its independence.

For erasure, the authenticated operator can use:

```text
DELETE /v1/admin/sites/<site-key>/data?challenge_id=<challenge-id>
DELETE /v1/admin/sites/<site-key>/data
```

The first erases one check, the second all decision data for that site. Both remove source decisions, labels and samples, preventing later pruning from recreating them. On the hosted service, erase through the dashboard (deleting a site erases upstream and the mirror together); an erasure run by hand against the API does not reach the mirror until its retention window closes. Apply deletion requests to any independent copies/backups too.
