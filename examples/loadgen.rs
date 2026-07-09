// Synthetic load generator for bollwark.
//
// Drives /v1/puzzle and /v1/verify with several scenarios that the Playwright
// e2e (single real browser) won't easily produce — burst rate, missing headers,
// full PoW-solve loops — and reports tier distribution, status codes, and
// latency percentiles for each.
//
// Usage:
//     cargo run --release --example loadgen -- --base http://127.0.0.1:3000
//
// Flags (all optional):
//     --base       URL of the running bollwark server (default 127.0.0.1:3000)
//     --requests   number of requests per scenario (default 200)
//     --concurrency number of in-flight requests (default 16)
//     --only       comma-separated subset: happy,no_ua,burst,full_solve
//
// The server picks the PoW difficulty per request based on tier. To make
// full_solve finish in reasonable time, run the server with low difficulty:
//     DEFAULT_DIFFICULTY=12 MAX_DIFFICULTY=16 cargo run

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use serde::Deserialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use bollwark::puzzle::challenge::solve_challenge;

#[derive(Debug, Clone)]
struct Args {
    base: String,
    requests: usize,
    concurrency: usize,
    only: Option<Vec<String>>,
}

fn parse_args() -> Args {
    let mut base = "http://127.0.0.1:3000".to_string();
    let mut requests = 200usize;
    let mut concurrency = 16usize;
    let mut only: Option<Vec<String>> = None;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--base" => base = it.next().expect("--base needs value"),
            "--requests" => requests = it.next().unwrap().parse().unwrap(),
            "--concurrency" => concurrency = it.next().unwrap().parse().unwrap(),
            "--only" => {
                only = Some(
                    it.next()
                        .unwrap()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect(),
                )
            }
            "-h" | "--help" => {
                println!("loadgen --base URL --requests N --concurrency C --only s1,s2");
                std::process::exit(0);
            }
            _ => panic!("unknown arg {a}"),
        }
    }

    Args {
        base,
        requests,
        concurrency,
        only,
    }
}

#[derive(Deserialize)]
struct CreateSiteResp {
    site_key: Uuid,
    secret_key: String,
}

#[derive(Deserialize, Clone)]
struct PuzzleResp {
    challenge_id: Uuid,
    prefix: String,
    difficulty: u32,
    tier: String,
}

#[derive(Default)]
struct Stats {
    name: &'static str,
    status_counts: std::collections::BTreeMap<u16, u64>,
    tier_counts: std::collections::BTreeMap<String, u64>,
    verify_outcomes: std::collections::BTreeMap<String, u64>,
    latencies_ms: Vec<u64>,
    errors: u64,
}

impl Stats {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    fn record(&mut self, status: u16, tier: Option<&str>, elapsed: Duration) {
        *self.status_counts.entry(status).or_insert(0) += 1;
        if let Some(t) = tier {
            *self.tier_counts.entry(t.to_string()).or_insert(0) += 1;
        }
        self.latencies_ms.push(elapsed.as_millis() as u64);
    }

    fn record_verify(&mut self, success: bool) {
        let key = if success {
            "success_true"
        } else {
            "success_false"
        };
        *self.verify_outcomes.entry(key.to_string()).or_insert(0) += 1;
    }

    fn record_error(&mut self) {
        self.errors += 1;
    }

    fn print(&self) {
        let mut lat = self.latencies_ms.clone();
        lat.sort_unstable();
        let p = |q: f64| -> u64 {
            if lat.is_empty() {
                0
            } else {
                let i = ((lat.len() as f64 - 1.0) * q).round() as usize;
                lat[i]
            }
        };
        println!("\n── scenario: {} ──", self.name);
        println!("  total requests:   {}", lat.len());
        println!("  errors:           {}", self.errors);
        println!(
            "  latency (ms):     p50={} p95={} p99={} max={}",
            p(0.50),
            p(0.95),
            p(0.99),
            lat.last().copied().unwrap_or(0)
        );
        println!("  status codes:");
        for (code, n) in &self.status_counts {
            println!("    {code}: {n}");
        }
        if !self.tier_counts.is_empty() {
            println!("  tier distribution:");
            for (tier, n) in &self.tier_counts {
                println!("    {tier:<20} {n}");
            }
        }
        if !self.verify_outcomes.is_empty() {
            println!("  verify outcomes:");
            for (k, n) in &self.verify_outcomes {
                println!("    {k:<20} {n}");
            }
        }
    }
}

async fn create_site(client: &Client, base: &str) -> CreateSiteResp {
    client
        .post(format!("{base}/v1/sites"))
        .json(&serde_json::json!({ "name": "loadgen" }))
        .send()
        .await
        .expect("POST /v1/sites failed")
        .error_for_status()
        .expect("POST /v1/sites non-2xx")
        .json()
        .await
        .expect("decode CreateSiteResp")
}

fn realistic_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        USER_AGENT,
        HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        ),
    );
    h.insert(
        HeaderName::from_static("accept-language"),
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    h.insert(
        HeaderName::from_static("accept-encoding"),
        HeaderValue::from_static("gzip, deflate, br"),
    );
    h
}

/// Send N puzzle requests with the given header map, with up to `concurrency`
/// in flight. Records per-response stats.
async fn run_puzzle_scenario(
    name: &'static str,
    args: &Args,
    base: &str,
    site_key: Uuid,
    headers: HeaderMap,
) -> Stats {
    let client = Client::builder()
        .default_headers(headers)
        .build()
        .expect("client");
    let stats = Arc::new(Mutex::new(Stats::new(name)));
    let sem = Arc::new(tokio::sync::Semaphore::new(args.concurrency));

    let url = format!("{base}/v1/puzzle?site_key={site_key}");
    let mut handles = Vec::with_capacity(args.requests);
    for _ in 0..args.requests {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.clone();
        let stats = Arc::clone(&stats);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let t = Instant::now();
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let tier = serde_json::from_str::<PuzzleResp>(&body)
                        .ok()
                        .map(|p| p.tier);
                    let mut s = stats.lock().await;
                    s.record(status, tier.as_deref(), t.elapsed());
                }
                Err(_) => {
                    let mut s = stats.lock().await;
                    s.record_error();
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Arc::try_unwrap(stats).ok().unwrap().into_inner()
}

/// End-to-end scenario: GET /v1/puzzle, solve PoW, POST /v1/verify.
/// Measures the full pipeline including verify-time scoring.
async fn run_full_solve_scenario(
    args: &Args,
    base: &str,
    site_key: Uuid,
    secret_key: &str,
) -> Stats {
    let client = Client::builder()
        .default_headers(realistic_headers())
        .build()
        .expect("client");
    let stats = Arc::new(Mutex::new(Stats::new("full_solve")));

    let puzzle_url = format!("{base}/v1/puzzle?site_key={site_key}");
    let verify_url = format!("{base}/v1/verify");
    let bearer = format!("Bearer {secret_key}");

    // PoW solving is CPU-bound. Don't oversaturate — cap parallel solves to
    // half the configured concurrency so the server can still answer.
    let solve_parallelism = args.concurrency.max(2) / 2;
    let sem = Arc::new(tokio::sync::Semaphore::new(solve_parallelism));

    let mut handles = Vec::with_capacity(args.requests);
    for i in 0..args.requests {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let puzzle_url = puzzle_url.clone();
        let verify_url = verify_url.clone();
        let bearer = bearer.clone();
        let stats = Arc::clone(&stats);
        let plant_honeypot = i % 25 == 0; // sprinkle a few "bot" submissions

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let t = Instant::now();
            // 1. Fetch puzzle.
            let puzzle: PuzzleResp = match client.get(&puzzle_url).send().await {
                Ok(r) if r.status().is_success() => match r.json().await {
                    Ok(p) => p,
                    Err(_) => {
                        stats.lock().await.record_error();
                        return;
                    }
                },
                Ok(r) => {
                    let status = r.status().as_u16();
                    stats.lock().await.record(status, None, t.elapsed());
                    return;
                }
                Err(_) => {
                    stats.lock().await.record_error();
                    return;
                }
            };

            // 2. Solve PoW (in a blocking task — CPU bound).
            let prefix = puzzle.prefix.clone();
            let difficulty = puzzle.difficulty;
            let nonce = tokio::task::spawn_blocking(move || solve_challenge(&prefix, difficulty))
                .await
                .expect("solve panicked");

            // 3. Verify.
            let mut body = serde_json::json!({
                "challenge_id": puzzle.challenge_id,
                "nonce": nonce,
                "time_on_page_ms": 4500,
                "behavior": {
                    "mouse_moves": 23,
                    "touches": 0,
                    "interactions": 3,
                    "first_interaction_ms": 850,
                },
            });
            if plant_honeypot {
                body["honeypot"] = serde_json::Value::String("bot@example".into());
            }

            match client
                .post(&verify_url)
                .header("authorization", &bearer)
                .json(&body)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let elapsed = t.elapsed();
                    let v: serde_json::Value = resp.json().await.unwrap_or_default();
                    let success = v.get("success").and_then(|b| b.as_bool()).unwrap_or(false);
                    let mut s = stats.lock().await;
                    s.record(status, Some(&puzzle.tier), elapsed);
                    s.record_verify(success);
                }
                Err(_) => {
                    stats.lock().await.record_error();
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Arc::try_unwrap(stats).ok().unwrap().into_inner()
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    println!(
        "loadgen → base={} requests={} concurrency={}",
        args.base, args.requests, args.concurrency
    );

    let bootstrap = Client::new();
    let site = create_site(&bootstrap, &args.base).await;
    println!("created site_key={}", site.site_key);

    let want = |name: &str| {
        args.only
            .as_ref()
            .is_none_or(|v| v.iter().any(|s| s == name))
    };

    let mut all_stats: Vec<Stats> = Vec::new();

    if want("happy") {
        all_stats.push(
            run_puzzle_scenario(
                "happy",
                &args,
                &args.base,
                site.site_key,
                realistic_headers(),
            )
            .await,
        );
    }

    if want("no_ua") {
        let mut h = realistic_headers();
        h.remove(USER_AGENT);
        all_stats.push(
            run_puzzle_scenario("no_ua (UA stripped)", &args, &args.base, site.site_key, h).await,
        );
    }

    if want("burst") {
        // Burst: minimal headers, max concurrency. Drives the rate signal.
        let burst_args = Args {
            concurrency: args.concurrency.max(64),
            ..args.clone()
        };
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static("curl/8.0"));
        all_stats.push(
            run_puzzle_scenario(
                "burst (curl UA, hot IP)",
                &burst_args,
                &args.base,
                site.site_key,
                h,
            )
            .await,
        );
    }

    if want("full_solve") {
        // Run a smaller batch — PoW is expensive.
        let solve_args = Args {
            requests: args.requests.min(50),
            ..args.clone()
        };
        // Re-create a fresh site so verify-time stats aren't polluted by burst
        // counters from earlier scenarios.
        let fresh = create_site(&bootstrap, &args.base).await;
        all_stats.push(
            run_full_solve_scenario(&solve_args, &args.base, fresh.site_key, &fresh.secret_key)
                .await,
        );
    }

    println!("\n=== summary ===");
    for s in &all_stats {
        s.print();
    }
}
