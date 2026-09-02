//! Measure the server-side cost of one Argon2id hash across memory settings,
//! so `ARGON2_M_COST` can be chosen with numbers rather than folklore.
//!
//! One verify is one hash; one *solve* is `2^difficulty` hashes on average.
//! The browser pays the solve (WASM, typically 2–3× slower than this native
//! figure on the same machine, and several times slower again on a low-end
//! phone), the server pays the verify. Run in release, on the machine class
//! you care about:
//!
//! ```text
//! cargo run --release --example argon2_cost -- [t_cost] [difficulty]
//! ```

use std::time::Instant;

use bollwark::puzzle::challenge::compute_argon2id;
use bollwark::puzzle::types::Argon2idParams;

fn main() {
    let mut args = std::env::args().skip(1);
    let t_cost: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(2);
    let difficulty: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(5);
    let expected_hashes = 1u64 << difficulty;
    const ROUNDS: usize = 7;

    println!(
        "Argon2id t_cost={t_cost} p_cost=1, {ROUNDS} hashes per row (median), \
         difficulty {difficulty} = {expected_hashes} expected hashes per solve"
    );
    println!(
        "{:>10} {:>12} {:>16} {:>18}",
        "m_cost KiB", "ms / hash", "native solve s", "verify RSS MiB"
    );
    for m_cost in [1024u32, 8192, 16384, 32768, 65536, 131072] {
        let params = Argon2idParams {
            m_cost,
            t_cost,
            p_cost: 1,
        };
        let mut samples = Vec::with_capacity(ROUNDS);
        for nonce in 0..ROUNDS as u64 {
            let start = Instant::now();
            let out = compute_argon2id("argon2-cost-bench", nonce, params);
            samples.push(start.elapsed().as_secs_f64() * 1000.0);
            assert!(out.is_some(), "params rejected by argon2");
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = samples[ROUNDS / 2];
        println!(
            "{:>10} {:>12.1} {:>16.2} {:>18.0}",
            m_cost,
            median,
            median * expected_hashes as f64 / 1000.0,
            f64::from(m_cost) / 1024.0
        );
    }
}
