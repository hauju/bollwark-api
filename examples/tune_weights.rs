//! Local-only tuning: cargo run --example tune_weights -- config.json NEW_OUTPUT_DIR
use std::{collections::BTreeMap, fs, path::Path};

use bollwark::risk::{
    behavior::score_behavior_with,
    verify::{score_remote_ip_with, score_time_on_page_with},
};
use bollwark::{
    dashboard::{query::training_blocking, types::TrainingVerify},
    risk::{BehaviorPresence, BehaviorReport, weights::SignalWeights},
};
use bollwark_tuning::{KEYS, Policy, Sample, Weights, compare, search};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    database: String,
    baseline_weights: String,
    train_site: uuid::Uuid,
    holdout_site: uuid::Uuid,
    /// Fixed before the experiment. Training labels must also predate this.
    split_at: DateTime<Utc>,
    retention_hours: u64,
    block_min: u32,
    max_false_positive_rate: f64,
    min_per_class: usize,
}

fn vector(w: &SignalWeights) -> Weights {
    let values = serde_json::to_value(w).expect("weights serialize");
    std::array::from_fn(|i| values[KEYS[i]].as_u64().unwrap() as u32)
}

fn apply(base: &SignalWeights, values: &Weights) -> SignalWeights {
    let mut map = serde_json::to_value(base).unwrap();
    for (key, value) in KEYS.iter().zip(values) {
        map[*key] = json!(value);
    }
    SignalWeights::parse(&map.to_string()).expect("known bounded weights")
}

fn bool_probe(value: &str) -> Option<Option<bool>> {
    match value {
        "true" => Some(Some(true)),
        "false" => Some(Some(false)),
        "n/a" | "absent" => Some(None),
        _ => None,
    }
}

/// Reduce telemetry to boolean activations immediately. Missing/legacy data and
/// rows incompatible with the supplied baseline are excluded, never guessed.
fn project(v: &TrainingVerify, base: &SignalWeights, spam: bool) -> Option<Sample> {
    if !matches!(v.outcome.as_str(), "pass" | "shadow_fail" | "block") {
        return None;
    }
    let b = BehaviorPresence::Present(BehaviorReport {
        mouse_moves: v.mouse_moves?,
        touches: v.touches?,
        interactions: v.interactions?,
        first_interaction_ms: v.first_interaction_ms,
        webdriver: bool_probe(&v.webdriver)?,
        automation: bool_probe(&v.automation)?,
        headless: bool_probe(&v.headless)?,
    });
    let behavior = |w: &SignalWeights| {
        score_behavior_with(w, b)
            + if v.impossible_timing {
                w.behavior_impossible_timing
            } else {
                0
            }
            + if v.duplicate_blob {
                w.behavior_duplicate
            } else {
                0
            }
    };
    if v.sig_time_on_page != score_time_on_page_with(base, v.time_on_page_ms)
        || v.sig_behavior != behavior(base)
        || v.sig_remote_ip != score_remote_ip_with(base, v.sig_remote_ip > 0)
        || (v.sig_honeypot != 0 && v.sig_honeypot != base.honeypot_tripped)
        || u64::from(v.score)
            != [
                v.sig_honeypot,
                v.sig_time_on_page,
                v.sig_behavior,
                v.sig_remote_ip,
            ]
            .iter()
            .map(|s| u64::from(*s))
            .sum::<u64>()
    {
        return None;
    }
    let zero = apply(base, &[0; KEYS.len()]);
    let active = std::array::from_fn(|i| {
        let mut unit = [0; KEYS.len()];
        unit[i] = 1;
        let w = apply(&zero, &unit);
        score_time_on_page_with(&w, v.time_on_page_ms)
            + score_remote_ip_with(&w, v.sig_remote_ip > 0)
            + behavior(&w)
            > 0
    });
    Some(Sample {
        spam,
        active,
        fixed_score: v.sig_honeypot,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: tune_weights CONFIG.json NEW_OUTPUT_DIR".into());
    }
    let config: Config = serde_json::from_slice(&fs::read(&args[1])?)?;
    let policy = Policy {
        block_min: config.block_min,
        max_false_positive_rate: config.max_false_positive_rate,
        min_per_class: config.min_per_class,
    };
    policy.validate()?;
    if config.train_site == config.holdout_site || !(1..=2160).contains(&config.retention_hours) {
        return Err("use distinct train/holdout sites and retention_hours in 1..=2160".into());
    }
    // Enforce the server's persisted opt-in/window as well as the local limit.
    let conn = rusqlite::Connection::open_with_flags(
        &config.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    conn.execute_batch("BEGIN")?;
    let server_hours: u64 = conn.query_row(
        "SELECT hours FROM training_retention WHERE id = 1",
        [],
        |r| r.get(0),
    )?;
    if server_hours == 0 || config.retention_hours > server_hours {
        return Err("training disabled or requested window exceeds server retention".into());
    }
    let now = Utc::now();
    let oldest = now - chrono::Duration::hours(config.retention_hours as i64);
    if config.split_at <= oldest
        || config.split_at >= now
        || config.split_at.timestamp() % 86400 != 0
    {
        return Err("split_at must be UTC midnight inside the retained window".into());
    }
    let base = SignalWeights::from_file(&config.baseline_weights)?;
    // Limit all weights before sums in the production scorer; refuse zero
    // verification weights because historical activations may have been lost.
    let map: BTreeMap<String, u32> = serde_json::from_value(serde_json::to_value(&base)?)?;
    if map.values().any(|w| *w > 1000) || base.honeypot_tripped == 0 || vector(&base).contains(&0) {
        return Err("baseline requires positive verify weights and all weights <= 1000".into());
    }
    let (mut train, mut future, mut unseen) = (Vec::new(), Vec::new(), Vec::new());
    let mut skipped = 0_usize;
    let mut after_id = 0;
    loop {
        let page = training_blocking(&conn, after_id, 1000)?;
        for row in page.samples {
            let is_train_site = row.site_key == config.train_site.to_string();
            let is_holdout_site = row.site_key == config.holdout_site.to_string();
            if !is_train_site && !is_holdout_site {
                continue;
            }
            let time = DateTime::parse_from_rfc3339(&row.hour)?;
            if time <= oldest || time > now {
                continue;
            }
            let sample = row
                .verify
                .as_ref()
                .and_then(|v| match row.label.as_deref() {
                    Some("spam") => project(v, &base, true),
                    Some("legit") => project(v, &base, false),
                    _ => None,
                });
            let Some(sample) = sample else {
                skipped += 1;
                continue;
            };
            if time >= config.split_at {
                if is_holdout_site {
                    unseen.push(sample);
                } else {
                    future.push(sample);
                }
            } else if is_train_site {
                // No retrospective label leakage from the evaluation window.
                let label_time = row
                    .labeled_at
                    .as_deref()
                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok());
                if label_time.is_some_and(|t| t < config.split_at) {
                    train.push(sample);
                } else {
                    skipped += 1;
                }
            }
        }
        match page.next_after_id {
            Some(id) => after_id = id,
            None => break,
        }
    }
    drop(conn);
    let baseline = vector(&base);
    let result = search(&train, baseline, policy);
    let candidate = result.as_ref().copied().unwrap_or(baseline);
    let temporal = compare(&future, &baseline, &candidate, policy);
    let cross_site = compare(&unseen, &baseline, &candidate, policy);
    let accepted = result.is_ok() && temporal.accepted && cross_site.accepted;
    let candidate_weights = apply(&base, &candidate);
    let report = json!({
        "schema_version": 1, "created_at": now, "split_at": config.split_at,
        "status": if accepted { "candidate_for_review" } else { "rejected" },
        "search_error": result.err(), "policy": policy, "retention_hours": config.retention_hours,
        "training": bollwark_tuning::evaluate(&train, &baseline, policy.block_min),
        "temporal_holdout": temporal, "cross_site_holdout": cross_site,
        "excluded_unlabeled_or_unreplayable": skipped,
        "baseline_weights": base, "proposed_weights": candidate_weights,
        "scope": "verify scoring only; empirical label quality and sampling bias remain operator responsibilities; no production change",
    });
    // New directory only: never overwrite a previous experiment or deployment.
    let output = Path::new(&args[2]);
    fs::create_dir(output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    }
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    if accepted {
        fs::write(
            output.join("weights.json"),
            serde_json::to_vec_pretty(&candidate_weights)?,
        )?;
    }
    println!(
        "{}: report.json written; {}",
        if accepted {
            "candidate for review"
        } else {
            "rejected"
        },
        if accepted {
            "weights.json requires shadow evaluation before deployment"
        } else {
            "no deployable weights written"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_matches_scoring_and_rejects_incomplete_rows() {
        let base = SignalWeights::default();
        let mut v = TrainingVerify {
            score: 80,
            outcome: "block".into(),
            success: false,
            monitored: false,
            sig_honeypot: 0,
            sig_time_on_page: 50,
            sig_behavior: 30,
            sig_remote_ip: 0,
            time_on_page_ms: Some(100),
            webdriver: "true".into(),
            automation: "true".into(),
            headless: "false".into(),
            mouse_moves: Some(10),
            touches: Some(0),
            interactions: Some(4),
            first_interaction_ms: Some(10),
            impossible_timing: false,
            duplicate_blob: false,
        };
        let s = project(&v, &base, true).unwrap();
        assert_eq!(
            s.active.iter().filter(|a| **a).count(),
            2,
            "automation saturates and keyboard interactions exempt instant timing"
        );
        assert_eq!(
            bollwark_tuning::evaluate(&[s], &vector(&base), 80).spam_blocked,
            1
        );
        v.mouse_moves = None;
        assert!(project(&v, &base, true).is_none());
        v.mouse_moves = Some(10);
        v.sig_behavior = 60;
        assert!(project(&v, &base, true).is_none());
    }
}
