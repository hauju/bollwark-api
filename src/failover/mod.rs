//! Client failover: letting an embedding form stay usable while this service
//! is unreachable, without turning "the captcha was down" into a free bypass.
//!
//! # The problem
//!
//! The widget is a hard dependency of every form it guards. If `GET /v1/puzzle`
//! fails, the visitor has no token, and the integrator's backend rejects the
//! submit — so our downtime becomes *their* downtime, silently, on every
//! embedding site at once. This is not hypothetical: `scripts/check-public-
//! endpoint.sh` exists because Traefik's self-signed-cert fallback has already
//! broken widget delivery while `/healthz` stayed green.
//!
//! # The mechanism
//!
//! When the widget exhausts its puzzle-fetch retries it mints a *failover
//! claim* instead of a solved token, and the form submits as usual. The
//! integrator's backend forwards it to `/v1/verify` like any other token. This
//! service then decides whether to honor it.
//!
//! # What this does and does not prove
//!
//! A failover claim is **unauthenticated by construction**. During an outage we
//! cannot have signed anything, so the claim is plain client-authored JSON that
//! anyone can fabricate. Honoring one is a deliberate fail-open, and the
//! security properties are only these:
//!
//! 1. **Attestation.** A claim is honored only when this service independently
//!    knows it was unable to serve — either a persisted-heartbeat gap across a
//!    restart ([`OutageSource::HeartbeatGap`]) or a window an operator declared
//!    ([`OutageSource::Declared`]). Absent that, the claim is refused; this is
//!    the "the client says we were down but we have no record of it" case.
//! 2. **Recency.** The load-bearing check is that *now* falls inside an
//!    attested window or within `grace` of its close — not the claim's
//!    `issued_at`, which is client-supplied and therefore forgeable. A stale
//!    window can never be reopened by backdating a claim.
//! 3. **Rate cap.** Accepted claims are capped per site per minute, so an
//!    attacker who catches a genuine outage still can't drive unbounded
//!    fail-open traffic through it.
//! 4. **Marking.** Every acceptance sets `failover: true` on the verify
//!    response, emits a WARN, and increments a counter surfaced at
//!    `GET /v1/admin/outages` — so an integrator can accept-but-flag rather
//!    than treating it as a clean pass.
//!
//! Within an attested window a determined attacker *does* get through. That is
//! the trade being made: a bounded, observable fail-open in exchange for not
//! taking every embedding form down with us. It is off by default
//! (`FAILOVER_ENABLED`) precisely because that trade is the operator's to make.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How a window came to be attested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutageSource {
    /// Inferred at boot from a gap in the persisted heartbeat: the process was
    /// not running (crash, OOM kill, deploy, host reboot) for longer than
    /// `FAILOVER_MIN_GAP_SECS`.
    HeartbeatGap,
    /// Declared by an operator via `POST /v1/admin/outages`. Covers the failure
    /// mode a heartbeat structurally cannot see — the process healthy the whole
    /// time while something in front of it (TLS, DNS, CDN, reverse proxy) made
    /// the widget unreachable to browsers.
    Declared,
}

/// A half-open `[start, end)` interval during which this service is known to
/// have been unable to serve puzzles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutageWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub source: OutageSource,
}

impl OutageWindow {
    /// Whether `now` is inside the window or still within `grace` of its close.
    ///
    /// The grace tail exists because a visitor who loaded the form *during* the
    /// outage submits it some seconds or minutes later, by which point we may
    /// already be back up. Without it, failover would only help visitors who
    /// happened to submit before recovery — i.e. almost nobody.
    fn covers(&self, now: DateTime<Utc>, grace: Duration) -> bool {
        now >= self.start && now < self.end + grace
    }
}

/// Persisted failover state. Small enough to rewrite wholesale on every save.
#[derive(Debug, Default, Serialize, Deserialize)]
struct FailoverState {
    /// Last time the process was observed alive. `None` on a first-ever boot,
    /// which is why a fresh deployment never attests an outage.
    #[serde(default)]
    last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default)]
    windows: Vec<OutageWindow>,
}

/// Per-site acceptance counter over a rolling 60s window.
#[derive(Debug)]
struct AcceptCounter {
    window_start: DateTime<Utc>,
    count: u32,
}

/// Why a failover claim was refused, or that it was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverVerdict {
    /// Honored: `now` falls inside (or within grace of) an attested window.
    Accept { source: OutageSource },
    /// `FAILOVER_ENABLED` is false, or no state path is configured so nothing
    /// can be attested.
    Disabled,
    /// The client claims it couldn't reach us, but we have no record of having
    /// been unreachable. The direct analogue of a forged bypass attempt.
    Unattested,
    /// Well-formed but the claim's own timestamp is implausible — far in the
    /// future, or older than any window could still cover.
    StaleClaim,
    /// Attested, but this site has already exhausted its per-minute cap.
    RateLimited,
}

impl FailoverVerdict {
    /// Short stable string for logs and the decision-log `outcome` column.
    pub fn outcome(&self) -> &'static str {
        match self {
            FailoverVerdict::Accept { .. } => "failover_pass",
            FailoverVerdict::Disabled => "failover_disabled",
            FailoverVerdict::Unattested => "failover_unattested",
            FailoverVerdict::StaleClaim => "failover_stale",
            FailoverVerdict::RateLimited => "failover_rate_limited",
        }
    }

    pub fn accepted(&self) -> bool {
        matches!(self, FailoverVerdict::Accept { .. })
    }
}

/// Tunables, mirrored from [`crate::config::AppConfig`].
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    pub enabled: bool,
    pub state_path: Option<PathBuf>,
    pub heartbeat_interval_secs: u64,
    pub min_gap_secs: u64,
    pub grace_secs: u64,
    pub max_per_min: u32,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            state_path: None,
            heartbeat_interval_secs: 15,
            min_gap_secs: 60,
            grace_secs: 300,
            max_per_min: 600,
        }
    }
}

/// Tolerance for client clock skew when sanity-checking a claim's `issued_at`.
/// Generous on purpose: this check only filters obvious nonsense, it is not a
/// security control (see the module docs — `issued_at` is forgeable).
const CLOCK_SKEW: i64 = 300;

/// Owns outage attestation and the failover accept/refuse decision.
pub struct FailoverGuard {
    config: FailoverConfig,
    state: RwLock<FailoverState>,
    accepts: RwLock<HashMap<Uuid, AcceptCounter>>,
    accepted_total: AtomicU64,
    refused_total: AtomicU64,
}

impl FailoverGuard {
    /// Load persisted state, and attest an outage window if the heartbeat shows
    /// the process was gone longer than `min_gap_secs`.
    ///
    /// A missing or corrupt state file is not fatal: it degrades to "nothing
    /// attested" (every claim refused), which is the safe direction. Failing
    /// boot over an unreadable failover file would turn a fail-open convenience
    /// into an availability risk of its own.
    pub fn load(config: FailoverConfig) -> Self {
        let now = Utc::now();
        let mut state = config
            .state_path
            .as_deref()
            .map(read_state)
            .unwrap_or_default();

        if let Some(last) = state.last_heartbeat {
            let gap = now - last;
            if gap >= Duration::seconds(config.min_gap_secs as i64) {
                tracing::warn!(
                    event = "failover_outage_attested",
                    source = "heartbeat_gap",
                    start = %last,
                    end = %now,
                    gap_secs = gap.num_seconds(),
                    "Heartbeat gap on boot — attesting an outage window"
                );
                state.windows.push(OutageWindow {
                    start: last,
                    end: now,
                    source: OutageSource::HeartbeatGap,
                });
            }
        }

        state.last_heartbeat = Some(now);
        prune(&mut state, now, config.grace_secs);

        let guard = Self {
            config,
            state: RwLock::new(state),
            accepts: RwLock::new(HashMap::new()),
            accepted_total: AtomicU64::new(0),
            refused_total: AtomicU64::new(0),
        };
        guard.persist();
        guard
    }

    /// A guard that attests nothing and refuses every claim. Used when failover
    /// is off, and by tests that don't exercise it.
    pub fn disabled() -> Self {
        Self::load(FailoverConfig::default())
    }

    pub fn enabled(&self) -> bool {
        // Without a state path nothing survives a restart, so a heartbeat gap
        // could never be detected and a declared window would evaporate on the
        // very restart it exists to cover. Treat that as off rather than
        // pretending to offer failover.
        self.config.enabled && self.config.state_path.is_some()
    }

    pub fn heartbeat_interval_secs(&self) -> u64 {
        self.config.heartbeat_interval_secs
    }

    /// Record that the process is alive. Called on a timer; the gap between the
    /// last of these and the next boot is what becomes an attested window.
    pub fn heartbeat(&self) {
        let now = Utc::now();
        {
            let mut state = self.state.write().expect("failover state poisoned");
            state.last_heartbeat = Some(now);
            prune(&mut state, now, self.config.grace_secs);
        }
        self.persist();
    }

    /// Declare an outage window covering `[start, end)`.
    ///
    /// This is the escape hatch for outages the process cannot self-observe:
    /// it was healthy throughout while something in front of it broke. The
    /// caller is trusted (admin bearer token).
    pub fn declare_outage(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> OutageWindow {
        let window = OutageWindow {
            start,
            end,
            source: OutageSource::Declared,
        };
        {
            let mut state = self.state.write().expect("failover state poisoned");
            state.windows.push(window.clone());
            prune(&mut state, Utc::now(), self.config.grace_secs);
        }
        self.persist();
        tracing::warn!(
            event = "failover_outage_attested",
            source = "declared",
            start = %window.start,
            end = %window.end,
            "Operator declared an outage window"
        );
        window
    }

    /// Windows still recent enough to cover a claim, for the admin endpoint.
    pub fn active_windows(&self) -> Vec<OutageWindow> {
        let now = Utc::now();
        let grace = Duration::seconds(self.config.grace_secs as i64);
        self.state
            .read()
            .expect("failover state poisoned")
            .windows
            .iter()
            .filter(|w| w.covers(now, grace))
            .cloned()
            .collect()
    }

    /// Accepted / refused counts since boot, for the admin endpoint.
    pub fn counters(&self) -> (u64, u64) {
        (
            self.accepted_total.load(Ordering::Relaxed),
            self.refused_total.load(Ordering::Relaxed),
        )
    }

    /// Decide a failover claim. `issued_at_ms` is the client-supplied mint time.
    pub fn evaluate(&self, site_key: &Uuid, issued_at_ms: i64) -> FailoverVerdict {
        let verdict = self.evaluate_at(site_key, issued_at_ms, Utc::now());
        if verdict.accepted() {
            self.accepted_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.refused_total.fetch_add(1, Ordering::Relaxed);
        }
        verdict
    }

    /// `evaluate` with an injectable clock, so the window/grace arithmetic is
    /// testable without sleeping.
    fn evaluate_at(
        &self,
        site_key: &Uuid,
        issued_at_ms: i64,
        now: DateTime<Utc>,
    ) -> FailoverVerdict {
        if !self.enabled() {
            return FailoverVerdict::Disabled;
        }

        let grace = Duration::seconds(self.config.grace_secs as i64);

        // Find an attested window that still covers *now*. Deliberately keyed
        // on `now`, not on the claim's timestamp: the client controls
        // `issued_at`, so binding to it would let a backdated claim reopen any
        // window we ever recorded.
        let source = {
            let state = self.state.read().expect("failover state poisoned");
            match state.windows.iter().find(|w| w.covers(now, grace)) {
                Some(w) => w.source,
                None => return FailoverVerdict::Unattested,
            }
        };

        // Sanity-only: reject a claim minted implausibly far in the future or
        // older than the widest window we'd still honor. Cheap filter on broken
        // or lazy clients; not load-bearing against a forger.
        let issued_at = match DateTime::from_timestamp_millis(issued_at_ms) {
            Some(t) => t,
            None => return FailoverVerdict::StaleClaim,
        };
        let skew = Duration::seconds(CLOCK_SKEW);
        if issued_at > now + skew || issued_at < now - grace - skew {
            return FailoverVerdict::StaleClaim;
        }

        if !self.admit(site_key, now) {
            return FailoverVerdict::RateLimited;
        }

        FailoverVerdict::Accept { source }
    }

    /// Per-site rolling-minute cap on accepted claims. `max_per_min == 0`
    /// disables the cap.
    fn admit(&self, site_key: &Uuid, now: DateTime<Utc>) -> bool {
        if self.config.max_per_min == 0 {
            return true;
        }
        let mut accepts = self.accepts.write().expect("failover accepts poisoned");
        let entry = accepts.entry(*site_key).or_insert(AcceptCounter {
            window_start: now,
            count: 0,
        });
        if now - entry.window_start >= Duration::seconds(60) {
            entry.window_start = now;
            entry.count = 0;
        }
        if entry.count >= self.config.max_per_min {
            return false;
        }
        entry.count += 1;
        true
    }

    /// Write state to disk. Best-effort: a failed write is logged, not fatal —
    /// the consequence is a missed attestation, which fails closed.
    ///
    /// Called at boot, on each heartbeat (default every 15s), and on declare —
    /// never from the verify path. The payload is a few hundred bytes, so the
    /// synchronous write is not a meaningful stall even on the async runtime.
    fn persist(&self) {
        let Some(path) = self.config.state_path.as_deref() else {
            return;
        };
        let snapshot = {
            let state = self.state.read().expect("failover state poisoned");
            serde_json::to_vec_pretty(&*state)
        };
        let bytes = match snapshot {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize failover state");
                return;
            }
        };
        if let Err(e) = write_atomic(path, &bytes) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Failed to persist failover state — an outage across the next \
                 restart may go unattested"
            );
        }
    }
}

/// Drop windows that can no longer cover any claim. Bounds the state file.
fn prune(state: &mut FailoverState, now: DateTime<Utc>, grace_secs: u64) {
    let grace = Duration::seconds(grace_secs as i64);
    state.windows.retain(|w| w.covers(now, grace));
}

fn read_state(path: &Path) -> FailoverState {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Failover state file is unreadable — starting with no attested \
                 outages (claims will be refused until one is recorded)"
            );
            FailoverState::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FailoverState::default(),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Failed to read failover state file"
            );
            FailoverState::default()
        }
    }
}

/// Write via temp file + rename so a crash mid-write can't leave a truncated
/// state file that reads back as "no attested outages".
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> FailoverConfig {
        FailoverConfig {
            enabled: true,
            state_path: Some(dir.join("failover.json")),
            heartbeat_interval_secs: 15,
            min_gap_secs: 60,
            grace_secs: 300,
            max_per_min: 5,
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bollwark-failover-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn first_boot_attests_nothing() {
        let dir = tmpdir("first-boot");
        let guard = FailoverGuard::load(cfg(&dir));
        assert!(guard.active_windows().is_empty());
        assert_eq!(
            guard.evaluate(&Uuid::new_v4(), Utc::now().timestamp_millis()),
            FailoverVerdict::Unattested,
            "a fresh deployment must not hand out a fail-open window"
        );
    }

    #[test]
    fn heartbeat_gap_across_restart_attests_a_window() {
        let dir = tmpdir("gap");
        let path = dir.join("failover.json");

        // Simulate a process that was last alive 10 minutes ago.
        let stale = FailoverState {
            last_heartbeat: Some(Utc::now() - Duration::minutes(10)),
            windows: vec![],
        };
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();

        let guard = FailoverGuard::load(cfg(&dir));
        let windows = guard.active_windows();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].source, OutageSource::HeartbeatGap);
        assert!(matches!(
            guard.evaluate(&Uuid::new_v4(), Utc::now().timestamp_millis()),
            FailoverVerdict::Accept { .. }
        ));
    }

    #[test]
    fn short_gap_is_not_an_outage() {
        let dir = tmpdir("short-gap");
        let path = dir.join("failover.json");
        let recent = FailoverState {
            last_heartbeat: Some(Utc::now() - Duration::seconds(5)),
            windows: vec![],
        };
        std::fs::write(&path, serde_json::to_vec(&recent).unwrap()).unwrap();

        let guard = FailoverGuard::load(cfg(&dir));
        assert!(
            guard.active_windows().is_empty(),
            "a normal restart is not an outage"
        );
    }

    #[test]
    fn declared_window_is_honored_then_expires_after_grace() {
        let dir = tmpdir("declared");
        let guard = FailoverGuard::load(cfg(&dir));
        let now = Utc::now();
        guard.declare_outage(now - Duration::minutes(5), now);

        let site = Uuid::new_v4();
        assert!(
            guard
                .evaluate_at(&site, now.timestamp_millis(), now)
                .accepted()
        );

        // Grace is 300s; 301s past the window's close it must stop covering.
        let after = now + Duration::seconds(301);
        assert_eq!(
            guard.evaluate_at(&site, after.timestamp_millis(), after),
            FailoverVerdict::Unattested,
            "a closed window must not stay open past its grace tail"
        );
    }

    #[test]
    fn backdated_claim_cannot_reopen_a_stale_window() {
        let dir = tmpdir("backdate");
        let guard = FailoverGuard::load(cfg(&dir));
        let now = Utc::now();
        guard.declare_outage(now - Duration::minutes(5), now);

        // An attacker replays a claim stamped inside the old window, long after
        // grace has elapsed. The window check keys on `now`, so this fails.
        let much_later = now + Duration::hours(2);
        assert_eq!(
            guard.evaluate_at(
                &site_key(),
                (now - Duration::minutes(4)).timestamp_millis(),
                much_later
            ),
            FailoverVerdict::Unattested
        );
    }

    #[test]
    fn future_dated_claim_is_stale() {
        let dir = tmpdir("future");
        let guard = FailoverGuard::load(cfg(&dir));
        let now = Utc::now();
        guard.declare_outage(now - Duration::minutes(1), now);
        assert_eq!(
            guard.evaluate_at(
                &site_key(),
                (now + Duration::hours(1)).timestamp_millis(),
                now
            ),
            FailoverVerdict::StaleClaim
        );
    }

    #[test]
    fn per_site_cap_bounds_accepted_claims() {
        let dir = tmpdir("cap");
        let guard = FailoverGuard::load(cfg(&dir)); // max_per_min = 5
        let now = Utc::now();
        guard.declare_outage(now - Duration::minutes(1), now);

        let site = site_key();
        for i in 0..5 {
            assert!(
                guard
                    .evaluate_at(&site, now.timestamp_millis(), now)
                    .accepted(),
                "claim {i} should be within the cap"
            );
        }
        assert_eq!(
            guard.evaluate_at(&site, now.timestamp_millis(), now),
            FailoverVerdict::RateLimited
        );

        // A different site has its own budget.
        assert!(
            guard
                .evaluate_at(&site_key(), now.timestamp_millis(), now)
                .accepted()
        );
    }

    #[test]
    fn disabled_without_state_path() {
        let mut c = FailoverConfig {
            enabled: true,
            ..FailoverConfig::default()
        };
        c.state_path = None;
        let guard = FailoverGuard::load(c);
        assert!(!guard.enabled());
        assert_eq!(
            guard.evaluate(&site_key(), Utc::now().timestamp_millis()),
            FailoverVerdict::Disabled
        );
    }

    #[test]
    fn corrupt_state_file_degrades_to_nothing_attested() {
        let dir = tmpdir("corrupt");
        std::fs::write(dir.join("failover.json"), b"{not json").unwrap();
        let guard = FailoverGuard::load(cfg(&dir));
        assert!(guard.active_windows().is_empty());
    }

    #[test]
    fn declared_window_survives_a_restart() {
        let dir = tmpdir("persist");
        let now = Utc::now();
        {
            let guard = FailoverGuard::load(cfg(&dir));
            guard.declare_outage(now - Duration::minutes(1), now + Duration::minutes(10));
        }
        // Reload from disk, as a restart would.
        let guard = FailoverGuard::load(cfg(&dir));
        assert_eq!(guard.active_windows().len(), 1);
        assert!(
            guard
                .evaluate(&site_key(), Utc::now().timestamp_millis())
                .accepted()
        );
    }

    fn site_key() -> Uuid {
        Uuid::new_v4()
    }
}
