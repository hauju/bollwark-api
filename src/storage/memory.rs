use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, RwLock};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::error::CaptchaError;
use crate::puzzle::types::Challenge;
use crate::risk::behavior::BEHAVIOR_DUPLICATE_WINDOW_SECS;
use crate::risk::signals::RATE_SUSTAINED_WINDOW_SECS;
use crate::site::types::{Site, SitePolicy};

use super::Store;

struct RateWindow {
    count: u32,
    window_start: i64,
}

/// Number of lock stripes for each rate map. Every `GET /v1/puzzle` bumps a
/// per-IP and a per-site counter; a single `RwLock<HashMap>` per map would
/// serialise every request on one writer. Striping by key hash spreads that
/// contention across independent locks. Power of two so the modulo is cheap.
const RATE_SHARDS: usize = 16;

/// Rate-window map split across `RATE_SHARDS` independently-locked stripes.
/// Each key lands in one stripe by hash, so concurrent requests for different
/// keys rarely contend. The critical section stays tiny (an entry lookup + a
/// counter bump), matching the previous single-lock behaviour per key.
struct ShardedRates<K> {
    shards: [RwLock<HashMap<K, RateWindow>>; RATE_SHARDS],
    /// Length of one counting window, in seconds. Per-instance because the
    /// maps count different things: issuance rate over 60s, repeated
    /// behaviour blobs over `BEHAVIOR_DUPLICATE_WINDOW_SECS`.
    window_secs: i64,
}

impl<K: Eq + Hash + Clone> ShardedRates<K> {
    fn new(window_secs: i64) -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
            window_secs,
        }
    }

    fn shard(&self, key: &K) -> &RwLock<HashMap<K, RateWindow>> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % RATE_SHARDS]
    }

    /// Increment the key's counter within the current window, resetting it
    /// when the window has rolled over. Returns the new count.
    fn increment(&self, key: K) -> Result<u32, CaptchaError> {
        let mut map = self.shard(&key).write().map_err(lock_err)?;
        let now = Utc::now().timestamp();
        let entry = map.entry(key).or_insert(RateWindow {
            count: 0,
            window_start: now,
        });
        if now - entry.window_start >= self.window_secs {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        Ok(entry.count)
    }

    /// Drop windows older than twice this map's window across every stripe.
    fn retain_fresh(&self, now_ts: i64) -> Result<(), CaptchaError> {
        for shard in &self.shards {
            let mut map = shard.write().map_err(lock_err)?;
            map.retain(|_, w| now_ts - w.window_start < self.window_secs * 2);
        }
        Ok(())
    }
}

pub struct InMemoryStore {
    challenges: RwLock<HashMap<Uuid, Challenge>>,
    sites_by_key: RwLock<HashMap<Uuid, Site>>,
    sites_by_secret: RwLock<HashMap<String, Uuid>>,
    ip_rates: ShardedRates<IpAddr>,
    /// The same per-IP key over the 15 min window. Entries live for two
    /// windows before the sweeper reclaims them, so this map holds every
    /// distinct source seen in the last half hour — a few dozen bytes each.
    ip_rates_sustained: ShardedRates<IpAddr>,
    site_rates: ShardedRates<Uuid>,
    /// Occurrences of one verify-time behaviour blob per site, keyed on
    /// `(site_key, behavior_fingerprint)`. Same shape as the counters above,
    /// on a longer window. Entries are only created after a *valid* proof of
    /// work, so growing this map costs an attacker one solve per entry, and
    /// `cleanup_expired` reclaims it on the same sweep as the rate windows.
    behavior_blobs: ShardedRates<(Uuid, u64)>,
    /// Optional write-through persistence for the sites table. Challenges
    /// and rate windows stay in-memory — they're cheap to lose on restart.
    /// Sites can't be: integrators store the secret_key client-side, so a
    /// restart that wipes them means every embedded captcha breaks.
    site_persistence: Option<Mutex<Connection>>,
}

const RATE_WINDOW_SECS: i64 = 60;

const SITES_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS sites (
    site_key        TEXT PRIMARY KEY,
    secret_key      TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    allowed_origins TEXT NOT NULL DEFAULT '',
    policy          TEXT
);
";

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            sites_by_key: RwLock::new(HashMap::new()),
            sites_by_secret: RwLock::new(HashMap::new()),
            ip_rates: ShardedRates::new(RATE_WINDOW_SECS),
            ip_rates_sustained: ShardedRates::new(RATE_SUSTAINED_WINDOW_SECS),
            site_rates: ShardedRates::new(RATE_WINDOW_SECS),
            behavior_blobs: ShardedRates::new(BEHAVIOR_DUPLICATE_WINDOW_SECS),
            site_persistence: None,
        }
    }

    /// Open or create a SQLite database at `path` for site persistence,
    /// load any existing sites into the in-memory map, and keep the
    /// connection for write-through inserts.
    pub fn with_site_persistence(path: impl AsRef<Path>) -> Result<Self, CaptchaError> {
        let conn = Connection::open(path.as_ref())
            .map_err(|e| CaptchaError::Storage(format!("open site db: {e}")))?;
        conn.execute_batch(SITES_SCHEMA)
            .map_err(|e| CaptchaError::Storage(format!("init site schema: {e}")))?;
        migrate_add_site_column(&conn, "allowed_origins", "TEXT NOT NULL DEFAULT ''")?;
        // Nullable: NULL means "no overrides", which is what every site
        // predating per-site policy has and what an emptied policy writes back.
        migrate_add_site_column(&conn, "policy", "TEXT")?;

        let sites = load_all_sites(&conn)?;

        let store = Self::new();
        {
            let mut by_key = store.sites_by_key.write().map_err(lock_err)?;
            let mut by_secret = store.sites_by_secret.write().map_err(lock_err)?;
            for site in sites {
                by_secret.insert(site.secret_key.clone(), site.site_key);
                by_key.insert(site.site_key, site);
            }
        }
        Ok(Self {
            site_persistence: Some(Mutex::new(conn)),
            ..store
        })
    }

    /// Number of challenges currently held in memory. Used by the puzzle
    /// handler as a global issuance backstop (`MAX_ACTIVE_CHALLENGES`) so a
    /// distributed flood can't grow the map unbounded between cleanup sweeps.
    pub fn challenge_count(&self) -> usize {
        self.challenges.read().map(|m| m.len()).unwrap_or_default()
    }

    /// Number of sites currently loaded. Useful at boot to log how many
    /// were restored from disk.
    pub fn site_count(&self) -> usize {
        self.sites_by_key
            .read()
            .map(|m| m.len())
            .unwrap_or_default()
    }

    /// Snapshot of every registered site, sorted by `created_at` ascending.
    /// Used by the admin dashboard. Cloning is cheap (a few strings per site)
    /// and keeps the read lock held for as little time as possible.
    pub fn list_sites(&self) -> Result<Vec<Site>, CaptchaError> {
        let map = self.sites_by_key.read().map_err(lock_err)?;
        let mut out: Vec<Site> = map.values().cloned().collect();
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }
}

/// Add a column to the `sites` table when a database created by an older
/// build doesn't have it yet. SQLite has no `ADD COLUMN IF NOT EXISTS`, so
/// probe `pragma_table_info` first and only ALTER when the column is absent —
/// a fresh database created from the current `SITES_SCHEMA` already has every
/// column, so this is a no-op there. Mirrors the in-place migration pattern in
/// `dashboard/log.rs`.
fn migrate_add_site_column(
    conn: &Connection,
    column: &str,
    definition: &str,
) -> Result<(), CaptchaError> {
    let has_column: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('sites') WHERE name = ?1")
        .and_then(|mut stmt| stmt.exists([column]))
        .map_err(|e| CaptchaError::Storage(format!("probe sites schema: {e}")))?;
    if !has_column {
        // `column`/`definition` are compile-time literals from the call sites
        // below, never user input — SQLite can't bind an identifier anyway.
        conn.execute(
            &format!("ALTER TABLE sites ADD COLUMN {column} {definition}"),
            [],
        )
        .map_err(|e| CaptchaError::Storage(format!("add {column} column: {e}")))?;
    }
    Ok(())
}

fn load_all_sites(conn: &Connection) -> Result<Vec<Site>, CaptchaError> {
    let mut stmt = conn
        .prepare(
            "SELECT site_key, secret_key, name, created_at, allowed_origins, policy FROM sites",
        )
        .map_err(|e| CaptchaError::Storage(format!("prepare load sites: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            let key_str: String = row.get(0)?;
            let secret: String = row.get(1)?;
            let name: String = row.get(2)?;
            let created_str: String = row.get(3)?;
            let origins_str: String = row.get(4)?;
            let policy_json: Option<String> = row.get(5)?;
            Ok((key_str, secret, name, created_str, origins_str, policy_json))
        })
        .map_err(|e| CaptchaError::Storage(format!("query sites: {e}")))?;

    let mut out = Vec::new();
    for row in rows {
        let (key_str, secret_key, name, created_str, origins_str, policy_json) =
            row.map_err(|e| CaptchaError::Storage(format!("read site row: {e}")))?;
        let site_key = Uuid::parse_str(&key_str)
            .map_err(|e| CaptchaError::Storage(format!("bad site_key in db: {e}")))?;
        let created_at = DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| CaptchaError::Storage(format!("bad created_at in db: {e}")))?
            .with_timezone(&Utc);
        // A policy row we can't parse must not be silently downgraded to
        // "no overrides": that would quietly restore the global (looser)
        // thresholds for a site whose operator deliberately tightened them.
        // Refuse to boot instead, the same stance `AppConfig::validated` takes.
        let policy = match policy_json {
            Some(json) => serde_json::from_str(&json).map_err(|e| {
                CaptchaError::Storage(format!("bad policy for site {key_str} in db: {e}"))
            })?,
            None => SitePolicy::default(),
        };
        out.push(Site {
            site_key,
            secret_key,
            name,
            created_at,
            // Space-joined; entries never contain whitespace (normalized at
            // provisioning time), so splitting on whitespace is lossless.
            allowed_origins: origins_str.split_whitespace().map(String::from).collect(),
            policy,
        });
    }
    Ok(out)
}

/// Serialize a policy for the `policy` column: `None` (SQL NULL) when nothing
/// is overridden, so an untouched site stays visibly untouched on disk and the
/// column reads the same as it does for sites created before policies existed.
fn policy_column(policy: &SitePolicy) -> Result<Option<String>, CaptchaError> {
    if policy.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(policy)
        .map(Some)
        .map_err(|e| CaptchaError::Storage(format!("serialize site policy: {e}")))
}

fn persist_site(conn: &Connection, site: &Site) -> Result<(), CaptchaError> {
    conn.execute(
        "INSERT INTO sites (site_key, secret_key, name, created_at, allowed_origins, policy) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            site.site_key.to_string(),
            site.secret_key,
            site.name,
            site.created_at.to_rfc3339(),
            site.allowed_origins.join(" "),
            policy_column(&site.policy)?,
        ],
    )
    .map_err(|e| CaptchaError::Storage(format!("insert site: {e}")))?;
    Ok(())
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for InMemoryStore {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<(), CaptchaError> {
        let mut map = self.challenges.write().map_err(lock_err)?;
        map.insert(challenge.id, challenge.clone());
        Ok(())
    }

    async fn get_challenge(&self, id: &Uuid) -> Result<Option<Challenge>, CaptchaError> {
        let map = self.challenges.read().map_err(lock_err)?;
        Ok(map.get(id).cloned())
    }

    async fn delete_challenge(&self, id: &Uuid) -> Result<(), CaptchaError> {
        let mut map = self.challenges.write().map_err(lock_err)?;
        map.remove(id);
        Ok(())
    }

    async fn consume_challenge(&self, challenge_id: &Uuid) -> Result<(), CaptchaError> {
        // Single-use is enforced by removal: exactly one caller removes the
        // challenge and passes; concurrent/replayed submits get `None` →
        // `ChallengeNotFound` (404).
        let mut map = self.challenges.write().map_err(lock_err)?;
        match map.remove(challenge_id) {
            Some(_) => Ok(()),
            None => Err(CaptchaError::ChallengeNotFound),
        }
    }

    async fn register_failed_attempt(
        &self,
        challenge_id: &Uuid,
        max_attempts: u32,
    ) -> Result<bool, CaptchaError> {
        if max_attempts == 0 {
            return Ok(false);
        }
        let mut map = self.challenges.write().map_err(lock_err)?;
        if let Some(challenge) = map.get_mut(challenge_id) {
            challenge.attempts += 1;
            if challenge.attempts >= max_attempts {
                map.remove(challenge_id);
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn store_site(&self, site: &Site) -> Result<(), CaptchaError> {
        // Hold the in-memory write locks across the SQLite write so persistence
        // and memory can't diverge under concurrent mutations of the same site
        // (two admin writes committing to disk in one order but to memory in
        // the other). Lock order is by_key → by_secret everywhere. Persist
        // inside the critical section, first, so a failed disk write (e.g.
        // UNIQUE collision on a regenerated secret) leaves memory untouched.
        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let mut by_secret = self.sites_by_secret.write().map_err(lock_err)?;
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            persist_site(&conn, site)?;
        }
        by_key.insert(site.site_key, site.clone());
        by_secret.insert(site.secret_key.clone(), site.site_key);
        Ok(())
    }

    async fn get_site_by_key(&self, site_key: &Uuid) -> Result<Option<Site>, CaptchaError> {
        let map = self.sites_by_key.read().map_err(lock_err)?;
        Ok(map.get(site_key).cloned())
    }

    async fn get_site_by_secret(&self, secret: &str) -> Result<Option<Site>, CaptchaError> {
        let site_key = {
            let by_secret = self.sites_by_secret.read().map_err(lock_err)?;
            by_secret.get(secret).copied()
        };

        match site_key {
            Some(key) => self.get_site_by_key(&key).await,
            None => Ok(None),
        }
    }

    async fn rotate_site_secret(
        &self,
        site_key: &Uuid,
        new_secret: String,
    ) -> Result<(), CaptchaError> {
        // One critical section (see store_site): resolve NotFound from memory,
        // persist inside the lock, then swap in-memory. On UNIQUE collision
        // (vanishingly rare for 32-byte random secrets) the persist fails and
        // memory is left unchanged.
        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let mut by_secret = self.sites_by_secret.write().map_err(lock_err)?;
        let Some(site) = by_key.get_mut(site_key) else {
            return Err(CaptchaError::NotFound);
        };
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            let updated = conn
                .execute(
                    "UPDATE sites SET secret_key = ?1 WHERE site_key = ?2",
                    params![new_secret, site_key.to_string()],
                )
                .map_err(|e| CaptchaError::Storage(format!("rotate site secret: {e}")))?;
            if updated == 0 {
                // Memory has the site but the DB row is missing — a pre-existing
                // divergence we should never hit. Surface it; memory is untouched.
                return Err(CaptchaError::Storage(
                    "site in memory but missing from db".into(),
                ));
            }
        }
        let old_secret = std::mem::replace(&mut site.secret_key, new_secret.clone());
        by_secret.remove(&old_secret);
        by_secret.insert(new_secret, *site_key);
        Ok(())
    }

    async fn update_site_origins(
        &self,
        site_key: &Uuid,
        origins: Vec<String>,
    ) -> Result<(), CaptchaError> {
        // One critical section (see store_site): resolve NotFound from memory,
        // persist inside the lock, then swap in-memory.
        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let Some(site) = by_key.get_mut(site_key) else {
            return Err(CaptchaError::NotFound);
        };
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            let updated = conn
                .execute(
                    "UPDATE sites SET allowed_origins = ?1 WHERE site_key = ?2",
                    params![origins.join(" "), site_key.to_string()],
                )
                .map_err(|e| CaptchaError::Storage(format!("update site origins: {e}")))?;
            if updated == 0 {
                return Err(CaptchaError::Storage(
                    "site in memory but missing from db".into(),
                ));
            }
        }
        site.allowed_origins = origins;
        Ok(())
    }

    async fn update_site_name(&self, site_key: &Uuid, name: String) -> Result<(), CaptchaError> {
        // One critical section (see store_site): resolve NotFound from memory,
        // persist inside the lock, then swap in-memory. The name is not indexed
        // — nothing looks a site up by it — so only `sites_by_key` is touched.
        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let Some(site) = by_key.get_mut(site_key) else {
            return Err(CaptchaError::NotFound);
        };
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            let updated = conn
                .execute(
                    "UPDATE sites SET name = ?1 WHERE site_key = ?2",
                    params![name, site_key.to_string()],
                )
                .map_err(|e| CaptchaError::Storage(format!("update site name: {e}")))?;
            if updated == 0 {
                return Err(CaptchaError::Storage(
                    "site in memory but missing from db".into(),
                ));
            }
        }
        site.name = name;
        Ok(())
    }

    async fn update_site_policy(
        &self,
        site_key: &Uuid,
        policy: SitePolicy,
    ) -> Result<(), CaptchaError> {
        // One critical section (see store_site): resolve NotFound from memory,
        // persist inside the lock, then swap in-memory.
        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let Some(site) = by_key.get_mut(site_key) else {
            return Err(CaptchaError::NotFound);
        };
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            let updated = conn
                .execute(
                    "UPDATE sites SET policy = ?1 WHERE site_key = ?2",
                    params![policy_column(&policy)?, site_key.to_string()],
                )
                .map_err(|e| CaptchaError::Storage(format!("update site policy: {e}")))?;
            if updated == 0 {
                return Err(CaptchaError::Storage(
                    "site in memory but missing from db".into(),
                ));
            }
        }
        site.policy = policy;
        Ok(())
    }

    async fn delete_site(&self, site_key: &Uuid) -> Result<(), CaptchaError> {
        // One critical section (see store_site): resolve NotFound from memory,
        // delete from disk inside the lock, then remove from memory.
        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let mut by_secret = self.sites_by_secret.write().map_err(lock_err)?;
        if !by_key.contains_key(site_key) {
            return Err(CaptchaError::NotFound);
        }
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            let deleted = conn
                .execute(
                    "DELETE FROM sites WHERE site_key = ?1",
                    params![site_key.to_string()],
                )
                .map_err(|e| CaptchaError::Storage(format!("delete site: {e}")))?;
            if deleted == 0 {
                return Err(CaptchaError::Storage(
                    "site in memory but missing from db".into(),
                ));
            }
        }
        let site = by_key
            .remove(site_key)
            .expect("presence checked under the same lock");
        by_secret.remove(&site.secret_key);
        Ok(())
    }

    async fn increment_ip_count(&self, ip: &IpAddr) -> Result<u32, CaptchaError> {
        self.ip_rates.increment(*ip)
    }

    async fn increment_ip_count_sustained(&self, ip: &IpAddr) -> Result<u32, CaptchaError> {
        self.ip_rates_sustained.increment(*ip)
    }

    async fn increment_site_count(&self, site_key: &Uuid) -> Result<u32, CaptchaError> {
        self.site_rates.increment(*site_key)
    }

    async fn increment_behavior_blob_count(
        &self,
        site_key: &Uuid,
        fingerprint: u64,
    ) -> Result<u32, CaptchaError> {
        self.behavior_blobs.increment((*site_key, fingerprint))
    }

    async fn cleanup_expired(&self) -> Result<(), CaptchaError> {
        let now = Utc::now();

        // Clean expired challenges
        {
            let mut map = self.challenges.write().map_err(lock_err)?;
            map.retain(|_, c| c.expires_at > now);
        }

        // Clean stale rate windows across every stripe
        let ts = now.timestamp();
        self.ip_rates.retain_fresh(ts)?;
        self.ip_rates_sustained.retain_fresh(ts)?;
        self.site_rates.retain_fresh(ts)?;
        self.behavior_blobs.retain_fresh(ts)?;

        Ok(())
    }
}

fn lock_err<T>(_: T) -> CaptchaError {
    CaptchaError::Storage("Lock poisoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::puzzle::types::Algorithm;
    use chrono::Duration;

    fn make_challenge(site_key: Uuid, ttl_secs: i64) -> Challenge {
        let now = Utc::now();
        Challenge {
            id: Uuid::new_v4(),
            site_key,
            algorithm: Algorithm::Sha256,
            prefix: "deadbeef".into(),
            difficulty: 8,
            created_at: now,
            dwell_since: now,
            expires_at: now + Duration::seconds(ttl_secs),
            attempts: 0,
            issued_to: None,
        }
    }

    fn make_site() -> Site {
        // Random secret so two sites in the same test don't collide on
        // the UNIQUE constraint when persistence is enabled.
        let secret = format!("secret-{}", Uuid::new_v4().simple());
        Site {
            site_key: Uuid::new_v4(),
            secret_key: secret,
            name: "Test Site".into(),
            created_at: Utc::now(),
            allowed_origins: Vec::new(),
            policy: SitePolicy::default(),
        }
    }

    #[tokio::test]
    async fn test_challenge_crud() {
        let store = InMemoryStore::new();
        let challenge = make_challenge(Uuid::new_v4(), 300);

        store.store_challenge(&challenge).await.unwrap();
        let fetched = store.get_challenge(&challenge.id).await.unwrap().unwrap();
        assert_eq!(fetched.id, challenge.id);

        store.delete_challenge(&challenge.id).await.unwrap();
        assert!(store.get_challenge(&challenge.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_consume_challenge_removes_once() {
        let store = InMemoryStore::new();
        let challenge = make_challenge(Uuid::new_v4(), 300);

        store.store_challenge(&challenge).await.unwrap();
        store.consume_challenge(&challenge.id).await.unwrap();

        assert!(store.get_challenge(&challenge.id).await.unwrap().is_none());
        let second = store.consume_challenge(&challenge.id).await;
        assert!(matches!(second, Err(CaptchaError::ChallengeNotFound)));
    }

    #[tokio::test]
    async fn test_register_failed_attempt_evicts_at_cap() {
        let store = InMemoryStore::new();
        let challenge = make_challenge(Uuid::new_v4(), 300);
        store.store_challenge(&challenge).await.unwrap();

        // Below the cap the challenge stays live.
        assert!(
            !store
                .register_failed_attempt(&challenge.id, 3)
                .await
                .unwrap()
        );
        assert!(
            !store
                .register_failed_attempt(&challenge.id, 3)
                .await
                .unwrap()
        );
        assert!(store.get_challenge(&challenge.id).await.unwrap().is_some());

        // The third failed attempt reaches the cap and evicts it.
        assert!(
            store
                .register_failed_attempt(&challenge.id, 3)
                .await
                .unwrap()
        );
        assert!(store.get_challenge(&challenge.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_register_failed_attempt_disabled_when_zero() {
        let store = InMemoryStore::new();
        let challenge = make_challenge(Uuid::new_v4(), 300);
        store.store_challenge(&challenge).await.unwrap();

        // max_attempts = 0 disables the cap: never evicts, never increments.
        for _ in 0..1000 {
            assert!(
                !store
                    .register_failed_attempt(&challenge.id, 0)
                    .await
                    .unwrap()
            );
        }
        assert!(store.get_challenge(&challenge.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_register_failed_attempt_missing_challenge() {
        let store = InMemoryStore::new();
        // A never-existed / already-consumed challenge is a no-op, not an error.
        assert!(
            !store
                .register_failed_attempt(&Uuid::new_v4(), 3)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_challenge_count() {
        let store = InMemoryStore::new();
        assert_eq!(store.challenge_count(), 0);
        let a = make_challenge(Uuid::new_v4(), 300);
        let b = make_challenge(Uuid::new_v4(), 300);
        store.store_challenge(&a).await.unwrap();
        store.store_challenge(&b).await.unwrap();
        assert_eq!(store.challenge_count(), 2);
        store.consume_challenge(&a.id).await.unwrap();
        assert_eq!(store.challenge_count(), 1);
    }

    #[tokio::test]
    async fn test_site_crud() {
        let store = InMemoryStore::new();
        let site = make_site();

        store.store_site(&site).await.unwrap();

        let by_key = store
            .get_site_by_key(&site.site_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_key.name, site.name);

        let by_secret = store
            .get_site_by_secret(&site.secret_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_secret.site_key, site.site_key);
    }

    #[tokio::test]
    async fn test_site_not_found() {
        let store = InMemoryStore::new();
        assert!(
            store
                .get_site_by_key(&Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_site_by_secret("nonexistent")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_sustained_ip_counter_is_independent_of_the_minute_counter() {
        let store = InMemoryStore::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        for _ in 0..3 {
            store.increment_ip_count(&ip).await.unwrap();
        }
        // The sustained map has seen nothing yet; it starts its own count.
        assert_eq!(store.increment_ip_count_sustained(&ip).await.unwrap(), 1);
        assert_eq!(store.increment_ip_count_sustained(&ip).await.unwrap(), 2);
        // And the minute counter was not touched by those increments.
        assert_eq!(store.increment_ip_count(&ip).await.unwrap(), 4);
    }

    #[tokio::test]
    async fn test_ip_rate_counter() {
        let store = InMemoryStore::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        assert_eq!(store.increment_ip_count(&ip).await.unwrap(), 1);
        assert_eq!(store.increment_ip_count(&ip).await.unwrap(), 2);
        assert_eq!(store.increment_ip_count(&ip).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_site_rate_counter() {
        let store = InMemoryStore::new();
        let site_key = Uuid::new_v4();

        assert_eq!(store.increment_site_count(&site_key).await.unwrap(), 1);
        assert_eq!(store.increment_site_count(&site_key).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_behavior_blob_counter_is_per_site_and_per_fingerprint() {
        let store = InMemoryStore::new();
        let site = Uuid::new_v4();
        let other_site = Uuid::new_v4();

        assert_eq!(
            store
                .increment_behavior_blob_count(&site, 42)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .increment_behavior_blob_count(&site, 42)
                .await
                .unwrap(),
            2
        );
        // A different blob on the same site is a separate count...
        assert_eq!(
            store
                .increment_behavior_blob_count(&site, 43)
                .await
                .unwrap(),
            1
        );
        // ...and so is the same blob on a different site: one tenant's traffic
        // must never push another tenant's visitors over the threshold.
        assert_eq!(
            store
                .increment_behavior_blob_count(&other_site, 42)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn test_cleanup_reclaims_stale_behavior_blob_windows() {
        let store = InMemoryStore::new();
        let site = Uuid::new_v4();
        store.increment_behavior_blob_count(&site, 7).await.unwrap();

        // Backdate past twice the dedup window, which is what `retain_fresh`
        // reclaims on. Without the sweep this map would grow for the process
        // lifetime.
        {
            let shard = store.behavior_blobs.shard(&(site, 7));
            let mut map = shard.write().unwrap();
            map.get_mut(&(site, 7)).unwrap().window_start =
                Utc::now().timestamp() - BEHAVIOR_DUPLICATE_WINDOW_SECS * 3;
        }

        store.cleanup_expired().await.unwrap();

        // Assert on the map, not on a fresh count: `increment` rolls a stale
        // window over by itself, so a count of 1 would look identical whether
        // or not the sweeper ever ran.
        assert!(
            !store
                .behavior_blobs
                .shard(&(site, 7))
                .read()
                .unwrap()
                .contains_key(&(site, 7)),
            "the sweeper must reclaim the dedup map, not just the rate windows"
        );
    }

    #[tokio::test]
    async fn test_rotate_site_secret_in_memory() {
        let store = InMemoryStore::new();
        let site = make_site();
        store.store_site(&site).await.unwrap();

        let new_secret = "rotated-secret".to_string();
        store
            .rotate_site_secret(&site.site_key, new_secret.clone())
            .await
            .unwrap();

        // Old secret no longer resolves.
        assert!(
            store
                .get_site_by_secret(&site.secret_key)
                .await
                .unwrap()
                .is_none()
        );
        // New secret resolves.
        let by_new = store
            .get_site_by_secret(&new_secret)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_new.site_key, site.site_key);
        assert_eq!(by_new.secret_key, new_secret);
    }

    #[tokio::test]
    async fn test_rotate_site_secret_not_found() {
        let store = InMemoryStore::new();
        let result = store.rotate_site_secret(&Uuid::new_v4(), "x".into()).await;
        assert!(matches!(result, Err(CaptchaError::NotFound)));
    }

    #[tokio::test]
    async fn test_delete_site_in_memory() {
        let store = InMemoryStore::new();
        let site = make_site();
        store.store_site(&site).await.unwrap();

        store.delete_site(&site.site_key).await.unwrap();

        assert!(
            store
                .get_site_by_key(&site.site_key)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_site_by_secret(&site.secret_key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_site_not_found() {
        let store = InMemoryStore::new();
        let result = store.delete_site(&Uuid::new_v4()).await;
        assert!(matches!(result, Err(CaptchaError::NotFound)));
    }

    #[tokio::test]
    async fn test_rotate_and_delete_persist_across_reopen() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        let site_a = make_site();
        let site_b = make_site();
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            store.store_site(&site_a).await.unwrap();
            store.store_site(&site_b).await.unwrap();
            store
                .rotate_site_secret(&site_a.site_key, "rotated".into())
                .await
                .unwrap();
            store.delete_site(&site_b.site_key).await.unwrap();
        }

        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        assert_eq!(store.site_count(), 1);
        let reloaded = store
            .get_site_by_secret("rotated")
            .await
            .unwrap()
            .expect("rotated secret resolves after reopen");
        assert_eq!(reloaded.site_key, site_a.site_key);
        assert!(
            store
                .get_site_by_key(&site_b.site_key)
                .await
                .unwrap()
                .is_none(),
            "deleted site should not reload"
        );
    }

    #[tokio::test]
    async fn test_site_persistence_round_trip() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        // First store: register a site, drop the store.
        let site = make_site();
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            store.store_site(&site).await.unwrap();
        }

        // Second store: should reload the site from disk.
        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        assert_eq!(store.site_count(), 1);
        let by_key = store
            .get_site_by_key(&site.site_key)
            .await
            .unwrap()
            .expect("site reloaded by key");
        assert_eq!(by_key.name, site.name);
        let by_secret = store
            .get_site_by_secret(&site.secret_key)
            .await
            .unwrap()
            .expect("site reloaded by secret");
        assert_eq!(by_secret.site_key, site.site_key);
    }

    #[tokio::test]
    async fn test_allowed_origins_round_trip() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        let mut site = make_site();
        site.allowed_origins = vec![
            "https://a.example".to_string(),
            "https://b.example:8443".to_string(),
        ];
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            store.store_site(&site).await.unwrap();
        }

        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        let reloaded = store
            .get_site_by_key(&site.site_key)
            .await
            .unwrap()
            .expect("site reloaded");
        assert_eq!(reloaded.allowed_origins, site.allowed_origins);
    }

    #[tokio::test]
    async fn test_update_site_origins_persists_across_reopen() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        let site = make_site();
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            store.store_site(&site).await.unwrap();
            // Site starts with no restriction; set one.
            store
                .update_site_origins(&site.site_key, vec!["https://only.example".to_string()])
                .await
                .unwrap();
        }

        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        let reloaded = store
            .get_site_by_key(&site.site_key)
            .await
            .unwrap()
            .expect("site reloaded");
        assert_eq!(reloaded.allowed_origins, vec!["https://only.example"]);
    }

    #[tokio::test]
    async fn test_update_site_origins_not_found() {
        let store = InMemoryStore::new();
        let result = store
            .update_site_origins(&Uuid::new_v4(), vec!["https://x.example".to_string()])
            .await;
        assert!(matches!(result, Err(CaptchaError::NotFound)));
    }

    #[tokio::test]
    async fn test_update_site_name_persists_across_reopen() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        let site = make_site();
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            store.store_site(&site).await.unwrap();
            store
                .update_site_name(&site.site_key, "renamed".to_string())
                .await
                .unwrap();
        }

        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        let reloaded = store
            .get_site_by_key(&site.site_key)
            .await
            .unwrap()
            .expect("site reloaded");
        assert_eq!(reloaded.name, "renamed");
    }

    #[tokio::test]
    async fn test_update_site_name_leaves_the_secret_lookup_intact() {
        // The name is not an index, but it shares the write path with the two
        // maps that are. A rename that disturbed `sites_by_secret` would break
        // every `/v1/verify` for that site with nothing in the response saying
        // why, so it gets a test rather than a comment.
        let store = InMemoryStore::new();
        let site = make_site();
        store.store_site(&site).await.unwrap();

        store
            .update_site_name(&site.site_key, "  renamed  ".to_string())
            .await
            .unwrap();

        let found = store
            .get_site_by_secret(&site.secret_key)
            .await
            .unwrap()
            .expect("the secret still resolves");
        assert_eq!(found.site_key, site.site_key);
        // Trimming is the handler's job (`normalize_site_name`), not the
        // store's — this pins that the store writes what it is handed.
        assert_eq!(found.name, "  renamed  ");
    }

    #[tokio::test]
    async fn test_update_site_name_not_found() {
        let store = InMemoryStore::new();
        let result = store
            .update_site_name(&Uuid::new_v4(), "whatever".to_string())
            .await;
        assert!(matches!(result, Err(CaptchaError::NotFound)));
    }

    #[tokio::test]
    async fn test_old_schema_db_migrates_allowed_origins_column() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        // Hand-create the pre-feature table (no allowed_origins column) and
        // insert a row, exactly as an older binary would have left it.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r"CREATE TABLE sites (
                    site_key   TEXT PRIMARY KEY,
                    secret_key TEXT NOT NULL UNIQUE,
                    name       TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sites (site_key, secret_key, name, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    Uuid::new_v4().to_string(),
                    "legacy-secret",
                    "Legacy Site",
                    Utc::now().to_rfc3339(),
                ],
            )
            .unwrap();
        }

        // Opening with the current code must migrate the column in place and
        // load the legacy row with an empty (unrestricted) origin list.
        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        assert_eq!(store.site_count(), 1);
        let reloaded = store
            .get_site_by_secret("legacy-secret")
            .await
            .unwrap()
            .expect("legacy site reloaded");
        assert!(reloaded.allowed_origins.is_empty());

        // And the migrated column is usable going forward.
        store
            .update_site_origins(&reloaded.site_key, vec!["https://new.example".to_string()])
            .await
            .unwrap();

        // The same legacy row must also gain the `policy` column, and load
        // with no overrides — a site provisioned before policies existed keeps
        // tracking the global config exactly as it did.
        assert!(reloaded.policy.is_empty());
        store
            .update_site_policy(
                &reloaded.site_key,
                SitePolicy {
                    tier_block_min: Some(70),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_policy_round_trips_through_persistence() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        let policy = SitePolicy {
            tier_checkbox_min: Some(10),
            tier_hard_pow_min: Some(25),
            tier_block_min: Some(60),
            ..Default::default()
        };

        let site_key = {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            let mut site = make_site();
            site.policy = policy;
            store.store_site(&site).await.unwrap();
            site.site_key
        };

        // Reopen: the policy must come back byte-identical, or a restart
        // silently reverts a tenant to the looser global thresholds.
        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        let reloaded = store.get_site_by_key(&site_key).await.unwrap().unwrap();
        assert_eq!(reloaded.policy, policy);
    }

    #[tokio::test]
    async fn test_update_site_policy_persists_and_clears() {
        let dir = tempdir();
        let path = dir.join("sites.db");

        let site = make_site();
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            store.store_site(&site).await.unwrap();
            store
                .update_site_policy(
                    &site.site_key,
                    SitePolicy {
                        verify_block_min: Some(30),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            let reloaded = store
                .get_site_by_key(&site.site_key)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reloaded.policy.verify_block_min, Some(30));

            // Clearing writes SQL NULL back, not "{}" — an emptied policy must
            // be indistinguishable from a site that never had one.
            store
                .update_site_policy(&site.site_key, SitePolicy::default())
                .await
                .unwrap();
        }
        let store = InMemoryStore::with_site_persistence(&path).unwrap();
        let reloaded = store
            .get_site_by_key(&site.site_key)
            .await
            .unwrap()
            .unwrap();
        assert!(reloaded.policy.is_empty());

        let conn = Connection::open(&path).unwrap();
        let stored: Option<String> = conn
            .query_row(
                "SELECT policy FROM sites WHERE site_key = ?1",
                params![site.site_key.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, None);
    }

    #[tokio::test]
    async fn test_update_site_policy_unknown_site_is_not_found() {
        let store = InMemoryStore::new();
        let result = store
            .update_site_policy(&Uuid::new_v4(), SitePolicy::default())
            .await;
        assert!(matches!(result, Err(CaptchaError::NotFound)));
    }

    #[tokio::test]
    async fn test_unparseable_policy_column_refuses_to_load() {
        // A corrupt policy must not degrade to "no overrides" — that would
        // silently restore the looser global thresholds for a site whose
        // operator deliberately tightened them.
        let dir = tempdir();
        let path = dir.join("sites.db");
        let site = make_site();
        {
            let store = InMemoryStore::with_site_persistence(&path).unwrap();
            store.store_site(&site).await.unwrap();
        }
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE sites SET policy = ?1 WHERE site_key = ?2",
            params!["not json", site.site_key.to_string()],
        )
        .unwrap();
        drop(conn);

        assert!(InMemoryStore::with_site_persistence(&path).is_err());
    }

    fn tempdir() -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "bollwark-test-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let store = InMemoryStore::new();
        let expired = make_challenge(Uuid::new_v4(), -10); // already expired
        let valid = make_challenge(Uuid::new_v4(), 300);

        store.store_challenge(&expired).await.unwrap();
        store.store_challenge(&valid).await.unwrap();

        store.cleanup_expired().await.unwrap();

        assert!(store.get_challenge(&expired.id).await.unwrap().is_none());
        assert!(store.get_challenge(&valid.id).await.unwrap().is_some());
    }
}
