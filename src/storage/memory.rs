use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, RwLock};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::error::CaptchaError;
use crate::puzzle::types::Challenge;
use crate::site::types::Site;

use super::Store;

struct RateWindow {
    count: u32,
    window_start: i64,
}

pub struct InMemoryStore {
    challenges: RwLock<HashMap<Uuid, Challenge>>,
    sites_by_key: RwLock<HashMap<Uuid, Site>>,
    sites_by_secret: RwLock<HashMap<String, Uuid>>,
    ip_rates: RwLock<HashMap<IpAddr, RateWindow>>,
    site_rates: RwLock<HashMap<Uuid, RateWindow>>,
    /// Optional write-through persistence for the sites table. Challenges
    /// and rate windows stay in-memory — they're cheap to lose on restart.
    /// Sites can't be: integrators store the secret_key client-side, so a
    /// restart that wipes them means every embedded captcha breaks.
    site_persistence: Option<Mutex<Connection>>,
}

const RATE_WINDOW_SECS: i64 = 60;

const SITES_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS sites (
    site_key   TEXT PRIMARY KEY,
    secret_key TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
";

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            sites_by_key: RwLock::new(HashMap::new()),
            sites_by_secret: RwLock::new(HashMap::new()),
            ip_rates: RwLock::new(HashMap::new()),
            site_rates: RwLock::new(HashMap::new()),
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
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(out)
    }
}

fn load_all_sites(conn: &Connection) -> Result<Vec<Site>, CaptchaError> {
    let mut stmt = conn
        .prepare("SELECT site_key, secret_key, name, created_at FROM sites")
        .map_err(|e| CaptchaError::Storage(format!("prepare load sites: {e}")))?;
    let rows = stmt
        .query_map([], |row| {
            let key_str: String = row.get(0)?;
            let secret: String = row.get(1)?;
            let name: String = row.get(2)?;
            let created_str: String = row.get(3)?;
            Ok((key_str, secret, name, created_str))
        })
        .map_err(|e| CaptchaError::Storage(format!("query sites: {e}")))?;

    let mut out = Vec::new();
    for row in rows {
        let (key_str, secret_key, name, created_str) =
            row.map_err(|e| CaptchaError::Storage(format!("read site row: {e}")))?;
        let site_key = Uuid::parse_str(&key_str)
            .map_err(|e| CaptchaError::Storage(format!("bad site_key in db: {e}")))?;
        let created_at = DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| CaptchaError::Storage(format!("bad created_at in db: {e}")))?
            .with_timezone(&Utc);
        out.push(Site {
            site_key,
            secret_key,
            name,
            created_at,
        });
    }
    Ok(out)
}

fn persist_site(conn: &Connection, site: &Site) -> Result<(), CaptchaError> {
    conn.execute(
        "INSERT INTO sites (site_key, secret_key, name, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            site.site_key.to_string(),
            site.secret_key,
            site.name,
            site.created_at.to_rfc3339(),
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

    async fn mark_solution_used(&self, challenge_id: &Uuid) -> Result<(), CaptchaError> {
        let mut map = self.challenges.write().map_err(lock_err)?;
        if let Some(challenge) = map.get_mut(challenge_id) {
            challenge.solved = true;
            Ok(())
        } else {
            Err(CaptchaError::ChallengeNotFound)
        }
    }

    async fn consume_challenge(&self, challenge_id: &Uuid) -> Result<(), CaptchaError> {
        let mut map = self.challenges.write().map_err(lock_err)?;
        match map.remove(challenge_id) {
            Some(challenge) if challenge.solved => Err(CaptchaError::ChallengeAlreadyUsed),
            Some(_) => Ok(()),
            None => Err(CaptchaError::ChallengeNotFound),
        }
    }

    async fn store_site(&self, site: &Site) -> Result<(), CaptchaError> {
        // Persist first so an in-memory insert isn't visible if the disk
        // write fails (e.g. UNIQUE collision on a regenerated secret).
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            persist_site(&conn, site)?;
        }
        {
            let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
            by_key.insert(site.site_key, site.clone());
        }
        {
            let mut by_secret = self.sites_by_secret.write().map_err(lock_err)?;
            by_secret.insert(site.secret_key.clone(), site.site_key);
        }
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
        // Persist first; on success, swap in-memory. On UNIQUE collision
        // (vanishingly rare for 32-byte random secrets) the in-memory
        // state is unchanged.
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            let updated = conn
                .execute(
                    "UPDATE sites SET secret_key = ?1 WHERE site_key = ?2",
                    params![new_secret, site_key.to_string()],
                )
                .map_err(|e| CaptchaError::Storage(format!("rotate site secret: {e}")))?;
            if updated == 0 {
                return Err(CaptchaError::NotFound);
            }
        }

        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let mut by_secret = self.sites_by_secret.write().map_err(lock_err)?;
        let Some(site) = by_key.get_mut(site_key) else {
            // The persistence layer already accepted the UPDATE — but the
            // in-memory map doesn't know about this site. That's a state
            // inconsistency we should never hit in practice (rows in the
            // DB are loaded into memory at boot, every store_site writes
            // both). Surface as Storage rather than NotFound.
            if self.site_persistence.is_some() {
                return Err(CaptchaError::Storage(
                    "site persisted update with no in-memory row".into(),
                ));
            }
            return Err(CaptchaError::NotFound);
        };
        let old_secret = std::mem::replace(&mut site.secret_key, new_secret.clone());
        by_secret.remove(&old_secret);
        by_secret.insert(new_secret, *site_key);
        Ok(())
    }

    async fn delete_site(&self, site_key: &Uuid) -> Result<(), CaptchaError> {
        if let Some(persist) = &self.site_persistence {
            let conn = persist.lock().map_err(lock_err)?;
            let deleted = conn
                .execute(
                    "DELETE FROM sites WHERE site_key = ?1",
                    params![site_key.to_string()],
                )
                .map_err(|e| CaptchaError::Storage(format!("delete site: {e}")))?;
            if deleted == 0 {
                return Err(CaptchaError::NotFound);
            }
        }

        let mut by_key = self.sites_by_key.write().map_err(lock_err)?;
        let mut by_secret = self.sites_by_secret.write().map_err(lock_err)?;
        let Some(site) = by_key.remove(site_key) else {
            if self.site_persistence.is_some() {
                return Err(CaptchaError::Storage(
                    "site persisted delete with no in-memory row".into(),
                ));
            }
            return Err(CaptchaError::NotFound);
        };
        by_secret.remove(&site.secret_key);
        Ok(())
    }

    async fn increment_ip_count(&self, ip: &IpAddr) -> Result<u32, CaptchaError> {
        let mut map = self.ip_rates.write().map_err(lock_err)?;
        let now = Utc::now().timestamp();
        let entry = map.entry(*ip).or_insert(RateWindow {
            count: 0,
            window_start: now,
        });

        if now - entry.window_start >= RATE_WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        Ok(entry.count)
    }

    async fn increment_site_count(&self, site_key: &Uuid) -> Result<u32, CaptchaError> {
        let mut map = self.site_rates.write().map_err(lock_err)?;
        let now = Utc::now().timestamp();
        let entry = map.entry(*site_key).or_insert(RateWindow {
            count: 0,
            window_start: now,
        });

        if now - entry.window_start >= RATE_WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        Ok(entry.count)
    }

    async fn cleanup_expired(&self) -> Result<(), CaptchaError> {
        let now = Utc::now();

        // Clean expired challenges
        {
            let mut map = self.challenges.write().map_err(lock_err)?;
            map.retain(|_, c| c.expires_at > now);
        }

        // Clean stale rate windows
        let ts = now.timestamp();
        {
            let mut map = self.ip_rates.write().map_err(lock_err)?;
            map.retain(|_, w| ts - w.window_start < RATE_WINDOW_SECS * 2);
        }
        {
            let mut map = self.site_rates.write().map_err(lock_err)?;
            map.retain(|_, w| ts - w.window_start < RATE_WINDOW_SECS * 2);
        }

        Ok(())
    }
}

fn lock_err<T>(_: T) -> CaptchaError {
    CaptchaError::Storage("Lock poisoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::puzzle::types::{Algorithm, ChallengeKind};
    use chrono::Duration;

    fn make_challenge(site_key: Uuid, ttl_secs: i64) -> Challenge {
        let now = Utc::now();
        Challenge {
            id: Uuid::new_v4(),
            site_key,
            kind: ChallengeKind::Pow,
            algorithm: Algorithm::Sha256,
            prefix: "deadbeef".into(),
            difficulty: 8,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_secs),
            solved: false,
            visual_answer: None,
            visual_image: None,
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
    async fn test_mark_solution_used() {
        let store = InMemoryStore::new();
        let challenge = make_challenge(Uuid::new_v4(), 300);

        store.store_challenge(&challenge).await.unwrap();
        store.mark_solution_used(&challenge.id).await.unwrap();

        let fetched = store.get_challenge(&challenge.id).await.unwrap().unwrap();
        assert!(fetched.solved);
    }

    #[tokio::test]
    async fn test_mark_solution_not_found() {
        let store = InMemoryStore::new();
        let result = store.mark_solution_used(&Uuid::new_v4()).await;
        assert!(matches!(result, Err(CaptchaError::ChallengeNotFound)));
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

    fn tempdir() -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "rust-captcha-test-{}-{}",
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
