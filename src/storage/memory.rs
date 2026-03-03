use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

use chrono::Utc;
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
}

const RATE_WINDOW_SECS: i64 = 60;

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            sites_by_key: RwLock::new(HashMap::new()),
            sites_by_secret: RwLock::new(HashMap::new()),
            ip_rates: RwLock::new(HashMap::new()),
            site_rates: RwLock::new(HashMap::new()),
        }
    }
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

    async fn store_site(&self, site: &Site) -> Result<(), CaptchaError> {
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
            expires_at: now + Duration::seconds(ttl_secs),
            solved: false,
        }
    }

    fn make_site() -> Site {
        Site {
            site_key: Uuid::new_v4(),
            secret_key: "secret123".into(),
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
