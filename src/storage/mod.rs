pub mod memory;

use std::future::Future;
use std::net::IpAddr;

use uuid::Uuid;

use crate::error::CaptchaError;
use crate::puzzle::types::Challenge;
use crate::site::types::{Site, SitePolicy};

pub trait Store: Send + Sync + 'static {
    fn store_challenge(
        &self,
        challenge: &Challenge,
    ) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    fn get_challenge(
        &self,
        id: &Uuid,
    ) -> impl Future<Output = Result<Option<Challenge>, CaptchaError>> + Send;

    fn delete_challenge(&self, id: &Uuid) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    /// Atomically consume a correctly-solved challenge. Exactly one caller
    /// can consume a challenge; later callers receive `ChallengeNotFound`
    /// because the challenge has been removed from the active set.
    fn consume_challenge(
        &self,
        challenge_id: &Uuid,
    ) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    /// Record a failed PoW attempt against a challenge and evict it once the
    /// count reaches `max_attempts`. Returns `true` when the challenge was
    /// evicted (cap reached), `false` while it stays live for retry. A
    /// `max_attempts` of 0 disables the cap and is always a no-op. Bounds how
    /// many (potentially memory-hard) verify attempts one challenge can absorb.
    fn register_failed_attempt(
        &self,
        challenge_id: &Uuid,
        max_attempts: u32,
    ) -> impl Future<Output = Result<bool, CaptchaError>> + Send;

    fn store_site(&self, site: &Site) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    fn get_site_by_key(
        &self,
        site_key: &Uuid,
    ) -> impl Future<Output = Result<Option<Site>, CaptchaError>> + Send;

    fn get_site_by_secret(
        &self,
        secret: &str,
    ) -> impl Future<Output = Result<Option<Site>, CaptchaError>> + Send;

    /// Replace the site's secret_key. Returns the new secret on success.
    /// Returns `NotFound` if the site doesn't exist. The old secret is
    /// invalidated immediately — any in-flight `/v1/verify` calls using
    /// the old secret will fail.
    fn rotate_site_secret(
        &self,
        site_key: &Uuid,
        new_secret: String,
    ) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    /// Replace the site's allowed-origins list (already validated/normalized
    /// by the caller). Returns `NotFound` if the site doesn't exist. Lets an
    /// operator change a tenant's origin allowlist without rotating its secret.
    fn update_site_origins(
        &self,
        site_key: &Uuid,
        origins: Vec<String>,
    ) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    /// Replace the site's display name (already validated by the caller).
    /// Returns `NotFound` if the site doesn't exist. Purely a label: nothing
    /// in the scoring pipeline reads it, so this is the one site edit that
    /// cannot change how a visitor is treated.
    fn update_site_name(
        &self,
        site_key: &Uuid,
        name: String,
    ) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    /// Replace the site's scoring policy (already validated by the caller
    /// against the process config). Returns `NotFound` if the site doesn't
    /// exist. Takes effect on the next request — challenges already issued
    /// keep the difficulty they were stamped with.
    fn update_site_policy(
        &self,
        site_key: &Uuid,
        policy: SitePolicy,
    ) -> impl Future<Output = Result<(), CaptchaError>> + Send;

    /// Delete a site. Returns `NotFound` if the site doesn't exist.
    /// Existing challenges issued to this site are not retroactively
    /// invalidated — they'll fail at `/v1/verify` time on the secret
    /// lookup, which is sufficient.
    fn delete_site(&self, site_key: &Uuid)
    -> impl Future<Output = Result<(), CaptchaError>> + Send;

    fn increment_ip_count(
        &self,
        ip: &IpAddr,
    ) -> impl Future<Output = Result<u32, CaptchaError>> + Send;

    fn increment_site_count(
        &self,
        site_key: &Uuid,
    ) -> impl Future<Output = Result<u32, CaptchaError>> + Send;

    /// Count how many times an identical verify-time behaviour blob has been
    /// submitted for this site inside the dedup window, returning the new
    /// count (this submission included). `fingerprint` is
    /// [`crate::risk::behavior::behavior_fingerprint`] — a hash of the blob's
    /// parsed fields, never the raw JSON.
    ///
    /// Deliberately in-memory and short-lived wherever it's implemented: the
    /// window exists to spot one script inside one site's traffic, and a hash
    /// of event counters is not something to persist.
    fn increment_behavior_blob_count(
        &self,
        site_key: &Uuid,
        fingerprint: u64,
    ) -> impl Future<Output = Result<u32, CaptchaError>> + Send;

    fn cleanup_expired(&self) -> impl Future<Output = Result<(), CaptchaError>> + Send;
}
