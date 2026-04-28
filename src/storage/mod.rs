pub mod memory;

use std::future::Future;
use std::net::IpAddr;

use uuid::Uuid;

use crate::error::CaptchaError;
use crate::puzzle::types::Challenge;
use crate::site::types::Site;

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

    fn mark_solution_used(
        &self,
        challenge_id: &Uuid,
    ) -> impl Future<Output = Result<(), CaptchaError>> + Send;

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

    fn cleanup_expired(&self) -> impl Future<Output = Result<(), CaptchaError>> + Send;
}
