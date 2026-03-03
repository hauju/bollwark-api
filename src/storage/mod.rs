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
