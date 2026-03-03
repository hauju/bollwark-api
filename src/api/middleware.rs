use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::CaptchaError;

/// Extract a Bearer token from the Authorization header.
pub fn extract_bearer_token(req: &Request) -> Result<&str, CaptchaError> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(CaptchaError::Unauthorized)?;

    header
        .strip_prefix("Bearer ")
        .ok_or(CaptchaError::Unauthorized)
}

/// Middleware that validates a Bearer token is present.
pub async fn require_bearer(req: Request, next: Next) -> Result<Response, CaptchaError> {
    extract_bearer_token(&req)?;
    Ok(next.run(req).await)
}
