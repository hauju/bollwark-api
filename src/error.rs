use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum CaptchaError {
    #[error("Challenge not found")]
    ChallengeNotFound,

    #[error("Challenge expired")]
    ChallengeExpired,

    #[error("Challenge already used")]
    ChallengeAlreadyUsed,

    #[error("Invalid solution")]
    InvalidSolution,

    #[error("Invalid site key")]
    InvalidSiteKey,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found")]
    NotFound,

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for CaptchaError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            CaptchaError::ChallengeNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            CaptchaError::ChallengeExpired => (StatusCode::GONE, self.to_string()),
            CaptchaError::ChallengeAlreadyUsed => (StatusCode::CONFLICT, self.to_string()),
            CaptchaError::InvalidSolution => (StatusCode::OK, self.to_string()),
            CaptchaError::InvalidSiteKey => (StatusCode::BAD_REQUEST, self.to_string()),
            CaptchaError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            CaptchaError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            CaptchaError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            CaptchaError::Storage(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into())
            }
            CaptchaError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
        };

        let body = json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}
