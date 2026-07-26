//! Extractor wrappers that render rejections through the app's JSON error
//! envelope (`{"error": ...}`) instead of axum's default plain-text response,
//! so a malformed query string or request body looks like every other API
//! error to a consumer doing structured error handling.

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Query, Request};
use axum::http::request::Parts;

use crate::error::CaptchaError;

/// `Json<T>` whose body-parse / `Content-Type` rejection maps to
/// `CaptchaError::BadRequest` (400 with the JSON envelope).
pub struct AppJson<T>(pub T);

impl<T, S> FromRequest<S> for AppJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = CaptchaError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| CaptchaError::BadRequest(e.body_text()))?;
        Ok(Self(value))
    }
}

/// `Query<T>` whose deserialize rejection maps to `CaptchaError::BadRequest`.
pub struct AppQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for AppQuery<T>
where
    Query<T>: FromRequestParts<S, Rejection = QueryRejection>,
    S: Send + Sync,
{
    type Rejection = CaptchaError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(value) = Query::<T>::from_request_parts(parts, state)
            .await
            .map_err(|e| CaptchaError::BadRequest(e.body_text()))?;
        Ok(Self(value))
    }
}
