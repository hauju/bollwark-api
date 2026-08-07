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

/// The bearer token from an `Authorization` header, if there is one.
///
/// RFC 7235 §2.1 makes the auth *scheme* case-insensitive, so `bearer x` is
/// as valid as `Bearer x`. Three call sites each used
/// `strip_prefix("Bearer ")`, which rejects the lowercase form — every real
/// client sends the capitalised one, so this never bit anyone, but three
/// copies of a hand-rolled header parse is three places for the next such
/// detail to be got wrong differently.
///
/// The *token* stays case-sensitive and is returned untouched: it is a
/// secret, and normalising it would shrink its keyspace.
pub fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    // A single space is the grammar, but tolerate the extra whitespace a
    // hand-built client can leave behind. An empty remainder is no token.
    let token = token.trim_start();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod bearer_tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::http::header::AUTHORIZATION;

    fn with_auth(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, value.parse().unwrap());
        h
    }

    #[test]
    fn the_scheme_is_case_insensitive() {
        for header in ["Bearer secret", "bearer secret", "BEARER secret"] {
            assert_eq!(bearer_token(&with_auth(header)), Some("secret"), "{header}");
        }
    }

    #[test]
    fn the_token_itself_is_not_normalised() {
        // It's a secret; lowercasing it would shrink the keyspace.
        assert_eq!(bearer_token(&with_auth("Bearer SeCrEt")), Some("SeCrEt"));
    }

    #[test]
    fn another_scheme_with_the_same_payload_is_not_a_bearer() {
        assert_eq!(bearer_token(&with_auth("Basic secret")), None);
        assert_eq!(bearer_token(&with_auth("Bearerish secret")), None);
    }

    #[test]
    fn a_missing_or_empty_token_is_none() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);
        assert_eq!(bearer_token(&with_auth("Bearer")), None);
        assert_eq!(bearer_token(&with_auth("Bearer ")), None);
        assert_eq!(bearer_token(&with_auth("Bearer    ")), None);
    }

    #[test]
    fn extra_whitespace_after_the_scheme_is_tolerated() {
        assert_eq!(bearer_token(&with_auth("Bearer   secret")), Some("secret"));
    }
}
