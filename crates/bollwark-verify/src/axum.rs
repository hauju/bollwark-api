//! An axum extractor that verifies before your handler runs.
//!
//! Enable with the `axum` feature.
//!
//! ```no_run
//! use axum::{Router, routing::post, extract::FromRef};
//! use bollwark_verify::{Client, axum::Captcha};
//! use serde::Deserialize;
//!
//! #[derive(Clone)]
//! struct AppState { captcha: Client }
//! impl FromRef<AppState> for Client {
//!     fn from_ref(s: &AppState) -> Client { s.captcha.clone() }
//! }
//!
//! #[derive(Deserialize)]
//! struct Signup { email: String }
//!
//! // Runs only if the captcha passed. `verdict` distinguishes a normal pass
//! // from a failover one.
//! async fn signup(Captcha(body, verdict): Captcha<Signup>) -> &'static str {
//!     let _ = (body.email, verdict);
//!     "ok"
//! }
//!
//! # fn f(state: AppState) -> Router {
//! Router::new().route("/signup", post(signup)).with_state(state)
//! # }
//! ```
//!
//! # This extractor fails closed
//!
//! An unreachable service rejects with `503`. That is the right default for
//! the endpoints worth protecting with an extractor — signup, payment, invite
//! — but it is the wrong one for a contact form, where refusing every visitor
//! during an outage is worse than accepting a few bots.
//!
//! There is deliberately no knob for this. If you want to fail open, call
//! [`Client::verify`] in the handler and write the policy where a reader can
//! see it, rather than inferring it from a builder argument three files away.

use axum::extract::{FromRef, FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::{Client, Error, Verdict};

/// A JSON body whose captcha token has already been verified.
///
/// Reads the token from `captcha_token` (or `captcha-token`) at the top level
/// of the JSON object and verifies it before deserializing `T`. The key is
/// left in place, so `T` may declare it or — as is usual, since serde ignores
/// unknown fields — simply not mention it.
///
/// The [`Verdict`] is carried through rather than discarded: only
/// [`Verdict::Passed`] reaches your handler, but `failover: true` means the
/// pass came without a proof of work, which is worth logging or flagging.
#[derive(Debug, Clone, Copy)]
pub struct Captcha<T>(pub T, pub Verdict);

impl<T, S> FromRequest<S> for Captcha<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
    Client: FromRef<S>,
{
    type Rejection = CaptchaRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let axum::Json(value) = axum::Json::<serde_json::Value>::from_request(req, state)
            .await
            .map_err(|_| CaptchaRejection::InvalidBody)?;

        let token = value
            .get("captcha_token")
            .or_else(|| value.get("captcha-token"))
            .and_then(serde_json::Value::as_str)
            .ok_or(CaptchaRejection::MissingToken)?;

        let client = Client::from_ref(state);
        let verdict = client
            .verify(token)
            .await
            .map_err(CaptchaRejection::Failed)?;
        if !verdict.accepted() {
            return Err(CaptchaRejection::Refused(verdict));
        }

        let body = serde_json::from_value(value).map_err(|_| CaptchaRejection::InvalidBody)?;
        Ok(Captcha(body, verdict))
    }
}

/// Why [`Captcha`] refused to run the handler.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptchaRejection {
    /// The body was not JSON, or did not deserialize into `T`.
    InvalidBody,
    /// No `captcha_token` string in the body. Usually a front end that never
    /// read the widget's hidden field.
    MissingToken,
    /// The service answered, and the answer was not a pass.
    Refused(Verdict),
    /// The service did not answer. Fails closed — see the module docs.
    Failed(Error),
}

impl IntoResponse for CaptchaRejection {
    fn into_response(self) -> Response {
        // Expired and Replayed are recoverable by resubmitting, so they say
        // so; Blocked deliberately does not explain itself.
        let (status, message) = match &self {
            CaptchaRejection::InvalidBody => (StatusCode::BAD_REQUEST, "Malformed request body."),
            CaptchaRejection::MissingToken => (StatusCode::BAD_REQUEST, "Verification required."),
            CaptchaRejection::Refused(Verdict::Expired | Verdict::Replayed) => (
                StatusCode::BAD_REQUEST,
                "Your verification expired. Please submit the form again.",
            ),
            CaptchaRejection::Refused(_) => (
                StatusCode::BAD_REQUEST,
                "Verification failed. Please reload and try again.",
            ),
            CaptchaRejection::Failed(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Verification unavailable. Please try again in a moment.",
            ),
        };
        (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl std::fmt::Display for CaptchaRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptchaRejection::InvalidBody => write!(f, "malformed request body"),
            CaptchaRejection::MissingToken => write!(f, "no captcha_token in body"),
            CaptchaRejection::Refused(v) => write!(f, "captcha refused: {v:?}"),
            CaptchaRejection::Failed(e) => write!(f, "captcha verify failed: {e}"),
        }
    }
}

impl std::error::Error for CaptchaRejection {}
