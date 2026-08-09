//! Server-side verification for the [Bollwark](https://bollwark.eu) CAPTCHA
//! service.
//!
//! The HTTP call this wraps is four lines of `reqwest`. What the crate is
//! actually for is the shape of the answer, because the obvious hand-rolled
//! version is wrong in two ways that only show up in production:
//!
//! ```ignore
//! // The version everyone writes:
//! let ok = resp.status().is_success() && body.success;
//! ```
//!
//! 1. **It collapses four different outcomes into one.** A challenge that
//!    expired (the visitor left the tab open), one that was replayed, and one
//!    the risk engine actually blocked are the same `false` here — so the
//!    visitor gets one generic "verification failed" for a problem that, in
//!    two of those three cases, a plain resubmit would have fixed.
//! 2. **It reads an outage as a failed check.** If the service is unreachable
//!    `is_success()` is false, so every visitor is silently rejected — a
//!    decision to fail closed that nobody made on purpose.
//!
//! So [`verify`](Client::verify) returns `Result<Verdict, Error>`, split on
//! exactly that line: a [`Verdict`] is what the service decided about this
//! visitor, an [`Error`] is that it did not get to decide. You cannot reach a
//! boolean without saying what an outage means for your endpoint — which is a
//! real policy question ([fail closed for signup or payments, open for a
//! contact form][outage]) that this crate deliberately refuses to guess.
//!
//! [outage]: Error::Unreachable
//!
//! # Example
//!
//! ```no_run
//! use bollwark_verify::{Client, Error, Verdict};
//!
//! # async fn f() -> Result<(), Box<dyn std::error::Error>> {
//! let client = Client::new("https://api.bollwark.eu", std::env::var("BOLLWARK_SECRET_KEY")?);
//!
//! match client.verify(token).await {
//!     Ok(Verdict::Passed { failover }) => {
//!         if failover {
//!             // Accepted without a proof of work, because the service was
//!             // attestably down when the visitor loaded the form.
//!             eprintln!("captcha failover — accepted without proof of work");
//!         }
//!         // ... proceed
//!     }
//!     Ok(Verdict::Expired | Verdict::Replayed) => {
//!         // Recoverable: ask them to submit again, don't accuse them.
//!     }
//!     Ok(Verdict::Blocked) => { /* refuse, or queue for review */ }
//!     Err(Error::Unreachable(_)) => { /* your call — see the note above */ }
//!     Err(e) => return Err(e.into()),
//! }
//! # Ok(()) }
//! # const token: &str = "";
//! ```
//!
//! With the `axum` feature, [`Captcha<T>`](axum::Captcha) does the same thing
//! as an extractor.

#![forbid(unsafe_code)]

use std::time::Duration;

#[cfg(feature = "axum")]
pub mod axum;

/// What the service decided about this submission.
///
/// Every variant means the service was reached and answered. "I could not
/// ask" is an [`Error`], never a `Verdict` — that split is the point of the
/// type.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike [`Error`]. Marking it so
/// would force every consumer to write a catch-all arm, which is precisely the
/// collapsing of distinct outcomes this crate exists to prevent. The verdict
/// space is fixed by the service's protocol; a fifth outcome would be a
/// breaking change and should be versioned as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Accepted.
    ///
    /// `failover` is true when the pass was granted **without** a solved
    /// puzzle, because the service was attestably unreachable when the
    /// visitor loaded the form. The honeypot and behavioural signals were
    /// still checked, but there is no proof of work behind this one. Ignore
    /// it and you get availability during outages; branch on it to
    /// accept-but-flag.
    Passed { failover: bool },

    /// Solved correctly, but refused on risk score.
    ///
    /// The one variant that is actually about a suspicious visitor. Refuse,
    /// or queue for review.
    Blocked,

    /// The challenge expired before it was submitted (HTTP 410).
    ///
    /// Usually a real person who left the form open. A resubmit fixes it, so
    /// prompt for one rather than reporting a failure.
    Expired,

    /// The challenge was already used, or no longer exists (HTTP 404).
    ///
    /// Challenges are single-use. A double-submitted form lands here, so —
    /// like [`Expired`](Verdict::Expired) — prefer "please try again" over an
    /// accusation, but never accept the submission.
    Replayed,
}

impl Verdict {
    /// Whether the submission should be accepted.
    ///
    /// True only for [`Passed`](Verdict::Passed), failover included. If you
    /// want to treat a failover pass differently, match instead.
    pub fn accepted(&self) -> bool {
        matches!(self, Verdict::Passed { .. })
    }
}

/// The service did not return a verdict.
///
/// Kept separate from [`Verdict`] so an outage cannot be mistaken for a failed
/// check. None of these mean the visitor did anything wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The service could not be reached, or did not answer in time.
    ///
    /// **This is a policy decision, not an error to bubble up blindly.** Fail
    /// closed on account creation or payments; fail open on a contact form,
    /// where refusing every visitor is the worse outcome. Whichever you pick,
    /// log it — a silent fail-open is indistinguishable from having no
    /// captcha at all.
    #[error("bollwark unreachable: {0}")]
    Unreachable(#[from] reqwest::Error),

    /// The secret key was rejected (HTTP 401).
    ///
    /// A deployment problem, not a bot: a wrong or rotated `secret_key`, or a
    /// token minted for a different site. Failing closed here is right — but
    /// alert on it, because every visitor is affected.
    #[error("bollwark rejected the secret key (401) — check secret_key")]
    Unauthorized,

    /// The token was malformed (HTTP 400).
    ///
    /// The widget produces opaque tokens that are forwarded verbatim, so in
    /// practice this means something mangled it in transit — truncation, a
    /// re-encoding, or a hand-built request.
    #[error("bollwark rejected the token as malformed (400)")]
    MalformedToken,

    /// An unrecognised status, which this crate will not guess the meaning of.
    #[error("bollwark returned an unexpected status: {status}")]
    Unexpected { status: u16 },
}

/// A client for one site's `secret_key`.
///
/// Cheap to clone (the inner `reqwest::Client` is a handle to a shared
/// connection pool), so build one per site at startup and share it — do not
/// construct one per request.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    verify_url: String,
    secret_key: String,
}

impl Client {
    /// Build a client for `base_url` (e.g. `https://api.bollwark.eu`) using
    /// this site's `secret_key`.
    ///
    /// A trailing slash on `base_url` is fine. The default timeout is 5s —
    /// short on purpose, because this call sits in front of a form submission
    /// and a hung captcha should surface as [`Error::Unreachable`] quickly
    /// rather than holding the visitor's request open.
    pub fn new(base_url: impl AsRef<str>, secret_key: impl Into<String>) -> Self {
        Self::with_timeout(base_url, secret_key, Duration::from_secs(5))
    }

    /// [`new`](Client::new) with an explicit request timeout.
    pub fn with_timeout(
        base_url: impl AsRef<str>,
        secret_key: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            // Only fails if the TLS backend cannot initialise, which is a
            // broken build rather than a runtime condition.
            .expect("bollwark-verify: could not build HTTP client");
        Self::with_http_client(http, base_url, secret_key)
    }

    /// [`new`](Client::new) reusing an existing `reqwest::Client`.
    ///
    /// Use this to share one connection pool, proxy config or timeout policy
    /// with the rest of your application.
    pub fn with_http_client(
        http: reqwest::Client,
        base_url: impl AsRef<str>,
        secret_key: impl Into<String>,
    ) -> Self {
        Self {
            http,
            verify_url: format!("{}/v1/verify", base_url.as_ref().trim_end_matches('/')),
            secret_key: secret_key.into(),
        }
    }

    /// Verify the opaque token the widget wrote into the `captcha-token`
    /// field.
    ///
    /// Forward that value verbatim — it is a black box carrying the challenge
    /// id, the proof-of-work nonce, the honeypot and behavioural telemetry.
    /// There is nothing to parse, and parsing it is not supported.
    ///
    /// An empty token short-circuits to [`Verdict::Replayed`] without a round
    /// trip: there is nothing to verify, and it must never be accepted.
    pub async fn verify(&self, token: &str) -> Result<Verdict, Error> {
        if token.is_empty() {
            return Ok(Verdict::Replayed);
        }

        let resp = self
            .http
            .post(&self.verify_url)
            .bearer_auth(&self.secret_key)
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await?;

        match resp.status().as_u16() {
            200 => {
                let body: VerifyResponse = resp.json().await?;
                Ok(if body.success {
                    Verdict::Passed {
                        failover: body.failover,
                    }
                } else {
                    Verdict::Blocked
                })
            }
            // Single-use: the challenge is removed on the first successful
            // verify, so a replay is indistinguishable from one that never
            // existed — and both must be refused.
            404 => Ok(Verdict::Replayed),
            410 => Ok(Verdict::Expired),
            400 => Err(Error::MalformedToken),
            401 => Err(Error::Unauthorized),
            status => Err(Error::Unexpected { status }),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct VerifyResponse {
    success: bool,
    #[serde(default)]
    failover: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_trailing_slash_does_not_double_up() {
        let a = Client::new("https://api.bollwark.eu", "s");
        let b = Client::new("https://api.bollwark.eu/", "s");
        assert_eq!(a.verify_url, "https://api.bollwark.eu/v1/verify");
        assert_eq!(a.verify_url, b.verify_url);
    }

    #[tokio::test]
    async fn empty_token_is_refused_without_a_round_trip() {
        // Points at a port nothing is listening on: reaching the network at
        // all would surface as Unreachable and fail this test.
        let client = Client::new("http://127.0.0.1:1", "secret");
        assert_eq!(client.verify("").await.unwrap(), Verdict::Replayed);
    }

    #[test]
    fn only_passed_is_accepted() {
        assert!(Verdict::Passed { failover: false }.accepted());
        assert!(Verdict::Passed { failover: true }.accepted());
        assert!(!Verdict::Blocked.accepted());
        assert!(!Verdict::Expired.accepted());
        assert!(!Verdict::Replayed.accepted());
    }
}
