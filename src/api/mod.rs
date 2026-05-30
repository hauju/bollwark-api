pub mod handlers;
pub mod middleware;
pub mod state;
pub mod types;

use axum::Router;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use tower::ServiceBuilder;
use tower_http::cors::{AllowCredentials, AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::dashboard::routes::AdminState;
use state::SharedState;

pub fn router(state: SharedState, admin: Option<AdminState>) -> Router {
    let cors = build_cors_layer(state.config.cors_allowed_origins.as_deref());
    let asset_cors = build_asset_cors_layer(state.config.cors_allowed_origins.as_deref());

    // Public CORS-enabled surface: just the puzzle endpoint. Browser widgets
    // hosted on a different origin from the captcha service need to fetch it.
    let public = Router::new()
        .route("/v1/puzzle", get(handlers::get_puzzle))
        .with_state(state.clone())
        .layer(cors);

    // Server-to-server / provisioning surface: NO CORS. Browsers can't
    // reach these from a different origin (same-origin policy blocks the
    // response), which is what we want for `/v1/verify` (site secret) and
    // `/v1/sites` (admin token).
    let internal = Router::new()
        .route("/v1/verify", post(handlers::verify))
        .route("/v1/sites", post(handlers::create_site))
        .with_state(state);

    let mut app = Router::new()
        // Marketing landing page at `/`. Static file read on each request —
        // tiny overhead, lets operators edit `static/landing.html` without
        // recompiling. Failing to read falls back to a redirect to `/static/`.
        .route("/", get(landing))
        // Liveness probe for load balancers / orchestrators. No auth, no
        // state read — returns immediately. We deliberately don't expose
        // dependency health (SQLite, etc.) here: a degraded backend
        // shouldn't pull the pod out of rotation, and the dashboard already
        // surfaces store errors via tracing.
        .route("/healthz", get(healthz))
        .merge(public)
        .merge(internal)
        .nest_service(
            "/static",
            ServiceBuilder::new()
                .layer(asset_cors)
                .service(ServeDir::new("static")),
        );

    if let Some(admin) = admin {
        // Admin routes are bearer-protected and not CORS-enabled either.
        app = app.merge(crate::dashboard::routes::router(admin));
    }

    app.layer(TraceLayer::new_for_http())
}

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok")
}

async fn landing() -> Response {
    match tokio::fs::read_to_string("static/landing.html").await {
        Ok(body) => Html(body).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "landing page not found").into_response(),
    }
}

/// Build the CORS layer for the public puzzle endpoint.
///
/// - If `allowed` is `None` (env unset): allow any origin without
///   credentials. The puzzle response is non-credentialed (no cookies
///   flow when the cookie's `SameSite=Lax` is in effect cross-origin),
///   so `*` is operationally equivalent to "any embed".
/// - If `allowed` is `Some(spec)`: parse it as a comma- or
///   whitespace-separated list. In that mode credentials are allowed so
///   cross-site embeds can opt into the trust cookie signal.
fn build_cors_layer(allowed: Option<&str>) -> CorsLayer {
    let methods = [Method::GET, Method::OPTIONS];
    let allow_headers = [header::CONTENT_TYPE, header::COOKIE];

    match allowed.map(parse_origins).unwrap_or_default() {
        list if !list.is_empty() => CorsLayer::new()
            .allow_origin(AllowOrigin::list(list))
            .allow_methods(methods)
            .allow_headers(allow_headers)
            .allow_credentials(AllowCredentials::yes()),
        _ => CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods(methods)
            .allow_headers(allow_headers),
    }
}

fn build_asset_cors_layer(allowed: Option<&str>) -> CorsLayer {
    match allowed.map(parse_origins).unwrap_or_default() {
        list if !list.is_empty() => CorsLayer::new()
            .allow_origin(AllowOrigin::list(list))
            .allow_methods([Method::GET, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE]),
        _ => CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods([Method::GET, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE]),
    }
}

fn parse_origins(spec: &str) -> Vec<HeaderValue> {
    spec.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match HeaderValue::from_str(s) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(origin = s, error = %e, "CORS_ALLOWED_ORIGINS: skipping malformed origin");
                None
            }
        })
        .collect()
}
