pub mod assets;
pub mod extract;
pub mod handlers;
pub mod state;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tower_http::trace::TraceLayer;

use crate::dashboard::routes::AdminState;
use state::SharedState;

pub fn router(state: SharedState, admin: Option<AdminState>) -> Router {
    let cors = build_cors_layer(state.config.cors_allowed_origins.as_deref());
    let asset_cors = build_cors_layer(state.config.cors_allowed_origins.as_deref());
    let bundle_cors = build_cors_layer(state.config.cors_allowed_origins.as_deref());
    let static_dir = state.config.static_dir.clone();
    let landing_path = format!("{static_dir}/landing.html");
    let bundle = build_widget_routes(&static_dir, bundle_cors);

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
        .route(
            "/v1/verify",
            post(handlers::verify)
                // A legitimate verify body is a hex token plus a small behaviour
                // blob — a few hundred bytes. Axum's 2 MB default let an
                // unauthenticated caller force a 2 MB read plus a ~1 MB
                // `hex::decode` allocation per request before the bearer check
                // ever runs; 8 KiB is generous for the real payload.
                .layer(DefaultBodyLimit::max(VERIFY_BODY_LIMIT_BYTES)),
        )
        .route("/v1/sites", post(handlers::create_site))
        // Outage attestation lives on the main router, not the dashboard's:
        // failover must work without ADMIN_DB_PATH. This is how an operator
        // (or the external monitor) records an outage the process could not
        // self-observe — it was healthy the whole time while TLS, DNS, or the
        // reverse proxy in front of it made the widget unreachable.
        .route(
            "/v1/admin/outages",
            post(handlers::declare_outage).get(handlers::list_outages),
        )
        .with_state(state);

    let mut app = Router::new()
        // Marketing landing page at `/`. Static file read on each request —
        // tiny overhead, lets operators edit `static/landing.html` without
        // recompiling. Failing to read falls back to a redirect to `/static/`.
        .route("/", get(move || landing(landing_path.clone())))
        // Liveness probe for load balancers / orchestrators. No auth, no
        // state read — returns immediately. We deliberately don't expose
        // dependency health (SQLite, etc.) here: a degraded backend
        // shouldn't pull the pod out of rotation, and the dashboard already
        // surfaces store errors via tracing.
        .route("/healthz", get(healthz))
        .merge(public)
        .merge(internal)
        .merge(bundle)
        // Legacy unversioned assets. This is the embed path integrators used
        // before `/v1/widget.js` existed, and the only path that serves the
        // operator-facing pages (`admin.html`, `testsite.html`, the info
        // pages), so it stays mounted indefinitely. It gets the entry point's
        // short TTL rather than the immutable one — nothing here is
        // content-addressed, so a long TTL would be the very staleness the
        // hashed bundle exists to avoid.
        .nest_service(
            "/static",
            ServiceBuilder::new()
                .layer(asset_cors)
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(assets::LEGACY_CACHE_CONTROL),
                ))
                .service(ServeDir::new(&static_dir)),
        );

    if let Some(admin) = admin {
        // Admin routes are bearer-protected and not CORS-enabled either.
        app = app.merge(crate::dashboard::routes::router(admin));
    }

    // Outermost layers, applied to every route.
    //
    // Neither hyper nor axum imposes any deadline by default, so before this a
    // request that never finished was held open indefinitely — one task, one fd
    // and one read buffer per connection, for free, until the process ran out of
    // descriptors.
    //
    // Scope worth being precise about: these bound the time from when the
    // request reaches the service (body read + handler). They do NOT bound a
    // client that dribbles out its *headers*, because hyper parses those before
    // the tower stack is entered. Classic slowloris therefore still has to be
    // handled at the reverse proxy — see the deployment notes.
    app.layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    ))
    .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(
        BODY_READ_TIMEOUT_SECS,
    )))
    .layer(TraceLayer::new_for_http())
}

/// Mount the versioned widget bundle: the stable `/v1/widget.js` entry point
/// plus the immutable `/assets/<hash>/` directory it points at.
///
/// CORS is applied at the router level so it covers both the entry point and
/// the nested asset service — the widget `fetch()`es its worker cross-origin
/// (to blob-wrap it), which is a CORS request even though the `<script>` tag
/// that loaded the entry point was not.
fn build_widget_routes(static_dir: &str, cors: CorsLayer) -> Router {
    let Some(bundle) = assets::WidgetBundle::load(static_dir) else {
        // No verifiable bundle. Answer the entry point with a 503 rather than
        // a 404: the URL is right, the server just can't serve it, and an
        // operator debugging a bad STATIC_DIR should be able to tell those
        // apart. `/static/` keeps working, so embeds on the legacy path are
        // unaffected.
        return Router::new().route("/v1/widget.js", get(assets::unavailable));
    };

    let mount = bundle.mount_path();
    tracing::info!(
        version = %bundle.version,
        mount = %mount,
        "widget bundle mounted"
    );

    let bundle = Arc::new(bundle);
    Router::new()
        .route(
            "/v1/widget.js",
            get(move || {
                let bundle = bundle.clone();
                async move { bundle.respond() }
            }),
        )
        .nest_service(
            &mount,
            ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(assets::IMMUTABLE_CACHE_CONTROL),
                ))
                .service(ServeDir::new(static_dir)),
        )
        .layer(cors)
}

/// Deadline for a single request once it reaches the service: body read plus
/// handler execution. Generous enough for a queued Argon2id verification behind
/// a full permit set, short enough that a stalled client can't pin resources.
const REQUEST_TIMEOUT_SECS: u64 = 15;

/// Deadline for streaming in a request body.
const BODY_READ_TIMEOUT_SECS: u64 = 10;

/// Body cap for `/v1/verify`. A widget token plus a behaviour blob is a few
/// hundred bytes; this leaves an order of magnitude of headroom.
const VERIFY_BODY_LIMIT_BYTES: usize = 8 * 1024;

async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok")
}

async fn landing(path: String) -> Response {
    match tokio::fs::read_to_string(&path).await {
        Ok(body) => Html(body).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "landing page not found").into_response(),
    }
}

/// Build the CORS layer for the public puzzle endpoint and static assets.
///
/// The service is cookie-free, so these requests are always
/// non-credentialed and a wildcard `Access-Control-Allow-Origin` is valid.
///
/// - If `allowed` is `None` (env unset): allow any origin (`*`) so the
///   widget can embed from any customer site.
/// - If `allowed` is `Some(spec)`: restrict to a comma- or
///   whitespace-separated allowlist; other origins get a same-origin
///   response that browsers block.
fn build_cors_layer(allowed: Option<&str>) -> CorsLayer {
    let methods = [Method::GET, Method::OPTIONS];
    let allow_headers = [header::CONTENT_TYPE];

    match allowed.map(parse_origins).unwrap_or_default() {
        list if !list.is_empty() => CorsLayer::new()
            .allow_origin(AllowOrigin::list(list))
            .allow_methods(methods)
            .allow_headers(allow_headers),
        _ => CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods(methods)
            .allow_headers(allow_headers),
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
