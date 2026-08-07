//! Admin HTTP routes. Only mounted when `ADMIN_DB_PATH` is set in config.
//! All routes require a bearer token matching `ADMIN_TOKEN`.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;

use super::types::SiteSummary;
use super::{DecisionLog, Sessions};
use crate::config::AppConfig;
use crate::site::types::SitePolicy;
use crate::storage::Store;
use crate::storage::memory::InMemoryStore;

#[derive(Clone)]
pub struct AdminState {
    pub sessions: Sessions,
    pub log: DecisionLog,
    pub token: Arc<String>,
    pub store: Arc<InMemoryStore>,
    /// Needed to validate a submitted [`SitePolicy`] against the values it
    /// will actually be merged with at request time — a partial override is
    /// only checkable in combination with the process config.
    pub config: AppConfig,
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route(
            "/v1/admin/sessions",
            get(list_sessions).delete(clear_sessions),
        )
        .route("/v1/admin/sessions/{id}", get(get_session))
        .route("/v1/admin/stats", get(get_stats))
        .route("/v1/admin/analytics", get(get_analytics))
        .route("/v1/admin/sites", get(list_sites))
        .route("/v1/admin/sites/{id}", axum::routing::delete(delete_site))
        .route(
            "/v1/admin/sites/{id}/rotate",
            axum::routing::post(rotate_site),
        )
        .route(
            "/v1/admin/sites/{id}/origins",
            axum::routing::put(update_site_origins),
        )
        .route(
            "/v1/admin/sites/{id}/policy",
            axum::routing::put(update_site_policy),
        )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct ListParams {
    #[serde(default)]
    limit: Option<u32>,
}

async fn list_sessions(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }

    // Cap at a sane upper bound so a misconfigured client can't ask for the
    // whole table.
    let limit = params.limit.unwrap_or(100).min(1000);
    match state.sessions.list(limit).await {
        Ok(sessions) => Json(json!({ "sessions": sessions })).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "admin list_sessions failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

async fn clear_sessions(State(state): State<AdminState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }

    match state.log.clear().await {
        Ok(()) => {
            tracing::info!("admin: cleared all session rows");
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin clear_sessions failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "clear failed").into_response()
        }
    }
}

async fn get_session(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }

    match state.sessions.get(id).await {
        Ok(Some(s)) => Json(s).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "admin get_session failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

async fn get_stats(State(state): State<AdminState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }

    match state.sessions.stats().await {
        Ok(mut stats) => {
            // The DB can't know how many records were dropped before they were
            // written — merge in the writer's live drop counter.
            stats.dropped_records = state.log.dropped_count();
            Json(stats).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin get_stats failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct AnalyticsParams {
    #[serde(default)]
    hours: Option<u32>,
    #[serde(default)]
    site_key: Option<String>,
}

async fn get_analytics(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<AnalyticsParams>,
) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }

    // Clamp the window to 30 days; below 1h the bucket math degenerates.
    let hours = params.hours.unwrap_or(24).clamp(1, 720);
    let site_key = params.site_key.filter(|s| !s.is_empty());
    match state.sessions.analytics(hours, site_key).await {
        Ok(analytics) => Json(analytics).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "admin get_analytics failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

async fn list_sites(State(state): State<AdminState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }

    let sites = match state.store.list_sites() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "admin list_sites: store read failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "store read failed").into_response();
        }
    };

    // Per-site activity is best-effort: if the decision log query fails
    // (e.g. a transient SQLite hiccup), fall back to an empty map so the
    // operator still sees the registered sites with zeroed counters.
    let activity = state.sessions.site_activity().await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "admin list_sites: activity query failed");
        Default::default()
    });

    let summaries: Vec<SiteSummary> = sites
        .into_iter()
        .map(|s| {
            let key = s.site_key.to_string();
            let act = activity.get(&key).cloned().unwrap_or_default();
            SiteSummary {
                site_key: key,
                name: s.name,
                created_at: s.created_at.to_rfc3339(),
                allowed_origins: s.allowed_origins,
                policy: s.policy,
                puzzle_count: act.puzzle_count,
                verify_count: act.verify_count,
                last_seen: act.last_seen,
                avg_bot_probability: act.avg_bot_probability,
            }
        })
        .collect();

    Json(json!({ "sites": summaries })).into_response()
}

async fn rotate_site(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }
    let site_key = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid site_key").into_response(),
    };
    let new_secret = hex::encode(rand::random::<[u8; 32]>());
    match state
        .store
        .rotate_site_secret(&site_key, new_secret.clone())
        .await
    {
        Ok(()) => {
            tracing::info!(site_key = %site_key, "admin: rotated site secret");
            Json(json!({ "site_key": site_key.to_string(), "secret_key": new_secret }))
                .into_response()
        }
        Err(crate::error::CaptchaError::NotFound) => {
            (StatusCode::NOT_FOUND, "site not found").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin rotate_site failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "rotate failed").into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct UpdateOriginsRequest {
    #[serde(default)]
    allowed_origins: Vec<String>,
}

/// Replace a site's scoring policy. The body *is* the policy object, and it
/// replaces the stored one wholesale rather than merging — `{}` clears every
/// override and returns the site to the process defaults. Partial merge would
/// make "unset this override" unexpressible, since `null` and "absent" both
/// have to mean inherit for the type to work at all.
async fn update_site_policy(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(policy): Json<SitePolicy>,
) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }
    let site_key = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid site_key").into_response(),
    };
    // Same validation as POST /v1/sites: reject anything that would silently
    // disable this site's protection or make a tier band unreachable.
    if let Err(msg) = policy.validate(&state.config) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    match state.store.update_site_policy(&site_key, policy).await {
        Ok(()) => {
            tracing::info!(
                site_key = %site_key,
                cleared = policy.is_empty(),
                "admin: updated site policy"
            );
            Json(json!({ "site_key": site_key.to_string(), "policy": policy })).into_response()
        }
        Err(crate::error::CaptchaError::NotFound) => {
            (StatusCode::NOT_FOUND, "site not found").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin update_site_policy failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

/// Replace a site's origin allowlist without rotating its secret. Validates +
/// normalizes each entry exactly like `POST /v1/sites`; a bad entry → 400.
async fn update_site_origins(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateOriginsRequest>,
) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }
    let site_key = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid site_key").into_response(),
    };
    let origins = match crate::site::types::normalize_origins(&body.allowed_origins) {
        Ok(o) => o,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    match state
        .store
        .update_site_origins(&site_key, origins.clone())
        .await
    {
        Ok(()) => {
            tracing::info!(site_key = %site_key, "admin: updated site origins");
            Json(json!({ "site_key": site_key.to_string(), "allowed_origins": origins }))
                .into_response()
        }
        Err(crate::error::CaptchaError::NotFound) => {
            (StatusCode::NOT_FOUND, "site not found").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin update_site_origins failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response()
        }
    }
}

async fn delete_site(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = check_auth(&state, &headers) {
        return resp;
    }
    let site_key = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid site_key").into_response(),
    };
    match state.store.delete_site(&site_key).await {
        Ok(()) => {
            tracing::info!(site_key = %site_key, "admin: deleted site");
            Json(json!({ "ok": true })).into_response()
        }
        Err(crate::error::CaptchaError::NotFound) => {
            (StatusCode::NOT_FOUND, "site not found").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin delete_site failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response()
        }
    }
}

#[allow(clippy::result_large_err)]
fn check_auth(state: &AdminState, headers: &HeaderMap) -> Result<(), axum::response::Response> {
    let token = crate::api::extract::bearer_token(headers);
    let Some(token) = token else {
        return Err((StatusCode::UNAUTHORIZED, "missing bearer token").into_response());
    };
    let a = token.as_bytes();
    let b = state.token.as_bytes();
    if a.len() != b.len() {
        return Err((StatusCode::UNAUTHORIZED, "invalid token").into_response());
    }
    // Constant-time XOR-OR; token entropy is high enough that a timing attack
    // is impractical, but we avoid `==` on the off-chance the runtime
    // short-circuits on first mismatch.
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "invalid token").into_response())
    }
}
