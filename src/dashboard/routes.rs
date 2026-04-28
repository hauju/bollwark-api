//! Admin HTTP routes. Only mounted when `ADMIN_DB_PATH` is set in config.
//! All routes require a bearer token matching `ADMIN_TOKEN`.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;

use super::{DecisionLog, Sessions};

#[derive(Clone)]
pub struct AdminState {
    pub sessions: Sessions,
    pub log: DecisionLog,
    pub token: Arc<String>,
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route(
            "/v1/admin/sessions",
            get(list_sessions).delete(clear_sessions),
        )
        .route("/v1/admin/sessions/{id}", get(get_session))
        .route("/v1/admin/stats", get(get_stats))
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
        Ok(stats) => Json(stats).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "admin get_stats failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "query failed").into_response()
        }
    }
}

#[allow(clippy::result_large_err)]
fn check_auth(state: &AdminState, headers: &HeaderMap) -> Result<(), axum::response::Response> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
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
