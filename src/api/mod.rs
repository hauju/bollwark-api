pub mod handlers;
pub mod middleware;
pub mod state;
pub mod types;

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use state::SharedState;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/v1/puzzle", get(handlers::get_puzzle))
        .route("/v1/verify", post(handlers::verify))
        .route("/v1/sites", post(handlers::create_site))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
