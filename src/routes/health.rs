use axum::{routing::get, Router};

pub fn routes() -> Router {
    Router::new()
        .route("/health", get(|| async { "OK !!!" }))
}