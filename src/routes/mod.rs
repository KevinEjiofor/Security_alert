pub mod user_authentication_route;
pub mod health;
// use axum::Router;
// use std::sync::Arc;
// use crate::user_authentication::controllers::user_authentication_controller::AuthController;
//
// pub fn create_routes(auth_controller: Arc<AuthController>) -> Router {
//     Router::new()
//         .merge(user_authentication_route::routes(auth_controller))
//         .merge(health::routes())
// }