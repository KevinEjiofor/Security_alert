use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    // pub fn success(data: T) -> Self {
    //     Self {
    //         success: true,
    //         data: Some(data),
    //         message: None,
    //     }
    // }

    pub fn success_with_message(data: T, message: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some(message),
        }
    }

    pub fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: Some(message),
        }
    }


    pub fn to_response(self, status: StatusCode) -> (StatusCode, Json<Self>) {
        (status, Json(self))
    }
}