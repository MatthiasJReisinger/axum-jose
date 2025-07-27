use axum::{
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::typed_header::TypedHeaderRejection;
use http::StatusCode;
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("missing kid in token header")]
    MissingKidError,
    #[error("token header contains invalid kid")]
    InvalidKidError,
    #[error(transparent)]
    TypedHeaderError(#[from] TypedHeaderRejection),
    #[error("failed to validate token")]
    TokenValidationError,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.to_string(),
        }));
        (StatusCode::UNAUTHORIZED, body).into_response()
    }
}
