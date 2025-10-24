use axum::{
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::typed_header::TypedHeaderRejection;
use http::StatusCode;
use serde_json::json;

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("missing kid in token header")]
    MissingKid,
    #[error("token header contains invalid kid")]
    InvalidKid,
    #[error(transparent)]
    InvalidAuthorizationHeader(#[from] TypedHeaderRejection),
    #[error("failed to decode JWK into key")]
    InvalidJwk(#[source] jsonwebtoken::errors::Error),
    #[error("JWT validation failed")]
    InvalidJwt(#[source] jsonwebtoken::errors::Error),
    #[error("failed to fetch JWK set")]
    FailedJwkSetRequest(#[from] reqwest::Error),
    #[error("received error response when fetching JWK set: {status_code}")]
    JwkSetRequestErrorResponse { status_code: StatusCode },
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.to_string(),
        }));
        (StatusCode::UNAUTHORIZED, body).into_response()
    }
}
