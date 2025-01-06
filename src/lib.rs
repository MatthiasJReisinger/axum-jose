use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::{request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, RequestExt, RequestPartsExt};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::typed_header::TypedHeaderRejection;
use axum_extra::TypedHeader;
use futures::future::BoxFuture;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde_json::json;
use tower::Layer;
use tower_service::Service;
use url::Url;

#[derive(Clone)]
pub struct AuthorizationLayer {
    issuer_domain: String,
    audience: String,
}

impl AuthorizationLayer {
    pub fn new(issuer_domain: String, audience: String) -> Self {
        Self {
            issuer_domain,
            audience,
        }
    }
}

impl<S> Layer<S> for AuthorizationLayer {
    type Service = AuthorizationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizationService {
            inner,
            issuer_domain: self.issuer_domain.clone(),
            audience: self.audience.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthorizationService<S> {
    inner: S,
    issuer_domain: String,
    audience: String,
}

impl<S> AuthorizationService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            issuer_domain: String::new(),
            audience: String::new(),
        }
    }
}

#[derive(Clone)]
pub struct Claims(pub serde_json::Value);

impl<S> Service<Request> for AuthorizationService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut inner = self.inner.clone();
        let domain = self.issuer_domain.clone();
        let audience = self.audience.clone();
        Box::pin(async move {
            let authorize_result = authorize_request(&mut req, domain, audience).await;
            match authorize_result {
                Ok(claims) => {
                    req.extensions_mut().insert(Claims(claims));
                    inner.call(req).await
                }
                Err(auth_error) => Ok(auth_error.into_response()),
            }
        })
    }
}

async fn authorize_request(
    req: &mut Request,
    issuer_domain: String,
    audience: String,
) -> Result<serde_json::Value, Error> {
    let mut parts: Parts = req.extract_parts::<Parts>().await.expect("infallible");

    // Extract the token from the authorization header
    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await?;

    authorize_token(bearer.token(), &issuer_domain, &audience).await
}

async fn authorize_token(
    token: &str,
    issuer_domain: &str,
    audience: &str,
) -> Result<serde_json::Value, Error> {
    // First, just decode the header part of the token, without validating the token, to get the kid.
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| Error::MissingKidError)?;

    // Fetch the JWKS from the issuer's domain and find the JWK with the matching kid.
    let mut issuer_url = Url::parse(&issuer_domain).expect("could not parse issuer domain");
    issuer_url.set_path("/.well-known/jwks.json");
    let jwks_response = reqwest::get(issuer_url)
        .await
        .map_err(|_| Error::TokenValidationError)?;
    let jwks: JwkSet = serde_json::from_str(
        &jwks_response
            .text()
            .await
            .map_err(|_| Error::TokenValidationError)?,
    )
    .map_err(|_| Error::TokenValidationError)?;
    let jwk = jwks.find(&kid).ok_or_else(|| Error::InvalidKidError)?;

    let decoding_key = match jwk.clone().algorithm {
        AlgorithmParameters::RSA(ref rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
            .map_err(|_| Error::TokenValidationError),
        _ => Err(Error::TokenValidationError),
    }?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[audience.to_string()]);
    validation.set_issuer(&[issuer_domain]);
    let token = decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|_| Error::TokenValidationError)?;
    Ok(token.claims)
}

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

#[cfg(test)]
mod test {
    use std::time::SystemTime;

    use axum::routing::get;
    use http::StatusCode;
    use jsonwebtoken::{
        jwk::{AlgorithmParameters, CommonParameters, KeyAlgorithm},
        Algorithm, EncodingKey, Header,
    };
    use tokio::task;
    use tokio_util::sync::CancellationToken;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::{authorize_token, AuthorizationLayer};

    struct MockAuthServer {
        _inner_server: MockServer,
        jwt: String,
        jwt_audience: String,
        jwt_issuer: String,
    }

    impl MockAuthServer {
        pub async fn new() -> MockAuthServer {
            let rsa_private_key = openssl::rsa::Rsa::generate(2048).unwrap();

            let jwk = jsonwebtoken::jwk::Jwk {
                common: jsonwebtoken::jwk::CommonParameters {
                    key_algorithm: Some(KeyAlgorithm::RS256),
                    key_id: Some("42".to_string()),
                    ..CommonParameters::default()
                },
                algorithm: AlgorithmParameters::RSA(jsonwebtoken::jwk::RSAKeyParameters {
                    n: base64_url::encode(&rsa_private_key.n().to_vec()),
                    e: base64_url::encode(&rsa_private_key.e().to_vec()),
                    key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                }),
            };
            let jwks = jsonwebtoken::jwk::JwkSet { keys: vec![jwk] };

            let mock_auth_server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/.well-known/jwks.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
                .mount(&mock_auth_server)
                .await;

            let issuer_domain = mock_auth_server.uri();
            let audience = "https://my.token.audience".to_string();
            let issued_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            let expires_at = issued_time + std::time::Duration::from_secs(3600);

            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("42".to_string());
            let claims = serde_json::json!({ "sub": "1234567890", "name": "John Doe", "admin": true, "aud": audience, "iss": issuer_domain, "iat": issued_time.as_secs(), "exp": expires_at.as_secs() });
            let jwt = jsonwebtoken::encode(
                &header,
                &claims,
                &EncodingKey::from_rsa_der(&rsa_private_key.private_key_to_der().unwrap()),
            )
            .unwrap();

            MockAuthServer {
                _inner_server: mock_auth_server,
                jwt,
                jwt_audience: audience,
                jwt_issuer: issuer_domain,
            }
        }

        pub fn jwt_issuer(&self) -> &str {
            &self.jwt_issuer
        }

        pub fn jwt_audience(&self) -> &str {
            &self.jwt_audience
        }

        pub fn jwt_token(&self) -> &str {
            &self.jwt
        }
    }

    #[tokio::test]
    async fn test_authorize_token() {
        let mock_auth_server = MockAuthServer::new().await;

        let _decoded_claims = authorize_token(
            mock_auth_server.jwt_token(),
            mock_auth_server.jwt_issuer(),
            mock_auth_server.jwt_audience(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_middleware_accepts_valid_token() {
        let mock_auth_server = MockAuthServer::new().await;

        let router = axum::Router::new()
            .route("/protected", get(|| async { "authorized" }))
            .layer(AuthorizationLayer::new(
                mock_auth_server.jwt_issuer().to_string(),
                mock_auth_server.jwt_audience().to_string(),
            ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let axum_server_addr = listener.local_addr().unwrap();

        let axum_shutdown_token = CancellationToken::new();
        let axum_shutdown_signal = axum_shutdown_token.clone().cancelled_owned();
        let _axum_shutdown_guard = axum_shutdown_token.drop_guard();
        task::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(axum_shutdown_signal)
                .await
                .unwrap();
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{axum_server_addr}/protected"))
            .bearer_auth(mock_auth_server.jwt_token())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "authorized");
    }

    #[tokio::test]
    async fn test_middleware_rejects_unauthorized_request() {
        let mock_auth_server = MockAuthServer::new().await;

        let router = axum::Router::new()
            .route("/protected", get(|| async { "authorized" }))
            .layer(AuthorizationLayer::new(
                mock_auth_server.jwt_issuer().to_string(),
                mock_auth_server.jwt_audience().to_string(),
            ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let axum_server_addr = listener.local_addr().unwrap();

        let axum_shutdown_token = CancellationToken::new();
        let axum_shutdown_signal = axum_shutdown_token.clone().cancelled_owned();
        let _axum_shutdown_guard = axum_shutdown_token.drop_guard();
        task::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(axum_shutdown_signal)
                .await
                .unwrap();
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{axum_server_addr}/protected"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap(),
            serde_json::json!({"error": "Header of type `authorization` was missing"})
        );
    }
}
