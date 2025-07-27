use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::{RequestExt, RequestPartsExt};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use futures::future::BoxFuture;
use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use oidc::OidcProvider;
use tower::Layer;
use tower_service::Service;
use url::Url;

mod error;
mod oidc;

pub use error::Error;

#[derive(Clone)]
pub struct AuthorizationLayer {
    issuer_url: Url,
    audience: String,
}

impl AuthorizationLayer {
    pub fn new(issuer_url: Url, audience: String) -> Self {
        Self {
            issuer_url,
            audience,
        }
    }
}

impl<S> Layer<S> for AuthorizationLayer {
    type Service = AuthorizationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthorizationService {
            inner,
            audience: self.audience.clone(),
            oidc_provider: Arc::new(OidcProvider::new(self.issuer_url.clone())),
        }
    }
}

#[derive(Clone)]
pub struct AuthorizationService<S> {
    inner: S,
    audience: String,
    oidc_provider: Arc<OidcProvider>,
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
        let oidc_provider = self.oidc_provider.clone();
        let audience = self.audience.clone();
        Box::pin(async move {
            let authorize_result = authorize_request(&mut req, &oidc_provider, audience).await;
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
    oidc_provider: &OidcProvider,
    audience: String,
) -> Result<serde_json::Value, Error> {
    let mut parts: Parts = req.extract_parts::<Parts>().await.expect("infallible");

    // Extract the token from the authorization header
    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await?;

    authorize_token(bearer.token(), &oidc_provider, &audience).await
}

async fn authorize_token(
    token: &str,
    oidc_provider: &OidcProvider,
    audience: &str,
) -> Result<serde_json::Value, Error> {
    // First, just decode the header part of the token, without validating the token, to get the kid.
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| Error::MissingKidError)?;

    // Fetch the JWKS from the issuer's domain and find the JWK with the matching kid.
    let jwks = oidc_provider.jwks().await?;
    let jwk = jwks.find(&kid).ok_or_else(|| Error::InvalidKidError)?;

    let decoding_key = match jwk.clone().algorithm {
        AlgorithmParameters::RSA(ref rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
            .map_err(|_| Error::TokenValidationError),
        _ => Err(Error::TokenValidationError),
    }?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[audience.to_string()]);
    validation.set_issuer(&[oidc_provider.issuer()]);
    let token = decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|_| Error::TokenValidationError)?;
    Ok(token.claims)
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
    use url::Url;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::{
        authorize_token,
        oidc::{OidcProvider, OpenIdConfiguration, OIDC_CONFIGURATION_ENDPOINT},
        AuthorizationLayer,
    };

    struct MockAuthServer {
        _inner_server: MockServer,
        jwt: String,
        jwt_audience: String,
        jwt_issuer: Url,
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
                .and(path(OIDC_CONFIGURATION_ENDPOINT))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(OpenIdConfiguration {
                        jwks_uri: format!("{}/.well-known/jwks.json", mock_auth_server.uri()),
                    }),
                )
                .mount(&mock_auth_server)
                .await;

            Mock::given(method("GET"))
                .and(path(".well-known/jwks.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
                .mount(&mock_auth_server)
                .await;

            let issuer_domain = Url::parse(&mock_auth_server.uri()).unwrap();
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

        pub fn jwt_issuer(&self) -> &Url {
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
            &OidcProvider::new(mock_auth_server.jwt_issuer().clone()),
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
                mock_auth_server.jwt_issuer().clone(),
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
                mock_auth_server.jwt_issuer().clone(),
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
