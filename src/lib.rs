//! axum-jose Lightweight authorization [middleware for `axum`](https://docs.rs/axum/latest/axum/middleware/index.html),
//! following [JSON Object Signing and Encryption (JOSE)](https://datatracker.ietf.org/wg/jose/charter/) standards.
//!
//! # Overview
//!
//! This crate provides a [`tower`](https://docs.rs/tower)-based [`AuthorizationLayer`] that integrates with `axum`'s
//! middleware system to add JWT-based authorization to your application. The middleware validates JWTs from incoming
//! requests against JWK (JSON Web Key) sets, which can be either provided locally or fetched from remote identity providers.
//!
//! # Getting Started
//!
//! ## Basic Setup
//!
//! This example illustrates how to validate JWTs against a remote JWK set provided e.g. by your OpenID Connect
//! provider.
//!
//! It also shows how to enable caching using the [`RemoteJwkSetBuilder::with_cache`] method to avoid fetching the JWK
//! set on every request. Choose a TTL that balances responsiveness to key rotation with provider
//! load. Shorter TTLs react faster to key rotation, while longer TTLs reduce requests to your identity provider.
//!
//! Note though, that the cache is not only invalidated when reaching its TTL but also when a JWT with an unknown `kid`
//! (key ID) is encountered. Therefore, in addition to caching, consider configuring rate limiting using
//! [`RemoteJwkSetBuilder::with_rate_limit`] to prevent running into your identity provider's server-side rate limits.
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use axum_jose::{RemoteJwkSet, AuthorizationLayer};
//! use url::Url;
//! use std::time::Duration;
//! use std::num::NonZero;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure a RemoteJwkSet with caching and rate limiting
//!     let remote_jwk_set = RemoteJwkSet::builder(
//!         Url::parse("https://your.oidc.provider/.well-known/jwks.json")?
//!     )
//!     .with_cache(Duration::from_secs(300))  // Cache for 5 minutes
//!     .with_rate_limit(NonZero::new(10).unwrap(), Duration::from_secs(60))  // 10 requests per minute
//!     .build();
//!
//!     // Create an authorization layer...
//!     let auth_layer = AuthorizationLayer::with_remote_jwk_set(
//!         remote_jwk_set,
//!         Url::parse("https://your.jwt.issuer")?,
//!         "your.jwt.audience".to_string(),
//!     );
//!
//!     // ...and apply it to your routes
//!     let router = Router::new()
//!         .route("/protected", get(|| async { "Authorized!" }))
//!         .layer(auth_layer);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, router).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Accessing JWT Claims
//!
//! After successful authorization, the JWT claims are available via axum's request extensions:
//!
//! ```rust,no_run
//! use axum::{Extension, routing::get};
//! use axum_jose::authorization::Claims;
//! use serde_json::Value;
//!
//! async fn protected_handler(Extension(Claims(claims)): Extension<Claims>) -> String {
//!     // Access standard claims
//!     let subject = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("unknown");
//!
//!     // Access custom claims
//!     let role = claims.get("role").and_then(|v| v.as_str()).unwrap_or("user");
//!
//!     format!("Hello, {}! Your role is: {}", subject, role)
//! }
//! ```
//!
//! For type-safe claim extraction, deserialize into a custom struct:
//!
//! ```rust,no_run
//! use serde::Deserialize;
//! use axum_jose::authorization::Claims;
//! use axum::Extension;
//!
//! #[derive(Deserialize)]
//! struct MyClaims {
//!     sub: String,
//!     role: String,
//! }
//!
//! async fn protected_handler(Extension(Claims(claims)): Extension<Claims>) -> String {
//!     match serde_json::from_value::<MyClaims>(claims) {
//!         Ok(my_claims) => format!("Hello, {}! Your role is: {}", my_claims.sub, my_claims.role),
//!         Err(_) => "Invalid claims".to_string(),
//!     }
//! }
//! ```
//!
//! ## Custom HTTP Client
//!
//! Provide a custom `reqwest::Client` for specific requirements like timeouts, proxies, etc.:
//!
//! ```rust,no_run
//! # use axum_jose::RemoteJwkSet;
//! # use url::Url;
//! # use std::time::Duration;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let http_client = reqwest::Client::builder()
//!     .timeout(Duration::from_secs(10))
//!     .build()?;
//!
//! let jwk_set = RemoteJwkSet::builder(
//!     Url::parse("https://example.com/.well-known/jwks.json")?
//! )
//! .with_http_client(http_client)
//! .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Using a Local JWK Set
//!
//! For testing purposes or scenarios where you manage keys locally you can use a `jsonwebtoken::jwk::JwkSet` directly
//! instead of fetching one from a remote URL:
//!
//! ```rust,no_run
//! # use axum::{routing::get, Router};
//! use axum_jose::AuthorizationLayer;
//! use jsonwebtoken::jwk::JwkSet;
//! # use url::Url;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load or construct your JWK set
//! let jwk_set: JwkSet = serde_json::from_str(r#"{"keys": [...]}"#)?;
//!
//! let auth_layer = AuthorizationLayer::with_local_jwk_set(
//!     jwk_set,
//!     Url::parse("https://your.jwt.issuer")?,
//!     "your.jwt.audience".to_string(),
//! );
//!
//! let router = Router::new()
//!     .route("/protected", get(|| async { "Authorized!" }))
//!     .layer(auth_layer);
//!
//! # let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! # axum::serve(listener, router).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! When authorization fails, the middleware returns an [`Error`] instance that translates into a `401 Unauthorized`
//! response with a JSON body containing a description of what went wrong:
//!
//! ```json
//! {
//!   "error": "JWT validation failed"
//! }
//! ```
//!
//! See [`Error`] for more details on possible error cases.

pub mod authorization;
pub use error::Error;

pub use authorization::AuthorizationLayer;
pub use remote_jwk_set::RemoteJwkSet;

mod error;
mod jwk_set;
mod remote_jwk_set;
