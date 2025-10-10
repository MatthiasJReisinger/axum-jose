//! Lightweight authorization [middleware for `axum`](https://docs.rs/axum/latest/axum/middleware/index.html), following
//! [JSON Object Signing and Encryption (JOSE)](https://datatracker.ietf.org/wg/jose/charter/) standards.
//!
//! ## Overview
//!
//! The JOSE standard is an umbrella for a number of specifications that have become the essential parts for modern
//! authentication and authorization protocols such as OpenID Connect and OAuth2, e.g.:
//!
//! - [JSON Web Tokens (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
//! - [JSON Web Signatures (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
//! - [JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
//! - [JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
//! - [JSON Web Keys (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
//!
//! This crate provides means to add JOSE-based authorization to your `axum` applications. For this purpose, it provides
//! a `tower`-based `AuthorizationLayer` that integrates with `axum`'s flexible middleware system.
//!
//! ## Features
//!
//! The main features of this crate are:
//!
//! - **JWT Validation**: Transparently extract JWTs from the `Authorization` headers (following the bearer scheme) of
//!   incoming HTTP requests and validate them against a JWK set that's either provided locally or fetched remotely from
//!   your OpenID Connect provider or OAuth2 authorization server.
//! - **Caching**: To avoid fetching remotely hosted JWK sets on every authentication request, this crate provides
//!   optional caching with configurable time-to-live.
//! - **Rate Limiting**: JWK sets are re-fetched either when the cache expires or when a JWT is signed with a key ID
//!   (`kid`) that is not part of the currently cached JWK set (e.g. due to token rotation on the server). To avoid
//!   overloading the JWK set endpoint of your OpenID Connect provider or OAuth2 authorization
//!   server and to prevent running into server-side rate limits, this crate provides optional rate limiting for
//!   outgoing requests to fetch JWK sets.
//!
//! ## Quickstart
//!
//! ```rust,no_run
//! use axum::{
//!     routing::get,
//!     Router,
//! };
//! use axum_jose::{RemoteJwkSet, AuthorizationLayer};
//! use url::Url;
//! use std::time::Duration;
//! use std::num::NonZero;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure a `RemoteJwkSet` to fetch the JWK set e.g. from your OpenID Connect provider which typically exposes an
//!     // endpoint such as `.well-known/jwks.json`.
//!     let remote_jwk_set = RemoteJwkSet::builder(Url::parse("https://your.oicd.provider/.well-known/jwks.json")?)
//!         .with_cache(Duration::from_secs(30))
//!         .with_rate_limit(NonZero::new(42).unwrap(), Duration::from_secs(120)).build();
//!
//!     // Set up an `axum` router whose routes are protected by an `AuthorizationLayer`.
//!     let router = axum::Router::new()
//!         .route("/protected", get(|| async {
//!             "Hello World!"
//!         }))
//!         .layer(AuthorizationLayer::with_remote_jwk_set(
//!             remote_jwk_set,
//!             Url::parse("https://your.jwt.issuer")?,
//!             "your.jwt.audience".to_string(),
//!         ));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, router).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Related Projects
//!
//! At the time of writing, the ecosystem around JOSE, OpenID Connect, and OAuth2 for `axum` and Rust is not yet as
//! mature as in other languages and web frameworks. There is no clear best practice for implementing authorization for
//! `axum`-based APIs but a number of crates, similar to this one, exist. To name a few:
//!
//! - [axum-jwt](https://crates.io/crates/axum-jwt)
//! - [axum-jkws](https://crates.io/crates/axum-jwks)
//! - [axum-oidc-layer](https://crates.io/crates/axum-oidc-layer)

pub mod authorization;
pub use error::Error;

pub use authorization::AuthorizationLayer;
pub use remote_jwk_set::RemoteJwkSet;

mod error;
mod jwk_set;
mod remote_jwk_set;
