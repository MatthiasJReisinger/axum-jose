# axum-jose

Lightweight authorization [middleware for `axum`](https://docs.rs/axum/latest/axum/middleware/index.html), following [JOSE (JSON Object Signing and Encryption) standards](https://datatracker.ietf.org/wg/jose/charter/).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/axum-jose)](https://crates.io/crates/axum)
[![Documentation](https://docs.rs/axum/badge.svg)](https://docs.rs/axum-jose)
[![Build status](https://github.com/MatthiasJReisinger/axum-jose/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/MatthiasJReisinger/axum-jose/actions/workflows/rust.yml)

## Overview

Add JWT-based authorization to your [`axum`](https://crates.io/crates/axum) applications with a simple, [`tower`](https://crates.io/crates/tower)-compatible middleware layer that integrates seamlessly with OpenID Connect and OAuth2 providers.

### JOSE (JSON Object Signing and Encryption) Standards

[JOSE](https://datatracker.ietf.org/wg/jose/charter/) is an umbrella for specifications that form the foundation of
modern authentication and authorization protocol like OpenID Connect and OAuth2. Core specifications include e.g.
[JSON Web Signatures (JWS)](https://datatracker.ietf.org/doc/html/rfc7515),
[JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516),
[JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518),
[JSON Web Keys (JWK)](https://datatracker.ietf.org/doc/html/rfc7517),
which provide the building blocks for [JSON Web Tokens (JWT)](https://datatracker.ietf.org/doc/html/rfc7519).

## Features

- **JWT Validation**: Transparently extract and validate JWTs from `Authorization` headers against JWK sets (local or remote).
- **Caching**: Caching of remote JWK sets to minimize provider requests.
- **Rate Limiting**: Configurable rate limiting prevents overloading your identity provider's JWK endpoints.

## Quickstart

```rust,no_run
use axum::{routing::get, Router};
use axum_jose::{RemoteJwkSet, AuthorizationLayer};
use url::Url;
use std::time::Duration;
use std::num::NonZero;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure remote JWK set from your OIDC provider
    let remote_jwk_set = RemoteJwkSet::builder(
        Url::parse("https://your.oidc.provider/.well-known/jwks.json")?
    )
    .with_cache(Duration::from_secs(300))
    .with_rate_limit(NonZero::new(10).unwrap(), Duration::from_secs(60))
    .build();

    // Protect your routes with the authorization layer
    let router = Router::new()
        .route("/protected", get(|| async { "Hello, authorized user!" }))
        .layer(AuthorizationLayer::with_remote_jwk_set(
            remote_jwk_set,
            Url::parse("https://your.jwt.issuer")?,
            "your.jwt.audience".to_string(),
        ));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await?;
    Ok(())
}
```

See the [documentation](https://docs.rs/axum-jose) for more examples and configuration options.

## Related Projects

At the time of writing, the ecosystem around JOSE, OpenID Connect, and OAuth2 for `axum` and Rust is not yet as mature
as in other languages and web frameworks. There is no clear best practice for implementing authorization for
`axum`-based APIs but a number of crates, similar to this one, exist. To name a few:

- [axum-jwt](https://crates.io/crates/axum-jwt)
- [axum-jwks](https://crates.io/crates/axum-jwks)
- [axum-oidc-layer](https://crates.io/crates/axum-oidc-layer)

## License

This project is licensed under the [MIT License](./LICENSE).
