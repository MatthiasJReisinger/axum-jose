use std::{
    task::{Context, Poll},
    time::Duration,
};

use futures::future::BoxFuture;
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use tower::{
    buffer::BufferLayer, util::BoxCloneService, Layer, Service, ServiceBuilder, ServiceExt,
};
use tower_layer::layer_fn;
use url::Url;

use crate::{jwks_cache::JwksCacheLayer, Error};

struct CacheConfig {
    time_to_live: Duration,
}

struct RateLimitConfig {
    num: u64,
    per: Duration,
}

/// Builder for configuring a `RemoteJwkSet` with optional caching and rate limiting.
pub struct RemoteJwkSetBuilder {
    url: Url,
    cache_config: Option<CacheConfig>,
    rate_limit_config: Option<RateLimitConfig>,
}

impl RemoteJwkSetBuilder {
    /// Creates a new builder with the given JWKS URL.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            cache_config: None,
            rate_limit_config: None,
        }
    }

    /// Enables caching to avoid re-fetching the remote JWK set on every authentication request.
    pub fn with_cache(mut self, time_to_live: Duration) -> Self {
        self.cache_config = Some(CacheConfig { time_to_live });
        self
    }

    /// Add rate limiting.
    pub fn with_rate_limit(mut self, num: u64, per: Duration) -> Self {
        self.rate_limit_config = Some(RateLimitConfig { num, per });
        self
    }

    /// Builds the `RemoteJwkSet` with the configured options.
    pub fn build(self) -> RemoteJwkSet {
        let http_client = Client::new();
        let request_service = JwkSetRequestService {
            http_client,
            url: self.url,
        };

        let cache_layer = self
            .cache_config
            .map(|cache_config| JwksCacheLayer::new(cache_config.time_to_live));

        let rate_limit_layer = self.rate_limit_config.map(|rate_limit_config| {
            layer_fn(move |inner| {
                let rate_limit =
                    tower::limit::RateLimitLayer::new(rate_limit_config.num, rate_limit_config.per);
                let rate_limited_service = rate_limit.layer(inner);

                // Wrap the rate limited service in another buffer service to make it `Clone`.
                let buffered_service = BufferLayer::new(1024).layer(rate_limited_service);

                // Finally, map any errors to our own error type.
                buffered_service.map_err(|_| Error::JwkSetRateLimitError)
            })
        });

        let service_tower = ServiceBuilder::new()
            .option_layer(cache_layer)
            .option_layer(rate_limit_layer)
            .service(request_service);

        RemoteJwkSet {
            service_tower: BoxCloneService::new(service_tower),
        }
    }
}

#[derive(Clone)]
pub struct RemoteJwkSet {
    service_tower: BoxCloneService<(), JwkSet, Error>,
}

impl RemoteJwkSet {
    /// Creates a builder for configuring a `RemoteJwkSet`.
    pub fn builder(url: Url) -> RemoteJwkSetBuilder {
        RemoteJwkSetBuilder::new(url)
    }

    pub async fn jwk_set(&mut self) -> Result<JwkSet, Error> {
        self.service_tower.ready().await?.call(()).await
    }
}

/// Helper service wrapping a `reqwest::Client` to fetch a JWK Set from a given URL.
#[derive(Clone)]
struct JwkSetRequestService {
    http_client: Client,
    url: Url,
}

impl Service<()> for JwkSetRequestService {
    type Response = JwkSet;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        let http_client = self.http_client.clone();
        let url = self.url.clone();
        Box::pin(async move {
            let response = http_client
                .get(url.clone())
                .send()
                .await
                .map_err(Error::from)?;

            if !response.status().is_success() {
                return Err(Error::JwkSetResponseError {
                    status_code: response.status(),
                });
            }

            let jwk_set: JwkSet = response.json().await.map_err(Error::from)?;
            Ok(jwk_set)
        })
    }
}
