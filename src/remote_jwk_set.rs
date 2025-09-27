use std::{num::NonZeroU32, sync::Arc, time::Duration};

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use reqwest::Client;
use url::Url;

use crate::Error;

/// The key under which the JWK Set is cached in the Moka cache.
const CACHE_KEY: &str = "jwk_set";

struct CacheConfig {
    time_to_live: Duration,
}

struct RateLimitConfig {
    num: NonZeroU32,
    per: Duration,
}

/// Builder for configuring a `RemoteJwkSet` with optional caching and rate limiting.
pub struct RemoteJwkSetBuilder {
    url: Url,
    cache_config: Option<CacheConfig>,
    rate_limit_config: Option<RateLimitConfig>,
    http_client: Option<Client>,
}

impl RemoteJwkSetBuilder {
    /// Creates a new builder with the given JWKS URL.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            cache_config: None,
            rate_limit_config: None,
            http_client: None,
        }
    }

    /// Enables caching to avoid re-fetching the remote JWK set on every authentication request.
    pub fn with_cache(mut self, time_to_live: Duration) -> Self {
        self.cache_config = Some(CacheConfig { time_to_live });
        self
    }

    /// Add rate limiting.
    pub fn with_rate_limit(mut self, num: NonZeroU32, per: Duration) -> Self {
        self.rate_limit_config = Some(RateLimitConfig { num, per });
        self
    }

    /// Allows to provide a custom [`reqwest::Client`] to enable configuration of HTTP client options such as timeouts, proxies, TLS settings, etc.
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Builds the `RemoteJwkSet` with the configured options.
    pub fn build(self) -> RemoteJwkSet {
        let cache = self.cache_config.map(|cache_config| {
            moka::future::Cache::<String, JwkSet>::builder()
                .max_capacity(1)
                .time_to_live(cache_config.time_to_live)
                .build()
        });

        let rate_limiter = self.rate_limit_config.map(|rate_limit_config| {
            let quota = Quota::with_period(rate_limit_config.per)
                .expect("invalid rate limit period")
                .allow_burst(rate_limit_config.num);
            Arc::new(RateLimiter::direct(quota))
        });

        RemoteJwkSet {
            http_client: self.http_client.unwrap_or_default(),
            url: self.url,
            cache,
            rate_limiter,
        }
    }
}

#[derive(Clone)]
pub struct RemoteJwkSet {
    http_client: Client,
    url: Url,
    cache: Option<moka::future::Cache<String, JwkSet>>,
    rate_limiter: Option<Arc<DefaultDirectRateLimiter>>,
}

impl RemoteJwkSet {
    /// Creates a builder for configuring a `RemoteJwkSet`.
    pub fn builder(url: Url) -> RemoteJwkSetBuilder {
        RemoteJwkSetBuilder::new(url)
    }

    pub async fn find(&self, kid: &str) -> Result<Option<Jwk>, Error> {
        // First, check if the cached JWK set covers the requested `kid`. Otherwise, if
        // * no JWK set is cached,
        // * or the cached JWK set does not cover the requested `kid`,
        // then re-fetch the JWK set from the remote URL.
        if let Some(cache) = &self.cache {
            if let Some(jwk_set) = cache.get(CACHE_KEY).await {
                if let Some(jwk) = jwk_set.find(kid) {
                    return Ok(Some(jwk.clone()));
                }
            }
        }

        // If rate limiting is enabled, wait until the next request is allowed.
        if let Some(rate_limiter) = &self.rate_limiter {
            rate_limiter.until_ready().await;
        }

        // Finally, fetch the JWK set from the remote URL.
        let response = self
            .http_client
            .get(self.url.clone())
            .send()
            .await
            .map_err(Error::from)?;

        if !response.status().is_success() {
            return Err(Error::JwkSetResponseError {
                status_code: response.status(),
            });
        }

        let jwk_set: JwkSet = response.json().await.map_err(Error::from)?;

        // Cache the fetched JWK set if caching is enabled.
        if let Some(cache) = &self.cache {
            cache.insert(CACHE_KEY.to_string(), jwk_set.clone()).await;
        }

        Ok(jwk_set.find(kid).cloned())
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::{AlgorithmParameters, CommonParameters, KeyAlgorithm};
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    use crate::remote_jwk_set::RemoteJwkSet;

    /// Tests that the JWK set isn't re-fetched if the same `kid` is requested multiple times.
    #[tokio::test]
    async fn test_cache_is_hit_if_cached_kid_is_requested() {
        // Create a mock JWK set containing a single RSA key with `kid` "42".
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

        // Start a mock HTTP server to serve the JWK set.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Create a `RemoteJwkSet` with caching enabled.
        let remote_jwk_set = RemoteJwkSet::builder(mock_server.uri().parse().unwrap())
            .with_cache(std::time::Duration::from_secs(60))
            .build();

        // Request the jwk for `kid` 42 to populate the cache.
        assert!(remote_jwk_set.find("42").await.unwrap().is_some());
        // Request the same `kid` again, which should hit the cache.
        assert!(remote_jwk_set.find("42").await.unwrap().is_some());
    }

    /// Tests that the JWK set is re-fetched if a `kid` is requested that is not present in the cached JWK set.
    #[tokio::test]
    async fn test_cache_is_bypassed_for_missing_kid() {
        // Create a mock JWK set containing a single RSA key with `kid` "42".
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

        // Start a mock HTTP server to serve the JWK set.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .expect(2)
            .mount(&mock_server)
            .await;

        // Create a `RemoteJwkSet` with caching enabled.
        let remote_jwk_set = RemoteJwkSet::builder(mock_server.uri().parse().unwrap())
            .with_cache(std::time::Duration::from_secs(60))
            .build();

        // Request the jwk for `kid` 42 to populate the cache.
        assert!(remote_jwk_set.find("42").await.unwrap().is_some());
        // Request another `kid` that's not present in the JWK set, to bypass the cache and thereby trigger another
        // request to obtain the JWK set.
        assert!(remote_jwk_set.find("43").await.unwrap().is_none());
    }
}
