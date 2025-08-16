use std::{
    task::{Context, Poll},
    time::Duration,
};

use futures::future::BoxFuture;
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use tower::{util::BoxCloneService, Service, ServiceBuilder, ServiceExt};
use url::Url;

use crate::{jwks_cache::JwksCacheLayer, Error};

#[derive(Clone)]
pub struct RemoteJwkSet {
    service_tower: BoxCloneService<(), JwkSet, Error>,
}

impl RemoteJwkSet {
    pub fn new(url: Url) -> Self {
        let url = url.clone();
        let http_client = Client::new();
        let service_tower = ServiceBuilder::new()
            .layer(JwksCacheLayer::new())
            .map_err(|_| Error::JwkSetRateLimitError)
            .buffer(1024)
            .rate_limit(5, Duration::from_secs(1))
            .service(JwkSetRequestService { http_client, url });

        Self {
            service_tower: BoxCloneService::new(service_tower),
        }
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
