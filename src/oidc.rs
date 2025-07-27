use http_cache_reqwest::{Cache, CacheMode, HttpCache, HttpCacheOptions, MokaManager};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::Error;

// TODO `jwks_uri` seems to be different on okta and we should probably retrieve it from the openid-configuration endpoint https://stackoverflow.com/questions/77948299/okta-oidc-where-how-do-i-find-my-jwks-uri
/// OpenID Connect API endpoint for retrieving the JWK set.
///
/// Note that this endpoint is not officially documented in the OpenID connect standard. Following the standard, the
/// correct way to request the OIDC provider's JWKs is by first retrieving the provider's metadata from the
/// `/.well-known/openid-configuration` endpoint, extracting the `jwks_uri` field from the corresponding JSON response
/// and finally requesting the JWKs from there.
///
/// However, most providers seem to adhere to the convention of providing their JWKs at `/.well-known/jwks.json`.
/// Hence, we avoid an additional redirection via `/.well-known/openid-configuration` and instead retrieve the JWKs
/// directly via this endpoint.
//const OIDC_JWKS_ENDPOINT: &str = "/.well-known/jwks.json";

pub const OIDC_CONFIGURATION_ENDPOINT: &str = ".well-known/openid-configuration";

pub struct OidcProvider {
    issuer_url: Url,
    http_client: ClientWithMiddleware,
}

impl OidcProvider {
    pub fn new(issuer_url: Url) -> Self {
        let http_client = ClientBuilder::new(Client::new())
            .with(Cache(HttpCache {
                mode: CacheMode::Default,
                manager: MokaManager::default(),
                options: HttpCacheOptions::default(),
            }))
            .build();

        Self {
            issuer_url,
            http_client,
        }
    }

    pub async fn configuration(&self) -> Result<OpenIdConfiguration, Error> {
        let openid_configuration_url = self.issuer_url.join(OIDC_CONFIGURATION_ENDPOINT).unwrap();
        let openid_configuration = self
            .http_client
            .get(openid_configuration_url)
            .send()
            .await
            .unwrap()
            .json::<OpenIdConfiguration>()
            .await
            .unwrap();
        Ok(openid_configuration)
    }

    pub fn issuer(&self) -> &Url {
        &self.issuer_url
    }

    pub async fn jwks(&self) -> Result<JwkSet, Error> {
        let openid_configuration = self.configuration().await.unwrap();

        let jwks_url = Url::parse(&openid_configuration.jwks_uri).unwrap();

        let jwks_response = self
            .http_client
            .get(jwks_url)
            .send()
            .await
            .map_err(|_| Error::TokenValidationError)?;
        let jwks: JwkSet = serde_json::from_str(
            &jwks_response
                .text()
                .await
                .map_err(|_| Error::TokenValidationError)?,
        )
        .map_err(|_| Error::TokenValidationError)?;
        Ok(jwks)
    }
}

/// Response payload of the OpenID provider's `.well-known/openid-configuration` endpoint.
///
/// Only covers those fields that are relevant in our context.
#[derive(Serialize, Deserialize)]
pub struct OpenIdConfiguration {
    /// The URI where to retrieve the OIDC provider's signing keys.
    pub jwks_uri: String,
}
