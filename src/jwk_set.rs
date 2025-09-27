use jsonwebtoken::jwk::Jwk;

use crate::{remote_jwk_set::RemoteJwkSet, Error};

/// Convenience wrapper around either a [`RemoteJwkSet`] or a local [`jsonwebtoken::jwk::JwkSet`].
#[derive(Clone)]
pub enum JwkSet {
    Local(jsonwebtoken::jwk::JwkSet),
    Remote(RemoteJwkSet),
}

impl JwkSet {
    pub async fn find(&self, kid: &str) -> Result<Option<Jwk>, Error> {
        match self {
            JwkSet::Local(local_jwk_set) => Ok(local_jwk_set.find(kid).cloned()),
            JwkSet::Remote(remote_jwk_set) => remote_jwk_set.find(kid).await,
        }
    }
}

impl From<jsonwebtoken::jwk::JwkSet> for JwkSet {
    fn from(jwk_set: jsonwebtoken::jwk::JwkSet) -> Self {
        JwkSet::Local(jwk_set)
    }
}

impl From<RemoteJwkSet> for JwkSet {
    fn from(remote_jwk_set: RemoteJwkSet) -> Self {
        JwkSet::Remote(remote_jwk_set)
    }
}
