use std::{
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::BoxFuture, FutureExt};
use jsonwebtoken::jwk::JwkSet;
use tower::{Layer, Service};

use crate::Error;

pub struct JwksCacheLayer {
    cache: moka::future::Cache<String, JwkSet>,
}

impl JwksCacheLayer {
    pub fn new() -> Self {
        let cache = moka::future::Cache::<String, JwkSet>::builder()
            .max_capacity(1)
            .time_to_live(Duration::from_secs(42))
            .build();
        JwksCacheLayer { cache }
    }
}

impl<S> Layer<S> for JwksCacheLayer {
    type Service = JwksCacheService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwksCacheService {
            inner,
            cache: self.cache.clone(),
            state: PollState::New,
        }
    }
}

/// Can safely be cloned and shared across threads since moka internally uses an Arc.
pub struct JwksCacheService<'a, S> {
    inner: S,
    cache: moka::future::Cache<String, JwkSet>,
    state: PollState<'a>,
}

impl<'a, S> Service<()> for JwksCacheService<'a, S>
where
    S: Service<(), Response = JwkSet, Error = Error> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = JwkSet;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.state {
            PollState::New => {
                // If we are in the New state, we need to start the cache future.
                let mut cache_future = self.cache.get("jwk_set").boxed::<'a>();

                match cache_future.as_mut().poll(cx) {
                    Poll::Ready(Some(jwks)) => {
                        // Cache is ready, transition to CacheReady state.
                        self.state = PollState::CacheReady { jwks };
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(None) => {
                        self.state = PollState::InnerPending;
                        Poll::Pending
                    }
                    Poll::Pending => {
                        // Cache is not ready, transition to CachePending state.
                        self.state = PollState::CachePending {
                            cache_future: cache_future,
                        };
                        Poll::Pending
                    }
                }
            }
            PollState::CachePending { ref cache_future } => {
                // If we are waiting for the cache to be ready, we need to poll it.
                match cache_future.as_mut().poll(cx) {
                    Poll::Ready(Some(jwks)) => {
                        // Cache is ready, transition to CacheReady state.
                        self.state = PollState::CacheReady { jwks };
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(None) => {
                        self.state = PollState::InnerPending;
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
            PollState::CacheReady { .. } => {
                // If the cache is ready, we can return Poll::Ready.
                Poll::Ready(Ok(()))
            }
            PollState::InnerPending => todo!(),
            PollState::InnerReady => {
                // If the inner service is ready, we can return Poll::Ready.
                Poll::Ready(Ok(()))
            }
        }
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        match self.state {
            PollState::CacheReady { ref jwks } => {
                // If the cache is ready, we can return the cached JwkSet.
                let jwks = jwks.clone();
                Box::pin(async move { Ok(jwks) })
            }
            PollState::InnerPending => {
                // If we are waiting for the inner service, we need to call it.
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                let cache = self.cache.clone();
                Box::pin(async move {
                    // Call the inner service to fetch the JwkSet and cache it.
                    let jwks = inner.call(()).await?;
                    cache.insert("jwk_set".to_string(), jwks.clone());
                    Ok(jwks)
                })
            }
            _ => {
                // If we are not in a ready state, we return a pending future.
                Box::pin(async { Err(Error::JwkSetRateLimitError) })
            }
        }
    }
}

enum PollState<'a> {
    New,
    CachePending {
        cache_future: BoxFuture<'a, Option<JwkSet>>,
    },
    CacheReady {
        jwks: JwkSet,
    },
    InnerPending,
    InnerReady,
}
