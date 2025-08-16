use std::{
    future::Future,
    task::{Context, Poll},
    time::Duration,
};

use futures::future::BoxFuture;
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
pub struct JwksCacheService<S> {
    inner: S,
    cache: moka::future::Cache<String, JwkSet>,
    state: PollState,
}

enum PollState {
    New,
    CachePending {
        cache_future: BoxFuture<'static, Option<JwkSet>>,
    },
    CacheReady {
        jwks: JwkSet,
    },
    InnerPending,
    InnerReady,
}

impl<S> Clone for JwksCacheService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cache: self.cache.clone(),
            state: PollState::New, // Reset state when cloning
        }
    }
}

impl<S> Service<()> for JwksCacheService<S>
where
    S: Service<(), Response = JwkSet, Error = Error> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = JwkSet;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.state {
            PollState::New => {
                // Create a Send future for the cache lookup
                let cache = self.cache.clone();
                let mut cache_future = Box::pin(async move { cache.get("jwk_set").await });

                match cache_future.as_mut().poll(cx) {
                    Poll::Ready(Some(jwks)) => {
                        // Cache is ready, transition to CacheReady state.
                        self.state = PollState::CacheReady { jwks };
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(None) => {
                        // If the cache does not contain any JwkSet (either to not having been populated yet or due to
                        // having run into its TTL), immediately poll the inner service.
                        match self.inner.poll_ready(cx) {
                            Poll::Ready(Ok(())) => {
                                self.state = PollState::InnerReady;
                                Poll::Ready(Ok(()))
                            }
                            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                            Poll::Pending => {
                                self.state = PollState::InnerPending;
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        self.state = PollState::CachePending { cache_future };
                        Poll::Pending
                    }
                }
            }
            PollState::CachePending { cache_future } => {
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
            PollState::InnerPending => match self.inner.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    self.state = PollState::InnerReady;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            },
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
            PollState::InnerReady => {
                // If we are ready to call the inner service, do it.
                let inner_clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, inner_clone);
                let cache = self.cache.clone();
                self.state = PollState::New; // Reset for next call
                Box::pin(async move {
                    // Call the inner service to fetch the JwkSet and cache it.
                    let jwks = inner.call(()).await?;
                    cache.insert("jwk_set".to_string(), jwks.clone()).await;
                    Ok(jwks)
                })
            }
            _ => {
                // If we are not in a ready state, we return a pending future.
                Box::pin(async { Err(Error::JwkSetCacheError) })
            }
        }
    }
}
