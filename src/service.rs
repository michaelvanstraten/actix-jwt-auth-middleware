use super::{AuthenticationMiddleware, Authority};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future;
use serde::{de::DeserializeOwned, Serialize};
use std::{rc::Rc, sync::Arc};

pub struct AuthService<C> {
    pub inner: Authority<C>,
}

impl<C> AuthService<C>
where
    C: DeserializeOwned,
{
    pub fn new(authority: Authority<C>) -> AuthService<C> {
        AuthService { inner: authority }
    }
}

impl<S, B, C> Transform<S, ServiceRequest> for AuthService<C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    C: Serialize + DeserializeOwned + Clone + 'static,
    B: MessageBody,
{
    type Response = <AuthenticationMiddleware<S, C> as Service<ServiceRequest>>::Response;
    type Error = Error;
    type Transform = AuthenticationMiddleware<S, C>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(AuthenticationMiddleware {
            service: Rc::new(service),
            inner: Arc::new(self.inner.clone()),
        })
    }
}