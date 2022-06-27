use super::{AuthenticationMiddleware, Authority};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, Handler, FromRequest,
};
use futures_util::future;
use serde::{de::DeserializeOwned, Serialize};
use std::{rc::Rc, sync::Arc};

pub struct AuthService<C, F, Args>
where
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest,
{
    pub inner: Authority<C, F, Args>,
}

impl<C, F, Args> AuthService<C, F, Args>
where
    C: DeserializeOwned,
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest,
{
    pub fn new(authority: Authority<C, F, Args>) -> AuthService<C, F, Args> {
        AuthService { inner: authority }
    }
}

impl<S, B, C, F, Args> Transform<S, ServiceRequest> for AuthService<C, F, Args>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    C: Serialize + DeserializeOwned + Clone + 'static,
    B: MessageBody,
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest + 'static,
{
    type Response = <AuthenticationMiddleware<S, C, F, Args> as Service<ServiceRequest>>::Response;
    type Error = Error;
    type Transform = AuthenticationMiddleware<S, C, F, Args>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(AuthenticationMiddleware {
            service: Rc::new(service),
            inner: Arc::new(self.inner.clone()),
        })
    }
}
