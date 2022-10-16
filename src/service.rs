use super::{AuthenticationMiddleware, Authority};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, FromRequest, Handler,
};
use futures_util::future;
use serde::{de::DeserializeOwned, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

pub struct AuthService<Claims, Algorithm, Guard, Args>
where
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
    Algorithm: jwt_compact::Algorithm,
{
    pub inner: Authority<Claims, Algorithm>,
    guard: Guard,
    _claim: PhantomData<Claims>,
    _args: PhantomData<Args>,
}

impl<Claims, Algorithm, Guard, Args> AuthService<Claims, Algorithm, Guard, Args>
where
    Claims: DeserializeOwned,
    Algorithm: jwt_compact::Algorithm,
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
{
    pub fn new(authority: Authority<Claims, Algorithm>, guard: Guard) -> AuthService<Claims, Algorithm, Guard, Args> {
        AuthService {
            inner: authority,
            guard,
            _claim: PhantomData,
            _args: PhantomData,
        }
    }
}

impl<S, B, Claims, Algorithm, Guard, Args> Transform<S, ServiceRequest> for AuthService<Claims, Algorithm, Guard, Args>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    B: MessageBody,
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest + 'static,
{
    type Response =
        <AuthenticationMiddleware<S, Claims, Algorithm, Guard, Args> as Service<ServiceRequest>>::Response;
    type Error = Error;
    type Transform = AuthenticationMiddleware<S, Claims, Algorithm, Guard, Args>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(AuthenticationMiddleware::new(
            Rc::new(service),
            Arc::new(self.inner.clone()),
            self.guard.clone(),
        ))
    }
}
