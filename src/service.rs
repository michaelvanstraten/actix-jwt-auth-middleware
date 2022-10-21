use super::{AuthenticationMiddleware, Authority};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, FromRequest, Handler,
};
use futures_util::future;
use serde::{de::DeserializeOwned, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

pub struct AuthService<Claims, Algorithm, Guard, Args, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub inner: Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>,
    guard: Guard,
    _claim: PhantomData<Claims>,
    _args: PhantomData<Args>,
}

impl<Claims, Algorithm, Guard, Args, RefreshAuthorizer, RefreshAuthorizerArgs>
    AuthService<Claims, Algorithm, Guard, Args, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    Claims: DeserializeOwned,
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
{
    pub fn new(
        authority: Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>,
        guard: Guard,
    ) -> AuthService<Claims, Algorithm, Guard, Args, RefreshAuthorizer, RefreshAuthorizerArgs> {
        AuthService {
            inner: authority,
            guard,
            _claim: PhantomData,
            _args: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm, Guard, Args, RefreshAuthorizer, RefreshAuthorizerArgs>
    Transform<S, ServiceRequest>
    for AuthService<Claims, Algorithm, Guard, Args, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest + 'static,
    RefreshAuthorizer: Handler<RefreshAuthorizerArgs, Output = Result<(), actix_web::Error>> + Clone,
    RefreshAuthorizerArgs: FromRequest + Clone + 'static,
{
    type Response = <AuthenticationMiddleware<
        S,
        Claims,
        Algorithm,
        Guard,
        Args,
        RefreshAuthorizer,
        RefreshAuthorizerArgs,
    > as Service<ServiceRequest>>::Response;
    type Error = Error;
    type Transform = AuthenticationMiddleware<
        S,
        Claims,
        Algorithm,
        Guard,
        Args,
        RefreshAuthorizer,
        RefreshAuthorizerArgs,
    >;
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
