use super::{AuthenticationMiddleware, Authority};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, FromRequest, Handler,
};
use futures_util::future;
use serde::{de::DeserializeOwned, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

pub struct AuthService<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub inner: Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>,
    _claims: PhantomData<Claims>,
}

impl<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
    AuthService<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    Claims: DeserializeOwned,
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub fn new(
        authority: Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>,
    ) -> AuthService<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs> {
        AuthService {
            inner: authority,
            _claims: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
    Transform<S, ServiceRequest>
    for AuthService<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
    RefreshAuthorizer:
        Handler<RefreshAuthorizerArgs, Output = Result<(), actix_web::Error>> + Clone,
    RefreshAuthorizerArgs: FromRequest + Clone + 'static,
{
    type Response = <AuthenticationMiddleware<
        S,
        Claims,
        Algorithm,
        RefreshAuthorizer,
        RefreshAuthorizerArgs,
    > as Service<ServiceRequest>>::Response;
    type Error = Error;
    type Transform =
        AuthenticationMiddleware<S, Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(AuthenticationMiddleware::new(
            Rc::new(service),
            Arc::new(self.inner.clone()),
        ))
    }
}