use crate::AuthError;

use super::Authority;
use actix_web::{
    body::MessageBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse},
    Error, FromRequest, Handler, HttpMessage,
};
use futures_util::future::{FutureExt as _, LocalBoxFuture};
use serde::{de::DeserializeOwned, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

pub struct AuthenticationMiddleware<
    S,
    Claims,
    Algorithm,
    Guard,
    Args,
    ReAuthorizer,
    ReAuthorizerArgs,
> where
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub service: Rc<S>,
    pub inner: Arc<Authority<Claims, Algorithm, ReAuthorizer, ReAuthorizerArgs>>,
    guard: Guard,
    _claim: PhantomData<Claims>,
    _args: PhantomData<Args>,
}

impl<S, Claims, Algorithm, Guard, Args, ReAuthorizer, ReAuthorizerArgs>
    AuthenticationMiddleware<
        S,
        Claims,
        Algorithm,
        Guard,
        Args,
        ReAuthorizer,
        ReAuthorizerArgs,
    >
where
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub fn new(
        service: Rc<S>,
        inner: Arc<Authority<Claims, Algorithm, ReAuthorizer, ReAuthorizerArgs>>,
        guard: Guard,
    ) -> Self {
        Self {
            service,
            inner,
            guard,
            _claim: PhantomData,
            _args: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm, Guard, Args, ReAuthorizer, ReAuthorizerArgs>
    Service<ServiceRequest>
    for AuthenticationMiddleware<
        S,
        Claims,
        Algorithm,
        Guard,
        Args,
        ReAuthorizer,
        ReAuthorizerArgs,
    >
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool> + 'static,
    Args: FromRequest + 'static,
    ReAuthorizer: Handler<ReAuthorizerArgs, Output = Result<(), actix_web::Error>> + Clone,
    ReAuthorizerArgs: FromRequest + Clone + 'static,
{
    type Response = ServiceResponse<Body>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let service = Rc::clone(&self.service);
        let guard = self.guard.clone();

        async move {
            match inner.verify_service_request(req).await {
                Ok((mut req, token_update)) => {
                    let (mut_req, mut payload) = req.parts_mut();
                    match Args::from_request(&mut_req, &mut payload).await {
                        Ok(args) => {
                            if guard.call(args).await == true {
                                service.call(req).await.and_then(|mut res| {
                                    if let Some(token_update) = token_update {
                                        if let Some(auth_cookie) = token_update.auth_cookie {
                                            res.response_mut().add_cookie(&auth_cookie)?
                                        }
                                        if let Some(refresh_cookie) = token_update.refresh_cookie {
                                            res.response_mut().add_cookie(&refresh_cookie)?
                                        }
                                    }
                                    Ok(res)
                                })
                            } else {
                                req.extensions_mut().remove::<Claims>();
                                Err(AuthError::Unauthorized.into())
                            }
                        }
                        Err(err) => Err(err.into()),
                    }
                }
                Err(err) => Err(err.into()),
            }
        }
        .boxed_local()
    }
}
