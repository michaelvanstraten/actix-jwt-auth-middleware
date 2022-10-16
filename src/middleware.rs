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

pub struct AuthenticationMiddleware<S, Claims, Algorithm, Guard, Args>
where
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
    Algorithm: jwt_compact::Algorithm,
{
    pub service: Rc<S>,
    pub inner: Arc<Authority<Claims, Algorithm>>,
    guard: Guard,
    _claim: PhantomData<Claims>,
    _args: PhantomData<Args>,
}

impl<S, Claims, Algorithm, Guard, Args> AuthenticationMiddleware<S, Claims, Algorithm, Guard, Args>
where
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool>,
    Args: FromRequest,
    Algorithm: jwt_compact::Algorithm,
{
    pub fn new(service: Rc<S>, inner: Arc<Authority<Claims, Algorithm>>, guard: Guard) -> Self {
        Self {
            service,
            inner,
            guard,
            _claim: PhantomData,
            _args: PhantomData,
        }
    }
}

impl<S, B, Claims, Algorithm, Guard, Args> Service<ServiceRequest>
    for AuthenticationMiddleware<S, Claims, Algorithm, Guard, Args>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + 'static,
    B: MessageBody,
    Guard: Handler<Args>,
    Guard::Output: PartialEq<bool> + 'static,
    Args: FromRequest + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let service = Rc::clone(&self.service);
        let guard = self.guard.clone();

        async move {
            match inner.verify_service_request(req).await {
                Ok(mut req) => {
                    let (mut_req, mut payload) = req.parts_mut();
                    match Args::from_request(&mut_req, &mut payload).await {
                        Ok(args) => {
                            if guard.call(args).await == true {
                                service.call(req).await
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
