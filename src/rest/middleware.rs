use crate::rest::RestAuthority;

use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::forward_ready;
use actix_web::dev::Service;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error;
use futures_util::future::FutureExt as _;
use futures_util::future::LocalBoxFuture;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[doc(hidden)]
pub struct RestAuthenticationMiddleware<S, Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub service: Rc<S>,
    pub inner: Arc<RestAuthority<Claims, Algorithm>>,
    _claims: PhantomData<Claims>,
}

impl<S, Claims, Algorithm> RestAuthenticationMiddleware<S, Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub fn new(service: Rc<S>, inner: Arc<RestAuthority<Claims, Algorithm>>) -> Self {
        Self {
            service,
            inner,
            _claims: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm> Service<ServiceRequest>
    for RestAuthenticationMiddleware<S, Claims, Algorithm>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
{
    type Response = ServiceResponse<Body>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let service = Rc::clone(&self.service);

        async move {
            match inner.verify_service_request(&mut req).await {
                Ok(()) => service.call(req).await.and_then(|res| Ok(res)),
                Err(err) => Err(err.into()),
            }
        }
        .boxed_local()
    }
}
