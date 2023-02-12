pub(crate) use crate::rest::ApiAuthority;

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::forward_ready;
use actix_web::dev::Service;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error;
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
    pub inner: Arc<ApiAuthority<Claims, Algorithm>>,
    _claims: PhantomData<Claims>,
}

impl<S, Claims, Algorithm> RestAuthenticationMiddleware<S, Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub fn new(service: Rc<S>, inner: Arc<ApiAuthority<Claims, Algorithm>>) -> Self {
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
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            match inner.verify_service_request(&mut req).await {
                Ok(()) => service.call(req).await.and_then(|res| Ok(res)),
                Err(err) => Err(err.into()),
            }
        })
    }
}
