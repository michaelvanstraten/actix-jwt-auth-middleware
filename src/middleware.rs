use super::Authority;
use actix_web::{
    body::MessageBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse},
    Error,
};
use futures_util::future::{FutureExt as _, LocalBoxFuture};
use serde::{de::DeserializeOwned, Serialize};
use std::{rc::Rc, sync::Arc};

pub struct AuthenticationMiddleware<S, C> {
    pub service: Rc<S>,
    pub inner: Arc<Authority<C>>,
}

impl<S, B, C> Service<ServiceRequest> for AuthenticationMiddleware<S, C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    C: Serialize + DeserializeOwned + Clone + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let service = Rc::clone(&self.service);

        async move {
            match inner.verify_service_request(req) {
                Ok(req) => service.call(req).await,
                Err(err) => Err(err.into()),
            }
        }
        .boxed_local()
    }
}