use super::Authority;
use actix_web::{
    body::MessageBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse},
    Error, FromRequest, Handler,
};
use futures_util::future::{FutureExt as _, LocalBoxFuture};
use serde::{de::DeserializeOwned, Serialize};
use std::{rc::Rc, sync::Arc};

pub struct AuthenticationMiddleware<S, C, F, Args>
where
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest,
{
    pub service: Rc<S>,
    pub inner: Arc<Authority<C, F, Args>>,
}

impl<S, B, C, F, Args> Service<ServiceRequest> for AuthenticationMiddleware<S, C, F, Args>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    C: Serialize + DeserializeOwned + Clone + 'static,
    B: MessageBody,
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let service = Rc::clone(&self.service);

        async move {
            match inner.verify_service_request(req).await {
                Ok(req) => service.call(req).await,
                Err(err) => Err(err.into()),
            }
        }
        .boxed_local()
    }
}
