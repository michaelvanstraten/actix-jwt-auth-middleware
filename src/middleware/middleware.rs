use crate::Authority;

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse};
use actix_web::{Error as ActixWebError, FromRequest, Handler};
use jwt_compact::Algorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[doc(hidden)]
pub struct AuthenticationMiddleware<S, Claims, Algo, ReAuth, Args>
where
    Algo: Algorithm + Clone,
    Algo::SigningKey: Clone,
{
    pub service: Rc<S>,
    pub inner: Arc<Authority<Claims, Algo, ReAuth, Args>>,
    claims_marker: PhantomData<Claims>,
}

impl<S, Claims, Algorithm, ReAuth, Args>
    AuthenticationMiddleware<S, Claims, Algorithm, ReAuth, Args>
where
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
{
    pub fn new(service: Rc<S>, inner: Arc<Authority<Claims, Algorithm, ReAuth, Args>>) -> Self {
        Self {
            service,
            inner,
            claims_marker: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algo, ReAuth, Args> Service<ServiceRequest>
    for AuthenticationMiddleware<S, Claims, Algo, ReAuth, Args>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = ActixWebError> + 'static,
    Claims: Serialize + DeserializeOwned + 'static,
    Algo: Algorithm + Clone + 'static,
    Algo::SigningKey: Clone,
    Body: MessageBody,
    ReAuth: Handler<Args, Output = Result<(), ActixWebError>>,
    Args: FromRequest + 'static,
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
                Ok(token_update) => service.call(req).await.and_then(|mut res| {
                    if let Some(token_update) = token_update {
                        if let Some(auth_cookie) = token_update.access_cookie {
                            res.response_mut().add_cookie(&auth_cookie)?
                        }
                        if let Some(refresh_cookie) = token_update.refresh_cookie {
                            res.response_mut().add_cookie(&refresh_cookie)?
                        }
                    }
                    Ok(res)
                }),
                Err(err) => Err(err.into()),
            }
        })
    }
}
