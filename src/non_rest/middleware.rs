use crate::Authority;

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
use actix_web::FromRequest;
use actix_web::Handler;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[doc(hidden)]
pub struct AuthenticationMiddleware<S, Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub service: Rc<S>,
    pub inner: Arc<Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>>,
    claims_marker: PhantomData<Claims>,
}

impl<S, Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
    AuthenticationMiddleware<S, Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    pub fn new(
        service: Rc<S>,
        inner: Arc<Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>>,
    ) -> Self {
        Self {
            service,
            inner,
            claims_marker: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs> Service<ServiceRequest>
    for AuthenticationMiddleware<S, Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
    RefreshAuthorizer:
        Handler<RefreshAuthorizerArgs, Output = Result<(), actix_web::Error>> + Clone,
    RefreshAuthorizerArgs: FromRequest + Clone + 'static,
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
                        if let Some(auth_cookie) = token_update.auth_cookie {
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
