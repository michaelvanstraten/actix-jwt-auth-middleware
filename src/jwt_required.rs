use actix_web::{FromRequest, Handler, Scope, dev::{ServiceFactory, ServiceRequest, ServiceResponse}, body::BoxBody};
use serde::{de::DeserializeOwned, Serialize};

use crate::{AuthService, Authority};
pub trait JWTRequired<Claims, Algorithm, ReAuthorizer, Args>
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    ReAuthorizer: Handler<Args, Output = Result<(), actix_web::Error>> + Clone,
    Args: FromRequest + Clone
{
    fn jwt_required(self, authority: Authority<Claims, Algorithm, ReAuthorizer, Args>) -> Scope<impl ServiceFactory<ServiceRequest, Config = (), Response = ServiceResponse<BoxBody>, Error = actix_web::error::Error, InitError = ()>>;
}

impl<Claims, Algorithm, ReAuthorizer, Args> JWTRequired<Claims, Algorithm, ReAuthorizer, Args> for Scope
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    ReAuthorizer: Handler<Args, Output = Result<(), actix_web::Error>> + Clone,
    Args: FromRequest + Clone + 'static
{
    fn jwt_required(self, authority: Authority<Claims, Algorithm, ReAuthorizer, Args>) -> Scope<impl ServiceFactory<ServiceRequest, Config = (), Response = ServiceResponse, Error = actix_web::Error, InitError = ()>> {
        self.wrap(AuthService::new(authority.clone(), || async move { true }))
    }
}