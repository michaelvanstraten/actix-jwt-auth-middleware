use crate::AuthenticationService;
use crate::Authority;

use actix_web::dev::ServiceFactory;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error as ActixError;
use actix_web::FromRequest;
use actix_web::Handler;
use actix_web::Resource;
use jwt_compact::Algorithm as JWTAlgorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait JWTOnResource<Claims, Algorithm, ReAuthorizer, Args>
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: JWTAlgorithm + Clone,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    ReAuthorizer: Handler<Args, Output = Result<(), ActixError>> + Clone,
    Args: FromRequest + Clone,
{
    fn use_jwt(
        self,
        authority: Authority<Claims, Algorithm, ReAuthorizer, Args>,
    ) -> Resource<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = ActixError,
            InitError = (),
        >,
    >;
}

impl<Claims, Algorithm, ReAuthorizer, Args> JWTOnResource<Claims, Algorithm, ReAuthorizer, Args>
    for Resource
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: JWTAlgorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    ReAuthorizer: Handler<Args, Output = Result<(), ActixError>> + Clone,
    Args: FromRequest + Clone + 'static,
{
    fn use_jwt(
        self,
        authority: Authority<Claims, Algorithm, ReAuthorizer, Args>,
    ) -> Resource<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = ActixError,
            InitError = (),
        >,
    > {
        self.wrap(AuthenticationService::new(authority.clone()))
    }
}
