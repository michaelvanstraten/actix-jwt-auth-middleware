use crate::AuthenticationService;
use crate::Authority;

use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{Error as ActixWebError, FromRequest, Handler, Resource};
use jwt_compact::Algorithm as JWTAlgorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait JWTOnResource<Claims, Algorithm, ReAuth, Args>
where
    Claims: Serialize + DeserializeOwned + 'static,
    Algorithm: JWTAlgorithm + Clone,
    Algorithm::SigningKey: Clone,
    ReAuth: Handler<Args, Output = Result<(), ActixWebError>>,
    Args: FromRequest,
{
    fn use_jwt(
        self,
        authority: Authority<Claims, Algorithm, ReAuth, Args>,
    ) -> Resource<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = ActixWebError,
            InitError = (),
        >,
    >;
}

impl<Claims, Algorithm, ReAuth, Args> JWTOnResource<Claims, Algorithm, ReAuth, Args> for Resource
where
    Claims: Serialize + DeserializeOwned + 'static,
    Algorithm: JWTAlgorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    ReAuth: Handler<Args, Output = Result<(), ActixWebError>>,
    Args: FromRequest + 'static,
{
    fn use_jwt(
        self,
        authority: Authority<Claims, Algorithm, ReAuth, Args>,
    ) -> Resource<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = ActixWebError,
            InitError = (),
        >,
    > {
        self.wrap(AuthenticationService::new(authority))
    }
}
