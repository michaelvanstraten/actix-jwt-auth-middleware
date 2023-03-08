use crate::AuthenticationService;
use crate::Authority;

use actix_web::dev::ServiceFactory;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error as ActixWebError;
use actix_web::FromRequest;
use actix_web::Handler;
use actix_web::Resource;
use jwt_compact::Algorithm as JWTAlgorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

/**
    This trait gives the ability to call [`Self::use_jwt`] on the implemented type.

    It is currently behind a features flag, `use_jwt_on_resource`, because it uses some experimental rust features.
*/
pub trait UseJWTOnResource<Claims, Algorithm, ReAuth, Args>
where
    Claims: Serialize + DeserializeOwned + 'static,
    Algorithm: JWTAlgorithm + Clone,
    Algorithm::SigningKey: Clone,
    ReAuth: Handler<Args, Output = Result<(), ActixWebError>>,
    Args: FromRequest,
{
    /**
        Calls `wrap` on the `scope` will passing the `authority`.
        Then it adds the `scope` as a service on `self`.

        If there is a [`crate::TokenSigner`] set on the `authority`, it is clone it and adds it as app data on `self`.
    */
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

impl<Claims, Algorithm, ReAuth, Args> UseJWTOnResource<Claims, Algorithm, ReAuth, Args> for Resource
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
