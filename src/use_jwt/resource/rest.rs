use crate::RestAuthenticationService;
use crate::RestAuthority;

use actix_web::dev::ServiceFactory;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Resource;
use actix_web::Error as ActixError;
use jwt_compact::Algorithm as JWTAlgorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait JWTRestOnResource<Claims, Algorithm>
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: JWTAlgorithm + Clone,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    fn use_jwt(
        self,
        rest_authority: RestAuthority<Claims, Algorithm>,
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

impl<Claims, Algorithm> JWTRestOnResource<Claims, Algorithm> for Resource
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: JWTAlgorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    fn use_jwt(
        self,
        rest_authority: RestAuthority<Claims, Algorithm>,
    ) -> Resource<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = ActixError,
            InitError = (),
        >,
    > {
        self.wrap(RestAuthenticationService::new(rest_authority.clone()))
    }
}
