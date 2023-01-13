use crate::RestAuthenticationService;
use crate::RestAuthority;

use actix_web::dev::ServiceFactory;
use actix_web::dev::ServiceRequest;
use actix_web::App;
use actix_web::Error as ActixError;
use actix_web::Scope;
use jwt_compact::Algorithm as JWTAlgorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

macro_rules! impl_use_jwt_rest_for {
    ($type:ident, $trait_name:ident) => {
        pub trait $trait_name<Claims, Algorithm>
        where
            Claims: Serialize + DeserializeOwned + Clone + 'static,
            Algorithm: JWTAlgorithm + Clone,
            Algorithm::SigningKey: Clone,
            Algorithm::VerifyingKey: Clone,
        {
            fn use_jwt_rest(
                self,
                rest_authority: RestAuthority<Claims, Algorithm>,
                scope: Scope,
            ) -> Self;
        }

        impl<Claims, Algorithm, T> $trait_name<Claims, Algorithm> for $type<T>
        where
            T: ServiceFactory<ServiceRequest, Config = (), Error = ActixError, InitError = ()>,
            Claims: Serialize + DeserializeOwned + Clone + 'static,
            Algorithm: JWTAlgorithm + Clone + 'static,
            Algorithm::SigningKey: Clone,
            Algorithm::VerifyingKey: Clone,
        {
            fn use_jwt_rest(
                self,
                rest_authority: RestAuthority<Claims, Algorithm>,
                scope: Scope,
            ) -> Self {
                self.service(scope.wrap(RestAuthenticationService::new(rest_authority)))
            }
        }
    };
}

impl_use_jwt_rest_for!(App, UseJWTRestOnApp);
impl_use_jwt_rest_for!(Scope, UseJWTRestOnScope);
