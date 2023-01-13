use crate::AuthenticationService;
use crate::Authority;

use actix_web::dev::ServiceFactory;
use actix_web::dev::ServiceRequest;
use actix_web::web::Data;
use actix_web::App;
use actix_web::Error as ActixError;
use actix_web::FromRequest;
use actix_web::Handler;
use actix_web::Scope;
use jwt_compact::Algorithm as JWTAlgorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

macro_rules! impl_use_jwt_for {
    ($type:ident, $trait_name:ident) => {
        pub trait $trait_name<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>
        where
            Claims: Serialize + DeserializeOwned + Clone + 'static,
            Algorithm: JWTAlgorithm + Clone,
            Algorithm::SigningKey: Clone,
            Algorithm::VerifyingKey: Clone,
            RefreshAuthorizer:
                Handler<RefreshAuthorizerArgs, Output = Result<(), actix_web::Error>> + Clone,
            RefreshAuthorizerArgs: FromRequest + Clone + 'static,
        {
            fn use_jwt(
                self,
                authority: Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>,
                scope: Scope,
            ) -> Self;
        }

        impl<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs, T>
            $trait_name<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs> for $type<T>
        where
            T: ServiceFactory<ServiceRequest, Config = (), Error = ActixError, InitError = ()>,
            Claims: Serialize + DeserializeOwned + Clone + 'static,
            Algorithm: JWTAlgorithm + Clone + 'static,
            Algorithm::SigningKey: Clone,
            Algorithm::VerifyingKey: Clone,
            RefreshAuthorizer:
                Handler<RefreshAuthorizerArgs, Output = Result<(), actix_web::Error>> + Clone,
            RefreshAuthorizerArgs: FromRequest + Clone + 'static,
        {
            fn use_jwt(
                self,
                authority: Authority<Claims, Algorithm, RefreshAuthorizer, RefreshAuthorizerArgs>,
                scope: Scope,
            ) -> Self {
                if let Some(cookie_signer) = authority.cookie_signer() {
                    self.app_data(Data::new(cookie_signer))
                } else {
                    self
                }
                .service(scope.wrap(AuthenticationService::new(authority)))
            }
        }
    };
}

impl_use_jwt_for!(App, UseJWTOnApp);
impl_use_jwt_for!(Scope, UseJWTOnScope);
