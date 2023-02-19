use crate::{AuthenticationService, Authority};

use actix_web::dev::ServiceFactory;
use actix_web::dev::ServiceRequest;
use actix_web::web::Data;
use actix_web::App;
use actix_web::Error as ActixWebError;
use actix_web::FromRequest;
use actix_web::Handler;
use actix_web::Scope;
use jwt_compact::Algorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

macro_rules! impl_use_jwt_for {
    ($type:ident, $trait_name:ident) => {
        /**
            This trait gives the ability to call [`Self::use_jwt`] on the implemented type.
        */
        pub trait $trait_name<Claims, Algo, ReAuth, Args>
        where
            Claims: Serialize + DeserializeOwned + 'static,
            Algo: Algorithm + Clone,
            Algo::SigningKey: Clone,
            ReAuth: Handler<Args, Output = Result<(), ActixWebError>>,
            Args: FromRequest + 'static,
        {
            /**
                Calls `wrap` on the `scope` will passing the `authority`.
                Then it adds the `scope` as a service on `self`.

                If there is a [`crate::TokenSigner`] set on the `authority`, it is clone it and adds it as app data on `self`.
            */
            fn use_jwt(
                self,
                authority: Authority<Claims, Algo, ReAuth, Args>,
                scope: Scope,
            ) -> Self;
        }

        impl<Claims, Algo, ReAuth, Args, T> $trait_name<Claims, Algo, ReAuth, Args> for $type<T>
        where
            T: ServiceFactory<ServiceRequest, Config = (), Error = ActixWebError, InitError = ()>,
            Claims: Serialize + DeserializeOwned + 'static,
            Algo: Algorithm + Clone + 'static,
            Algo::SigningKey: Clone,
            ReAuth: Handler<Args, Output = Result<(), ActixWebError>> + Clone,
            Args: FromRequest + 'static,
        {
            fn use_jwt(
                self,
                authority: Authority<Claims, Algo, ReAuth, Args>,
                scope: Scope,
            ) -> Self {
                if let Some(token_signer) = authority.token_signer() {
                    self.app_data(Data::new(token_signer))
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
