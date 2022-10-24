use crate::{AuthService, Authority};

use actix_web::{
    body::BoxBody,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    FromRequest, Handler,
};
use serde::{de::DeserializeOwned, Serialize};

macro_rules! impl_use_jwt {
    ($type:ident $(,$generics:ident)*) => {
        pub trait $type<Claims, Algorithm, ReAuthorizer, Args, $($generics),*>
        where
            Claims: Serialize + DeserializeOwned + Clone + 'static,
            Algorithm: jwt_compact::Algorithm + Clone,
            Algorithm::SigningKey: Clone,
            Algorithm::VerifyingKey: Clone,
            ReAuthorizer: Handler<Args, Output = Result<(), actix_web::Error>> + Clone,
            Args: FromRequest + Clone,
            $($generics: ServiceFactory<ServiceRequest, Response = ServiceResponse, Config = (), Error = actix_web::error::Error, InitError = ()> + 'static,),*
        {
            fn use_jwt(
                self,
                authority: Authority<Claims, Algorithm, ReAuthorizer, Args>,
            ) -> actix_web::$type<
                impl ServiceFactory<
                    ServiceRequest,
                    Config = (),
                    Response = ServiceResponse<BoxBody>,
                    Error = actix_web::Error,
                    InitError = (),
                >,
            >;
        }

        impl<Claims, Algorithm, ReAuthorizer, Args, $($generics),*>
            $type<Claims, Algorithm, ReAuthorizer, Args, $($generics),*> for actix_web::$type $(<$generics>)*
        where
            Claims: Serialize + DeserializeOwned + Clone + 'static,
            Algorithm: jwt_compact::Algorithm + Clone + 'static,
            Algorithm::SigningKey: Clone,
            Algorithm::VerifyingKey: Clone,
            ReAuthorizer: Handler<Args, Output = Result<(), actix_web::Error>> + Clone,
            Args: FromRequest + Clone + 'static,
            $($generics: ServiceFactory<ServiceRequest, Response = ServiceResponse, Config = (), Error = actix_web::error::Error, InitError = ()> + 'static,),*
        {
            fn use_jwt(
                self,
                authority: Authority<Claims, Algorithm, ReAuthorizer, Args>,
            ) -> actix_web::$type<
                impl ServiceFactory<
                    ServiceRequest,
                    Config = (),
                    Response = ServiceResponse,
                    Error = actix_web::Error,
                    InitError = (),
                >
            > {
                self.wrap(AuthService::new(authority.clone()))
            }
        }
    }
}

impl_use_jwt!(Scope);
impl_use_jwt!(Resource);
impl_use_jwt!(App, T);
