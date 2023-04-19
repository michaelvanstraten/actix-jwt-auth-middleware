use crate::AuthenticationServiceInner;
use crate::Authority;

use std::future;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error as ActixWebError, FromRequest, Handler};
use jwt_compact::Algorithm;
use serde::de::DeserializeOwned;
use serde::Serialize;

/**
   A wrapper around the [`Authority`] which can be passed to the `wrap` function of a [`App`](actix_web::App)/[`Scope`](actix_web::Scope) or [`Resource`](actix_web::Resource).

   ## Example
   ```rust
   use actix_jwt_auth_middleware::{TokenSigner, Authority, AuthenticationService};
   use actix_web::{web, App};
   use serde::{Serialize, Deserialize};
   use exonum_crypto::KeyPair;
   use jwt_compact::{alg::Ed25519};

   #[derive(Serialize, Deserialize, Clone)]
   struct User {
       id: u32
   }

   let key_pair = KeyPair::random();

   let authority = Authority::<User, _, _, _>::new()
       .refresh_authorizer(|| async move { Ok(()) })
       .token_signer(Some(
           TokenSigner::new()
               .signing_key(key_pair.secret_key().clone())
               .algorithm(Ed25519)
               .build()
               .unwrap()
       ))
       .verifying_key(key_pair.public_key().clone())
       .build()
       .unwrap();

   let app = App::new()
       .service(
           web::scope("/auth-only")
               .wrap(
                   AuthenticationService::new(authority.clone())
               )
        );
   ```
*/
pub struct AuthenticationService<Claims, Algo, ReAuth, Args>
where
    Algo: Algorithm + Clone,
    Algo::SigningKey: Clone,
{
    inner: Arc<Authority<Claims, Algo, ReAuth, Args>>,
    claims_marker: PhantomData<Claims>,
}

impl<Claims, Algo, ReAuth, Args> AuthenticationService<Claims, Algo, ReAuth, Args>
where
    Claims: DeserializeOwned,
    Algo: Algorithm + Clone,
    Algo::SigningKey: Clone,
{
    /**
        returns a new `AuthenticationService` wrapping the [`Authority`]
    */
    pub fn new(
        authority: Authority<Claims, Algo, ReAuth, Args>,
    ) -> AuthenticationService<Claims, Algo, ReAuth, Args> {
        AuthenticationService {
            inner: Arc::new(authority),
            claims_marker: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algo, ReAuth, Args> Transform<S, ServiceRequest>
    for AuthenticationService<Claims, Algo, ReAuth, Args>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = ActixWebError> + 'static,
    Claims: Serialize + DeserializeOwned + 'static,
    Algo: Algorithm + Clone + 'static,
    Algo::SigningKey: Clone,
    Body: MessageBody,
    ReAuth: Handler<Args, Output = Result<(), ActixWebError>>,
    Args: FromRequest + 'static,
{
    type Response = <AuthenticationServiceInner<S, Claims, Algo, ReAuth, Args> as Service<
        ServiceRequest,
    >>::Response;
    type Error = ActixWebError;
    type Transform = AuthenticationServiceInner<S, Claims, Algo, ReAuth, Args>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(AuthenticationServiceInner::new(
            Rc::new(service),
            Arc::clone(&self.inner),
        )))
    }
}
