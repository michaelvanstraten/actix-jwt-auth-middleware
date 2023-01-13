use crate::rest::RestAuthenticationMiddleware;
use crate::RestAuthority;

use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::Service;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::dev::Transform;
use actix_web::Error as ActixError;
use futures_util::future;
use serde::de::DeserializeOwned;
use serde::Serialize;

/**
   A wrapper around the [`RestAuthority`] which can be passed to the `wrap` function of a [`App`](actix_web::App)/[`Scope`](actix_web::Scope) or [`Resource`](actix_web::Resource).

   ## Example
   ```rust
   use actix_jwt_auth_middleware::{CookieSigner, Authority, AuthenticationService};
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
       .cookie_signer(Some(
           CookieSigner::new()
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
pub struct RestAuthenticationService<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    inner: RestAuthority<Claims, Algorithm>,
    _claims: PhantomData<Claims>,
}

impl<Claims, Algorithm> RestAuthenticationService<Claims, Algorithm>
where
    Claims: DeserializeOwned,
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /**
        returns a new RestAuthenticationService wrapping the [`RestAuthority`]
    */
    pub fn new(
        authority: RestAuthority<Claims, Algorithm>,
    ) -> RestAuthenticationService<Claims, Algorithm> {
        RestAuthenticationService {
            inner: authority,
            _claims: PhantomData,
        }
    }
}

impl<S, Body, Claims, Algorithm> Transform<S, ServiceRequest>
    for RestAuthenticationService<Claims, Algorithm>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = ActixError> + 'static,
    S::Future: 'static,
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone + 'static,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    Body: MessageBody,
{
    type Response =
        <RestAuthenticationMiddleware<S, Claims, Algorithm> as Service<ServiceRequest>>::Response;
    type InitError = ();
    type Error = ActixError;
    type Transform = RestAuthenticationMiddleware<S, Claims, Algorithm>;
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(RestAuthenticationMiddleware::new(
            Rc::new(service),
            Arc::new(self.inner.clone()),
        ))
    }
}
