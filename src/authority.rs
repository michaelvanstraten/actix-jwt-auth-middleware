use std::marker::PhantomData;

use super::{AuthError, AuthResult};
use actix_web::{cookie::Cookie, dev::ServiceRequest, FromRequest, Handler, HttpMessage, HttpResponse};
use ed25519_dalek::Keypair;
use jwt_compact::{alg::Ed25519, AlgorithmExt, Claims, Header, Token, UntrustedToken};
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Serialize};

pub type GuardFn<C> = fn(&C) -> bool;

pub struct Authority<C, F, Args>
where
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest,
{
    pub cookie_name: &'static str,
    key_pair: Keypair,
    header: Header,
    auth_handler: F,
    _claims: PhantomData<C>,
    _args: PhantomData<Args>,
}

impl<C: Serialize + DeserializeOwned + Clone + 'static, F, Args> Authority<C, F, Args>
where
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest,
{
    pub fn new(f: F, cookie_name: &'static str, key_pair: Keypair, header: Header) -> Self {
        Self {
            cookie_name,
            key_pair,
            header,
            auth_handler: f,
            _claims: PhantomData,
            _args: PhantomData,
        }
    }

    // pub fn default_with_guard_fn(f: F) -> Self {
    //     let mut new_authorizer = Self::default();
    //     new_authorizer.auth_handler = f;
    //     new_authorizer
    // }

    pub fn create_signed_cookie(&self, claims: C) -> AuthResult<Cookie> {
        let claims = Claims::new(claims);
        let compact_token = Ed25519
            .compact_token(self.header.clone(), &claims, &self.key_pair)
            .map_err(|err| AuthError::TokenCreation(err))?;
        Ok(Cookie::build(self.cookie_name, compact_token)
            .secure(true)
            .finish())
    }

    pub async fn verify_service_request(&self, mut req: ServiceRequest) -> AuthResult<ServiceRequest> {
        let token = self.extract_from_cookie(req.cookie(self.cookie_name))?;
        req.extensions_mut().insert(token.claims().custom.clone());
        let (mut_req, mut payload) = req.parts_mut();


        match Args::from_request(&mut_req, &mut payload).await  {
            Ok(args) => if self.auth_handler.call(args).await == true {
                req.extensions_mut().insert(token.claims().custom.clone());
                Ok(req)
            } else {
                Err(AuthError::Unauthorized)
            },
            Err(err) => todo!(),
        }
    }

    fn extract_from_cookie(&self, cookie: Option<Cookie>) -> AuthResult<Token<C>> {
        if let Some(token_cookie) = cookie {
            match UntrustedToken::new(token_cookie.value()) {
                Ok(untrusted_token) => {
                    match Ed25519.validate_integrity::<C>(&untrusted_token, &self.key_pair.public) {
                        Ok(token) => Ok(token),
                        Err(err) => Err(err.into()),
                    }
                }
                Err(err) => Err(err.into()),
            }
        } else {
            Err(AuthError::NoCookie)
        }
    }
}

impl<C, F, Args> Clone for Authority<C, F, Args>
where
    F: Clone,
    F: Handler<Args>,
    F::Output: PartialEq<bool>,
    Args: FromRequest,
{
    fn clone(&self) -> Self {
        Self {
            cookie_name: self.cookie_name.clone(),
            key_pair: Keypair::from_bytes(&self.key_pair.to_bytes()).unwrap(),
            header: self.header.clone(),
            auth_handler: self.auth_handler.clone(),
            _claims: PhantomData,
            _args: PhantomData,
        }
    }
}

// impl<C, F, Args> Default for Authority<C, F, Args>
// where
//     F: Handler<Args>,
//     F::Output: PartialEq<bool>,
//     Args: FromRequest,
// {
//     fn default() -> Self {
//         let mut csprng = OsRng {};
//         Self {
//             cookie_name: "auth-token",
//             key_pair: Keypair::generate(&mut csprng),
//             header: Header::default(),
//             auth_handler: default_auth_handler,
//             _claims: PhantomData,
//             _args: PhantomData,
//         }
//     }
// }

// async fn default_auth_handler() -> bool {
//     true
// }
