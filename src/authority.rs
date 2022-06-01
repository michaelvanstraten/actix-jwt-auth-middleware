use super::{AuthError, AuthResult};
use actix_web::{cookie::Cookie, dev::ServiceRequest, HttpMessage};
use ed25519_dalek::Keypair;
use jwt_compact::{alg::Ed25519, AlgorithmExt, Claims, Header, Token, UntrustedToken};
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Serialize};

pub type GuardFn<C> = fn(&C) -> bool;

pub struct Authority<C> {
    pub cookie_name: &'static str,
    key_pair: Keypair,
    header: Header,
    guard_fn: GuardFn<C>,
}

impl<C: Serialize + DeserializeOwned + Clone + 'static> Authority<C> {
    pub fn new(
        f: GuardFn<C>,
        cookie_name: &'static str,
        key_pair: Keypair,
        header: Header,
    ) -> Self {
        Self {
            cookie_name,
            key_pair,
            header,
            guard_fn: f,
        }
    }

    pub fn default_with_guard_fn(f: GuardFn<C>) -> Self {
        let mut new_authorizer = Self::default();
        new_authorizer.guard_fn = f;
        new_authorizer
    }

    pub fn create_signed_cookie(&self, claims: C) -> AuthResult<Cookie> {
        let claims = Claims::new(claims);
        let compact_token = Ed25519
            .compact_token(self.header.clone(), &claims, &self.key_pair)
            .map_err(|err| AuthError::TokenCreation(err))?;
        Ok(Cookie::build(self.cookie_name, compact_token)
            .secure(true)
            .finish())
    }

    pub fn verify_service_request(&self, req: ServiceRequest) -> AuthResult<ServiceRequest> {
        let token = self.extract_from_cookie(req.cookie(self.cookie_name))?;
        if (self.guard_fn)(&token.claims().custom) {
            req.extensions_mut().insert(token.claims().custom.clone());
            Ok(req)
        } else {
            Err(AuthError::Unauthorized)
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

impl<C> Clone for Authority<C> {
    fn clone(&self) -> Self {
        Self {
            cookie_name: self.cookie_name.clone(),
            key_pair: Keypair::from_bytes(&self.key_pair.to_bytes()).unwrap(),
            header: self.header.clone(),
            guard_fn: self.guard_fn.clone(),
        }
    }
}

impl<C> Default for Authority<C> {
    fn default() -> Self {
        let mut csprng = OsRng {};
        Self {
            cookie_name: "auth-token",
            key_pair: Keypair::generate(&mut csprng),
            header: Header::default(),
            guard_fn: |_| true,
        }
    }
}
