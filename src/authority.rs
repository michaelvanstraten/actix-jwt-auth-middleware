use std::marker::PhantomData;

use super::{AuthError, AuthResult};
use actix_web::{cookie::Cookie, dev::ServiceRequest, HttpMessage};
use jwt_compact::{AlgorithmExt, Claims as TokenClaims, Header, Token, UntrustedToken};
use serde::{de::DeserializeOwned, Serialize};

pub struct Authority<Claims, Algorithm: jwt_compact::Algorithm> {
    pub cookie_name: &'static str,
    algorithm: Algorithm,
    signing_key: Algorithm::SigningKey,
    verifying_key: Algorithm::VerifyingKey,
    header: Header,
    _claims: PhantomData<Claims>,
}

impl<Claims: Serialize + DeserializeOwned + Clone + 'static, Algorithm: jwt_compact::Algorithm>
    Authority<Claims, Algorithm>
{
    pub fn new(
        cookie_name: &'static str,
        signing_key: Algorithm::SigningKey,
        verifying_key: Algorithm::VerifyingKey,
        header: Header,
        algorithm: Algorithm,
    ) -> Self {
        Self {
            cookie_name,
            signing_key,
            verifying_key,
            header,
            algorithm: algorithm,
            _claims: PhantomData,
        }
    }

    pub fn create_signed_cookie(&self, claims: Claims) -> AuthResult<Cookie> {
        Ok(Cookie::build(self.cookie_name, self.create_token(claims)?)
            .secure(true)
            .finish())
    }

    pub fn create_token(&self, claims: Claims) -> AuthResult<String> {
        let claims = TokenClaims::new(claims);
        self.algorithm
            .compact_token(self.header.clone(), &claims, &self.signing_key)
            .map_err(|err| AuthError::TokenCreation(err))
    }

    pub async fn verify_service_request(&self, req: ServiceRequest) -> AuthResult<ServiceRequest> {
        let token = self.extract_from_cookie(req.cookie(self.cookie_name))?;

        req.extensions_mut().insert(token.claims().custom.clone());
        Ok(req)
    }

    fn extract_from_cookie(&self, cookie: Option<Cookie>) -> AuthResult<Token<Claims>> {
        if let Some(token_cookie) = cookie {
            match UntrustedToken::new(token_cookie.value()) {
                Ok(untrusted_token) => {
                    match self
                        .algorithm
                        .validate_integrity::<Claims>(&untrusted_token, &self.verifying_key)
                    {
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

impl<Claims, Algorithm> Clone for Authority<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    fn clone(&self) -> Self {
        Self {
            cookie_name: self.cookie_name.clone(),
            signing_key: self.signing_key.clone(),
            verifying_key: self.verifying_key.clone(),
            algorithm: self.algorithm.clone(),
            header: self.header.clone(),
            _claims: self._claims.clone(),
        }
    }
}
