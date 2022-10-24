use std::marker::PhantomData;

use actix_web::cookie::Cookie;
use chrono::Duration;
use derive_builder::Builder;
use jwt_compact::{Header, Claims as TokenClaims, TimeOptions, AlgorithmExt};
use serde::Serialize;

use crate::{AuthResult, AuthError};

#[derive(Builder, Clone)]
pub struct CookieSigner<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
{
    #[builder(default = "\"access_token\"")]
    pub(crate) access_token_name: &'static str,
    /// This will control how long a access token is valid for. Increasing this value will result in less calls to the `re_authorizer` function but it will also increase the time for a revocation of a token to take effect.
    #[builder(default = "Duration::seconds(60)")]
    access_token_lifetime: Duration,
    #[builder(default = "\"refresh_token\"")]
    pub(crate) refresh_token_name: &'static str,
    /// This will control how long a client can not interact with the server and still get a refresh of the access token. This will of course only have an effect if the `renew_access_token_automatically` flag is set to true.
    #[builder(default = "Duration::minutes(30)")]
    refresh_token_lifetime: Duration,
    #[builder(default)]
    header: Header,
    pub(crate) algorithm: Algorithm,
    signing_key: Algorithm::SigningKey,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    _claims: PhantomData<Claims>,
}

impl<Claims, Algorithm> CookieSigner<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
    Claims: Serialize + Clone
{   
    pub fn new() -> CookieSignerBuilder<Claims, Algorithm> {
        CookieSignerBuilder::default()
    }

    pub fn create_access_token_cookie(
        &self,
        claims: &Claims
    ) -> AuthResult<Cookie<'static>> {
        self.create_signed_cookie(claims, self.access_token_name, self.access_token_lifetime)
    }

    pub fn create_refresh_token_cookie(
        &self,
        claims: &Claims
    ) -> AuthResult<Cookie<'static>> {
        self.create_signed_cookie(claims, self.refresh_token_name, self.refresh_token_lifetime)
    }

    pub fn create_signed_cookie(
        &self,
        claims: &Claims,
        token_name: &'static str,
        token_lifetime: Duration,
    ) -> AuthResult<Cookie<'static>> {
        let token_claims = TokenClaims::new(claims)
            .set_duration_and_issuance(&TimeOptions::default(), token_lifetime);

        let token = self
            .algorithm
            .token(self.header.clone(), &token_claims, &self.signing_key)
            .map_err(|err| AuthError::TokenCreation(err))?;

        Ok(Cookie::build(token_name, token).secure(true).finish())
    }
}
