use crate::validate::validate_jwt;
use crate::AuthError;
use crate::AuthResult;

use std::marker::PhantomData;

use actix_web::dev::ServiceRequest;
use actix_web::http::header::HeaderMap;
use actix_web::HttpMessage;
use derive_builder::Builder;
use jwt_compact::TimeOptions;
use jwt_compact::Token;
use jwt_compact::ValidationError::Expired as TokenExpired;
use serde::de::DeserializeOwned;
use serde::Serialize;

/**
    Handles the authorization of requests for the middleware as well as refreshing the `access`/`refresh` token.

    Please referee to the [`AuthorityBuilder`] for a detailed description of options available on this struct.
*/
#[derive(Builder, Clone)]
pub struct RestAuthority<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /**
        Depending on wether a [`CookieSigner`] is set, setting this field will have no affect.

        Defaults to the value of the `access_token_name` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this defaults to `"access_token"`.
    */
    #[builder(default = "\"access_token\"")]
    pub(crate) access_token_name: &'static str,
    /**
        Depending on wether a [`CookieSigner`] is set, setting this field will have no affect.

        Defaults to the value of the `refresh_token_name` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this defaults to `"refresh_token"`.
    */
    #[builder(default = "\"refresh_token\"")]
    pub(crate) refresh_token_name: &'static str,
    /**
        Key used to verify integrity of access and refresh token.
    */
    verifying_key: Algorithm::VerifyingKey,
    /**
        The Cryptographic signing algorithm used in the process of creation of access and refresh tokens.

        Please referee to the [`Supported algorithms`](https://docs.rs/jwt-compact/latest/jwt_compact/#supported-algorithms) section of the `jwt-compact` crate
        for a comprehensive list of the supported algorithms.

        Defaults to the value of the `algorithm` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this field needs to be set.
    */
    algorithm: Algorithm,
    /**
        Used in the creating of the `token`, the current timestamp is taken from this, but please referee to the Structs documentation.

        Defaults to the value of the `time_options` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this field needs to be set.
    */
    time_options: TimeOptions,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    _claims: PhantomData<Claims>,
}

impl<Claims, Algorithm> RestAuthority<Claims, Algorithm>
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /**
        Returns a new [`RestAuthorityBuilder`]
    */
    pub fn new() -> RestAuthorityBuilder<Claims, Algorithm> {
        RestAuthorityBuilder::default()
    }

    /**
        Use by the [`crate::AuthenticationMiddleware`]
        in oder to verify an incoming request and ether hand it of to protected services
        or deny the request by return a wrapped [`AuthError`].
    */
    pub async fn verify_service_request(&self, req: &mut ServiceRequest) -> AuthResult<()> {
        match self.validate_token(req.headers(), self.access_token_name) {
            Ok(access_token) => {
                req.extensions_mut()
                    .insert(access_token.claims().custom.clone());
                Ok(())
            }
            Err(AuthError::TokenValidation(TokenExpired) | AuthError::NoToken) => {
                match self.validate_token(req.headers(), self.refresh_token_name) {
                    Ok(refresh_token) => {
                        let claims = refresh_token.claims().custom.clone();
                        req.extensions_mut().insert(claims.clone());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    fn validate_token(
        &self,
        header_map: &HeaderMap,
        header_key: &'static str,
    ) -> AuthResult<Token<Claims>> {
        match header_map.get(header_key) {
            Some(header_value) => match header_value.to_str() {
                Ok(token_value) => validate_jwt(
                    &token_value,
                    &self.algorithm,
                    &self.verifying_key,
                    &self.time_options,
                ),
                Err(_) => todo!(),
            },
            None => Err(AuthError::NoToken),
        }
    }
}
