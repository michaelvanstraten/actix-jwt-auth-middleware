use std::marker::PhantomData;

use super::{AuthError, AuthResult};
use actix_web::{cookie::Cookie, dev::ServiceRequest, FromRequest, Handler, HttpMessage};
use chrono::Duration;
use derive_builder::Builder;
use jwt_compact::{
    AlgorithmExt, Claims as TokenClaims, Header, TimeOptions, Token, UntrustedToken,
    ValidationError::Expired as TokenExpired,
};
use serde::{de::DeserializeOwned, Serialize};

pub struct TokenUpdate {
    pub(crate) auth_cookie: Option<Cookie<'static>>,
    pub(crate) refresh_cookie: Option<Cookie<'static>>,
}

#[derive(Builder, Clone)]
pub struct Authority<Claims, Algorithm, ReAuthorizer, Args>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /// A function that will decide over wether a client with a valid refresh token gets a new access token. This function implements a method of revoking of a jwt token. Similar to the [AuthService<Guard>](actix_jwt_auth_middleware::AuthService) this function will get access to the.
    re_authorizer: ReAuthorizer,
    #[builder(default = "\"access_token\"")]
    pub access_token_name: &'static str,
    /// This will control how long a access token is valid for. Increasing this value will result in less calls to the `re_authorizer` function but it will also increase the time for a revocation of a token to take effect.
    #[builder(default = "Duration::seconds(60)")]
    access_token_lifetime: Duration,
    #[builder(default = "true")]
    renew_access_token_automatically: bool,
    #[builder(default = "\"refresh_token\"")]
    pub refresh_token_name: &'static str,
    /// This will control how long a client can not interact with the server and still get a refresh of the access token. This will of course only have an effect if the `renew_access_token_automatically` flag is set to true.
    #[builder(default = "Duration::minutes(30)")]
    refresh_token_lifetime: Duration,
    #[builder(default = "false")]
    renew_refresh_token_automatically: bool,
    algorithm: Algorithm,
    signing_key: Algorithm::SigningKey,
    verifying_key: Algorithm::VerifyingKey,
    #[builder(default)]
    header: Header,
    #[doc(hidden)]
    _claims: PhantomData<Claims>,
    #[doc(hidden)]
    _args: PhantomData<Args>,
}

impl<Claims, Algorithm, ReAuthorizer, Args>
    Authority<Claims, Algorithm, ReAuthorizer, Args>
where
    Claims: Serialize + DeserializeOwned + Clone + 'static,
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
    ReAuthorizer: Handler<Args, Output = Result<(), actix_web::Error>> + Clone,
    Args: FromRequest + Clone,
{
    pub fn new() -> AuthorityBuilder<Claims, Algorithm, ReAuthorizer, Args> {
        AuthorityBuilder::default()
    }

    pub fn create_access_token(&self, claims: Claims) -> AuthResult<String> {
        self.create_token(claims, self.access_token_lifetime)
    }

    pub fn create_refresh_token(&self, claims: Claims) -> AuthResult<String> {
        self.create_token(claims, self.refresh_token_lifetime)
    }

    pub fn create_token(&self, claims: Claims, token_lifetime: Duration) -> AuthResult<String> {
        let claims = TokenClaims::new(claims)
            .set_duration_and_issuance(&TimeOptions::default(), token_lifetime);

        self.algorithm
            .token(self.header.clone(), &claims, &self.signing_key)
            .map_err(|err| AuthError::TokenCreation(err))
    }

    pub async fn verify_service_request(
        &self,
        mut req: ServiceRequest,
    ) -> AuthResult<(ServiceRequest, Option<TokenUpdate>)> {
        match self.verify_cookie(req.cookie(self.access_token_name)) {
            Ok(access_token) => {
                req.extensions_mut()
                    .insert(access_token.claims().custom.clone());
                Ok((req, None))
            }
            Err(AuthError::TokenValidation(TokenExpired))
                if self.renew_access_token_automatically =>
            {
                let (mut_req, mut payload) = req.parts_mut();
                match Args::from_request(&mut_req, &mut payload).await {
                    Ok(args) => match self.re_authorizer.call(args).await {
                        Ok(()) => match self.verify_cookie(req.cookie(self.refresh_token_name)) {
                            Ok(refresh_token) => {
                                let access_token = self.create_access_token(
                                    refresh_token.claims().clone().custom.clone(),
                                )?;
                                req.extensions_mut()
                                    .insert(refresh_token.claims().custom.clone());
                                Ok((req, Some(self.make_token_update(Some(access_token), None))))
                            }
                            Err(AuthError::TokenValidation(TokenExpired))
                                if self.renew_refresh_token_automatically =>
                            {
                                let claims = UntrustedToken::new(
                                    req.cookie(self.access_token_name).unwrap().value(),
                                )
                                .unwrap()
                                .deserialize_claims_unchecked::<Claims>()
                                .unwrap()
                                .custom;

                                let refresh_token = self.create_refresh_token(claims.clone())?;
                                let access_token = self.create_access_token(claims.clone())?;

                                Ok((
                                    req,
                                    Some(self.make_token_update(
                                        Some(access_token),
                                        Some(refresh_token),
                                    )),
                                ))
                            }
                            Err(e) => Err(e),
                        },
                        Err(e) => Err(AuthError::Internal(e)),
                    },
                    Err(err) => Err(AuthError::Internal(err.into())),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn make_token_update(
        &self,
        access_token: Option<String>,
        refresh_token: Option<String>,
    ) -> TokenUpdate {
        TokenUpdate {
            auth_cookie: access_token.map(|v| {
                Cookie::build(self.access_token_name, v)
                    .secure(true)
                    .finish()
            }),
            refresh_cookie: refresh_token.map(|v| {
                Cookie::build(self.access_token_name, v)
                    .secure(true)
                    .finish()
            }),
        }
    }

    fn verify_cookie(&self, cookie: Option<Cookie>) -> AuthResult<Token<Claims>> {
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
            Err(AuthError::Unauthorized)
        }
    }
}
