use std::marker::PhantomData;

use crate::CookieSigner;

use super::{AuthError, AuthResult};
use actix_web::{cookie::Cookie, dev::ServiceRequest, FromRequest, Handler, HttpMessage};
use derive_builder::Builder;
use jwt_compact::{AlgorithmExt, Token, UntrustedToken, ValidationError::Expired as TokenExpired};
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
    cookie_signer: CookieSigner<Claims, Algorithm>,
    #[builder(default = "true")]
    renew_access_token_automatically: bool,
    #[builder(default = "false")]
    renew_refresh_token_automatically: bool,
    verifying_key: Algorithm::VerifyingKey,
    #[builder(setter(skip), default = "self.cookie_signer.as_ref().unwrap().algorithm.clone()")]
    algorithm: Algorithm,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    _claims: PhantomData<Claims>,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    _args: PhantomData<Args>,
}

impl<Claims, Algorithm, ReAuthorizer, Args> Authority<Claims, Algorithm, ReAuthorizer, Args>
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

    pub fn cookie_signer(&self) -> CookieSigner<Claims, Algorithm> {
        self.cookie_signer.clone()
    }

    pub async fn verify_service_request(
        &self,
        mut req: ServiceRequest,
    ) -> AuthResult<(ServiceRequest, Option<TokenUpdate>)> {
        match self.verify_cookie(req.cookie(self.cookie_signer.access_token_name)) {
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
                        Ok(()) => match self
                            .verify_cookie(req.cookie(self.cookie_signer.refresh_token_name))
                        {
                            Ok(refresh_token) => {
                                let claims = refresh_token.claims().custom.clone();
                                req.extensions_mut().insert(claims.clone());
                                Ok((
                                    req,
                                    Some(TokenUpdate {
                                        auth_cookie: None,
                                        refresh_cookie: None,
                                    }),
                                ))
                            }
                            Err(AuthError::TokenValidation(TokenExpired))
                                if self.renew_refresh_token_automatically =>
                            {
                                let claims =
                                    self.extract_untrusted_claims_from_service_request(&req);
                                Ok((
                                    req,
                                    Some(TokenUpdate {
                                        auth_cookie: Some(
                                            self.cookie_signer
                                                .create_access_token_cookie(&claims)?,
                                        ),
                                        refresh_cookie: Some(
                                            self.cookie_signer
                                                .create_refresh_token_cookie(&claims)?,
                                        ),
                                    }),
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

    fn extract_untrusted_claims_from_service_request(&self, req: &ServiceRequest) -> Claims {
        UntrustedToken::new(
            req.cookie(self.cookie_signer.access_token_name)
                .unwrap()
                .value(),
        )
        .unwrap()
        .deserialize_claims_unchecked::<Claims>()
        .unwrap()
        .custom
    }
}
