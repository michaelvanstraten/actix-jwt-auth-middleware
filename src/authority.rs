use std::marker::PhantomData;

use crate::{AuthError, AuthResult, CookieSigner};

use actix_web::{cookie::Cookie, dev::ServiceRequest, FromRequest, Handler, HttpMessage};
use derive_builder::Builder;
use jwt_compact::{
    AlgorithmExt, TimeOptions, Token, UntrustedToken, ValidationError::Expired as TokenExpired,
};
use serde::{de::DeserializeOwned, Serialize};

macro_rules! pull_from_cookie_signer {
    ($self:ident ,$field_name:ident) => {
        match $self.cookie_signer {
            Some(Some(ref value)) => value.$field_name.clone(),
            _ => {
                return ::derive_builder::export::core::result::Result::Err(
                    ::derive_builder::export::core::convert::Into::into(
                        ::derive_builder::UninitializedFieldError::from(stringify!($field_name)),
                    ),
                );
            }
        }
    };

    ($self:ident, $field_name:ident, $alternative:expr) => {
        match $self.cookie_signer {
            Some(Some(ref value)) => value.$field_name.clone(),
            _ => $alternative,
        }
    };
}

#[doc(hidden)]
// struct used to signal to the middleware that a cookie needs to be updated
// after the wrapped service has returned a response. 
pub struct TokenUpdate {
    pub(crate) auth_cookie: Option<Cookie<'static>>,
    pub(crate) refresh_cookie: Option<Cookie<'static>>,
}

/**
    Handles the authorization of requests for the middleware as well as refreshing the `auth`/`re_auth` token.

    Please referee to the [`AuthorityBuilder`] for a detailed description of options available on this struct.
*/
#[derive(Builder, Clone)]
pub struct Authority<Claims, Algorithm, ReAuthorizer, Args>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
    Algorithm::VerifyingKey: Clone,
{
    /**
        The re_authorizer is called every time,
        when a client with an expired access token but a valid refresh token
        tries to fetch a resource protected by the jwt middleware.

        By returning the `Ok` variant your grand the client permission to get a new access token.
        In contrast, by returning the `Err` variant you deny the request. The [`actix_web::Error`](actix_web::Error) returned in this case
        will be passed along as a wrapped internal [`AuthError`] back to the client (There are options to remap this [actix-error-mapper]).

        Since re_authorizer has to implement the [`Handler`](actix_web::dev::Handler) trait,
        you are able to access your regular application an request state from within
        the function. This allows you to perform Database Check etc...
    */
    re_authorizer: ReAuthorizer,
    /**
       Not Passing a CookieSinger struct will make your middleware unable to refresh the access token automatically.

       You will have to provide a algorithm manually in this case because the Authority can not pull it from the `cookie_signer` field.

       Please referee to the structs own documentation for more details.
    */
    #[builder(default = "None")]
    cookie_signer: Option<CookieSigner<Claims, Algorithm>>,
    /**
        Depending on wether a CookieSinger is set, setting this field will have no affect.

        Defaults to the value of the `access_token_name` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this defaults to `"access_token"`.
    */
    #[builder(default = "pull_from_cookie_signer!(self, access_token_name, \"access_token\")")]
    pub(crate) access_token_name: &'static str,
    /**
        Self explanatory, if set to false the clients access token will not be automatically refreshed.

        Defaults to `true`
    */
    #[builder(default = "true")]
    renew_access_token_automatically: bool,
    /**
        If set to true the clients refresh token will automatically refreshed,
        this allows clients to basically stay authenticated over a infinite amount of time, so i don't recommend it.

        Defaults to `false`
    */
    #[builder(default = "false")]
    renew_refresh_token_automatically: bool,
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
    #[builder(default = "pull_from_cookie_signer!(self, algorithm)")]
    algorithm: Algorithm,
    /**
        Used in the creating of the `token`, the current timestamp is taken from this, but please referee to the Structs documentation.  

        Defaults to the value of the `time_options` field set on the `cookie_signer`, if the `cookie_signer` is not set,
        this field needs to be set.
    */
    #[builder(default = "pull_from_cookie_signer!(self, time_options)")]
    time_options: TimeOptions,
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
    /**
        Returns a new [AuthorityBuilder]
    */
    pub fn new() -> AuthorityBuilder<Claims, Algorithm, ReAuthorizer, Args> {
        AuthorityBuilder::default()
    }

    /**
        Returns a Clone of the `cookie_signer` field on the Authority.
    */
    pub fn cookie_signer(&self) -> Option<CookieSigner<Claims, Algorithm>> {
        self.cookie_signer.clone()
    }

    /**
        Use by the [`crate::AuthenticationMiddleware`]
        in oder to verify an incoming request and ether hand it of to protected services
        or deny the request by return a wrapped [`AuthError`].
    */
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
                match self.cookie_signer {
                    Some(ref cookie_signer) => {
                        let (mut_req, mut payload) = req.parts_mut();
                        match Args::from_request(&mut_req, &mut payload).await {
                            Ok(args) => match self.re_authorizer.call(args).await {
                                Ok(()) => match self
                                    .verify_cookie(req.cookie(cookie_signer.refresh_token_name))
                                {
                                    Ok(refresh_token) => {
                                        let claims = refresh_token.claims().custom.clone();
                                        req.extensions_mut().insert(claims.clone());
                                        Ok((
                                            req,
                                            Some(TokenUpdate {
                                                auth_cookie: Some(
                                                    cookie_signer
                                                        .create_access_token_cookie(&claims)?,
                                                ),
                                                refresh_cookie: None,
                                            }),
                                        ))
                                    }
                                    Err(AuthError::TokenValidation(TokenExpired))
                                        if self.renew_refresh_token_automatically =>
                                    {
                                        let claims = self
                                            .extract_untrusted_claims_from_service_request(&req);
                                        Ok((
                                            req,
                                            Some(TokenUpdate {
                                                auth_cookie: Some(
                                                    cookie_signer
                                                        .create_access_token_cookie(&claims)?,
                                                ),
                                                refresh_cookie: Some(
                                                    cookie_signer
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
                    None => Err(AuthError::NoCookieSigner),
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
                        Ok(token) => {
                            match token.claims().validate_expiration(&self.time_options) {
                                Ok(_) => Ok(token),
                                Err(err) => Err(AuthError::TokenValidation(err)),
                            }
                        }
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
        UntrustedToken::new(req.cookie(self.access_token_name).unwrap().value())
            .unwrap()
            .deserialize_claims_unchecked::<Claims>()
            .unwrap()
            .custom
    }
}

#[cfg(test)]
mod tests {
    use super::Authority;
    use actix_web::cookie::Cookie;
    use chrono::Duration;
    use exonum_crypto::KeyPair;
    use jwt_compact::{alg::Ed25519, AlgorithmExt, Claims, Header, TimeOptions};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    struct TestClaims {}

    #[test]
    fn valid_token() {
        let key_pair = KeyPair::random();

        let time_options = TimeOptions::from_leeway(Duration::min_value());
        let header = Header::default();
        let claims = Claims::new(TestClaims {});

        let authority = Authority::<TestClaims, _, _, _>::new()
            .algorithm(Ed25519)
            .verifying_key(key_pair.public_key())
            .re_authorizer(|| async { Ok(()) })
            .time_options(time_options.clone())
            .build()
            .unwrap();

        let token = Ed25519
            .token(header, &claims, key_pair.secret_key())
            .unwrap();

        let cookie = Cookie::build(authority.access_token_name, token).finish();

        authority.verify_cookie(Some(cookie)).unwrap();
    }
}
