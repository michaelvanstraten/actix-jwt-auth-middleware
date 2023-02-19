use crate::helper_macros::{pull_from_token_signer, return_token_update};
use crate::validate::validate_jwt;
use crate::{AuthError, AuthResult, TokenSigner};

use std::marker::PhantomData;

use actix_web::cookie::Cookie;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::HeaderMap;
use actix_web::{Error as ActixWebError, FromRequest, Handler, HttpMessage};
use derive_builder::Builder;
use jwt_compact::ValidationError::Expired as TokenExpired;
use jwt_compact::{Algorithm, TimeOptions, Token, UntrustedToken};
use serde::de::DeserializeOwned;
use serde::Serialize;

/*
    Struct used to signal to the middleware that a cookie needs to be updated
    after the wrapped service has returned a response.
*/
#[doc(hidden)]
#[derive(Debug)]
pub struct TokenUpdate {
    pub(crate) access_cookie: Option<Cookie<'static>>,
    pub(crate) refresh_cookie: Option<Cookie<'static>>,
}

/**
    The [`Authority`] handles the process of authorizing service requests in this crate.

    It holds many configuration options to enable/disable specific authorization methods as well as the automatic renewal of JWTs.
    # Example
    ```rust
    # use actix_jwt_auth_middleware::{Authority, TokenSigner};
    # use jwt_compact::alg::Ed25519;
    # use exonum_crypto::KeyPair;
    # let key_pair = KeyPair::random();
    let authority = Authority::<(), Ed25519, _, _>::new()
        .refresh_authorizer(|| async move { Ok(()) })
        .token_signer(Some(
            TokenSigner::new()
                .signing_key(key_pair.secret_key().clone())
                .algorithm(Ed25519)
                .build()
                .expect(""),
        ))
        .verifying_key(key_pair.public_key())
        .build()
        .unwrap();
    ```
    Please refer to the [`AuthorityBuilder`] for a detailed description of options available on this struct.
*/
#[derive(Builder, Clone)]
#[builder(pattern = "owned")]
pub struct Authority<Claims, Algo, ReAuth, Args>
where
    Algo: Algorithm + Clone,
    Algo::SigningKey: Clone,
{
    /**
        The `refresh_authorizer` is called every time,
        when a client with an expired access token but a valid refresh token
        tries to fetch a resource protected by the JWT middleware.

        By returning the `Ok` variant your grand the client permission to get a new access token.
        In contrast, by returning the `Err` variant you deny the request.
        The [`actix_web::Error`] returned in this case
        will be passed along as a wrapped [`AuthError::RefreshAuthorizerDenied`] back to the client
        (There are options to remap this, for example this crate: [`actix-error-mapper-middleware`](https://github.com/michaelvanstraten/actix-error-mapper-middleware)).

        Since `refresh_authorizer` has to implement the [`Handler`](actix_web::dev::Handler) trait,
        you are able to access your regular application an request state from within
        the function. This allows you to perform Database Check etc...
    */
    refresh_authorizer: ReAuth,
    /**
        Depending on whether a [`TokenSigner`] is set, setting this field will have no affect.

        Defaults to the value of the `access_token_name` field set on the `token_signer`, if the `token_signer` is not set,
        this defaults to `"access_token"`.
    */
    #[builder(default = "pull_from_token_signer!(self, access_token_name, \"access_token\")")]
    pub(crate) access_token_name: &'static str,
    /**
        If set to false the clients access token will not be automatically refreshed.

        Defaults to `true`
    */
    #[builder(default = "true")]
    renew_access_token_automatically: bool,
    /**
        Depending on whether a [`TokenSigner`] is set, setting this field will have no affect.

        Defaults to the value of the `refresh_token_name` field set on the `token_signer`,
        if the `token_signer` is not set, this defaults to `"refresh_token"`.
    */
    #[builder(default = "pull_from_token_signer!(self, refresh_token_name, \"refresh_token\")")]
    pub(crate) refresh_token_name: &'static str,
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
    verifying_key: Algo::VerifyingKey,
    /**
        The Cryptographic signing algorithm used in the process of creation of access and refresh tokens.

        Please referee to the [`Supported algorithms`](https://docs.rs/jwt-compact/latest/jwt_compact/#supported-algorithms) section of the `jwt-compact` crate for a comprehensive list of the supported algorithms.

        Defaults to the value of the `algorithm` field set on the `token_signer`, if the `token_signer` is not set,
        this field needs to be set.
    */
    #[builder(default = "pull_from_token_signer!(self, algorithm)")]
    algorithm: Algo,
    /**
        Used in the creating of the `token`, the current time stamp is taken from this, but please referee to the Structs documentation.

        Defaults to the value of the `time_options` field set on the `token_signer`, if the `token_signer` is not set,
        this field needs to be set.
    */
    #[builder(default = "pull_from_token_signer!(self, time_options)")]
    time_options: TimeOptions,
    /**
       Not Passing a [`TokenSigner`] struct will make your middleware unable to refresh the access token automatically.

       You will have to provide a algorithm manually in this case because the Authority can not pull it from the `token_signer` field.

       Please referee to the structs own documentation for more details.
    */
    #[builder(default = "None")]
    token_signer: Option<TokenSigner<Claims, Algo>>,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    claims_marker: PhantomData<Claims>,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    args_marker: PhantomData<Args>,
}

impl<Claims, Algo, ReAuth, Args> Authority<Claims, Algo, ReAuth, Args>
where
    Claims: Serialize + DeserializeOwned + 'static,
    Algo: Algorithm + Clone,
    Algo::SigningKey: Clone,
    ReAuth: Handler<Args, Output = Result<(), ActixWebError>>,
    Args: FromRequest,
{
    /**
        Returns a new [`AuthorityBuilder`]
    */
    pub fn new() -> AuthorityBuilder<Claims, Algo, ReAuth, Args> {
        AuthorityBuilder::default()
    }

    /**
        Returns a Clone of the `token_signer` field on the Authority.
    */
    pub fn token_signer(&self) -> Option<TokenSigner<Claims, Algo>>
    where
        TokenSigner<Claims, Algo>: Clone,
    {
        self.token_signer.clone()
    }

    /**
        Use by the [`crate::AuthenticationMiddleware`]
        in order to verify an incoming request and ether hand it of to protected services
        or deny the request by return a wrapped [`AuthError`].
    */
    pub async fn verify_service_request(
        &self,
        req: &mut ServiceRequest,
    ) -> AuthResult<Option<TokenUpdate>> {
        match self.validate_cookie(&req, self.access_token_name) {
            Ok(access_token) => {
                let (_, claims) = access_token.into_parts();
                req.extensions_mut().insert(claims.custom);
                Ok(None)
            }
            Err(AuthError::TokenValidation(TokenExpired) | AuthError::NoToken)
                if self.renew_access_token_automatically =>
            {
                self.call_refresh_authorizer(req).await?;
                match (
                    self.validate_cookie(&req, self.refresh_token_name),
                    &self.token_signer,
                ) {
                    (Ok(refresh_token), Some(token_signer)) => {
                        let (_, claims) = refresh_token.into_parts();

                        let access_cookie = token_signer.create_access_cookie(&claims.custom)?;

                        req.extensions_mut().insert(claims.custom);

                        return_token_update!(access_cookie)
                    }
                    (Err(AuthError::TokenValidation(TokenExpired)), Some(token_signer))
                        if self.renew_refresh_token_automatically =>
                    {
                        let claims = extract_claims_unsafe(
                            req.cookie(self.refresh_token_name)
                                .expect("Cookie has to be set in oder to get to this point")
                                .value(),
                        );

                        let access_cookie = token_signer.create_access_cookie(&claims)?;
                        let refresh_cookie = token_signer.create_refresh_cookie(&claims)?;

                        req.extensions_mut().insert(claims);

                        return_token_update!(access_cookie, refresh_cookie)
                    }
                    (Ok(_), None) => Err(AuthError::NoTokenSigner),
                    (Err(err), _) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    fn validate_cookie(
        &self,
        req: &ServiceRequest,
        cookie_name: &'static str,
    ) -> AuthResult<Token<Claims>> {
        match req.cookie(cookie_name) {
            Some(token_value) => validate_jwt(
                &token_value.value(),
                &self.algorithm,
                &self.verifying_key,
                &self.time_options,
            ),
            None => Err(AuthError::NoToken),
        }
    }

    fn validate_header_value(
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
                Err(_) => Err(AuthError::NoToken),
            },
            None => Err(AuthError::NoToken),
        }
    }

    fn validate_query(&self) {}

    async fn call_refresh_authorizer(&self, req: &mut ServiceRequest) -> AuthResult<()> {
        let (mut_req, mut payload) = req.parts_mut();
        match Args::from_request(&mut_req, &mut payload).await {
            Ok(args) => self
                .refresh_authorizer
                .call(args)
                .await
                .map_err(|err| AuthError::RefreshAuthorizerDenied(err.into())),
            Err(err) => Err(AuthError::Internal(err.into())),
        }
    }
}

fn extract_claims_unsafe<'a, S, Claims>(token_value: &'a S) -> Claims
where
    S: AsRef<str> + ?Sized,
    Claims: DeserializeOwned,
{
    UntrustedToken::new(token_value)
        .expect(
            "UntrustedToken token has to be parseable fro, cookie value in order to get to here",
        )
        .deserialize_claims_unchecked::<Claims>()
        .expect("Claims has to be desirializeable to get to this point")
        .custom
}
