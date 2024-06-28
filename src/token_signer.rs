use crate::AuthError;
use crate::AuthResult;

use std::marker::PhantomData;
use std::time::Duration;

use actix_web::cookie::Cookie;
use actix_web::cookie::CookieBuilder;
use actix_web::http::header::HeaderValue;
use chrono::TimeDelta;
use derive_builder::Builder;
use jwt_compact::Algorithm;
use jwt_compact::AlgorithmExt;
use jwt_compact::Claims as TokenClaims;
use jwt_compact::Header;
use jwt_compact::TimeOptions;
use serde::Serialize;

/**
    The [`TokenSigner`] is a convenience struct,
    which holds configuration values as well as a private key for generation JWTs.

    For example, the [`crate::Authority`] uses it to automatically refresh the `access`/`refresh` token.
    # Example
    ```rust
    # use std::time::Duration;
    # use actix_jwt_auth_middleware::{TokenSigner, AuthError};
    # use serde::Serialize;
    # use ed25519_compact::KeyPair;
    # use jwt_compact::{alg::Ed25519, TimeOptions};
    #[derive(Serialize, Clone)]
    struct User {
        id: u32
    }

    let KeyPair {
        sk: secret_key,
        ..
    } = KeyPair::generate();

    let token_signer = TokenSigner::<User, _>::new()
        .signing_key(secret_key)
        .access_token_name("my_access_token")
        // makes every refresh token generated be valid for 2 hours
        .refresh_token_lifetime(Duration::from_secs(120 * 60))
        // generated tokens can still be used up to 10 seconds after they expired
        .time_options(TimeOptions::from_leeway(chrono::Duration::seconds(10)))
        .algorithm(Ed25519)
        .build().unwrap();

    let cookie = token_signer.create_access_cookie(&User{
        id: 1
    })?;
    # Ok::<(), AuthError>(())
    ```
    Please refer to the [`TokenSignerBuilder`] for a detailed description of Options available on this struct.
*/
#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct TokenSigner<Claims, Algo>
where
    Algo: Algorithm,
{
    /**
        The name of the future access tokens.

        For example, the name of the cookie generated in [`TokenSigner::create_access_cookie`].

        Defaults to `"access_token"`
    */
    #[builder(default = "\"access_token\".into()")]
    #[builder(setter(into))]
    pub(crate) access_token_name: String,
    /**
        The lifetime duration of the access token.

        Defaults to `Duration::from_secs(60)`
    */
    #[builder(default = "Duration::from_secs(60)")]
    access_token_lifetime: Duration,
    /**
        Specify cookie parameters like Path, HttpOnly or SameSite.
        Example usage `.cookie_builder(Cookie::build("", "").secure(true).path("/"))`

        Defaults to (`Cookie::build("", "").secure(true)`).
    */
    #[builder(default = "Cookie::build(\"\", \"\").secure(true)")]
    cookie_builder: CookieBuilder<'static>,
    /**
        The name of the future refresh tokens.

        For example, the name of the cookie generated in [`TokenSigner::create_refresh_cookie`].

        Defaults to `"refresh_token"`
    */
    #[builder(default = "\"refresh_token\".into()")]
    #[builder(setter(into))]
    pub(crate) refresh_token_name: String,
    /**
        The lifetime duration of the refresh token.

        Defaults to `Duration::from_secs(30 * 60)`
    */
    #[builder(default = "Duration::from_secs(30 * 60)")]
    refresh_token_lifetime: Duration,
    /**
        JWT Header used in the creation of access and refresh tokens.

        Please refer to the structs own documentation for more details.

        Defaults to `Header::default()`
    */
    #[builder(default)]
    header: Header,
    /**
        The Cryptographic signing algorithm used in the process of creation of access and refresh tokens.

        Please referee to the [`Supported algorithms`](https://docs.rs/jwt-compact/latest/jwt_compact/#supported-algorithms) section of the `jwt-compact` crate
        for a comprehensive list of the supported algorithms.
    */
    pub(crate) algorithm: Algo,
    /**
        Key used to sign tokens.
    */
    signing_key: Algo::SigningKey,
    /**
        Used in the creating of the `token`, the current time stamp is taken from this.

        Please refer to the structs own documentation for more details.

        Defaults to `TimeOptions::from_leeway(Duration::seconds(0))`
    */
    #[builder(default = "TimeOptions::from_leeway(TimeDelta::try_seconds(0).unwrap())")]
    pub(crate) time_options: TimeOptions,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    claims_marker: PhantomData<Claims>,
}

impl<Claims, Algorithm> TokenSigner<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm + Clone,
    Claims: Serialize,
{
    /**
        Returns a new [`TokenSignerBuilder`]
    */
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> TokenSignerBuilder<Claims, Algorithm> {
        TokenSignerBuilder::create_empty()
    }

    /**
        Returns the value of the `access_token_name` field on this struct.
    */
    pub fn access_token_name(&self) -> &str {
        &self.access_token_name
    }

    /**
        Returns the value of the `refresh_token_name` field on this struct.
    */
    pub fn refresh_token_name(&self) -> &str {
        &self.refresh_token_name
    }

    /**
        Creates a refresh token header value.

        Internally it calls [`Self::create_header_value`] while passing the previously defined
        `refresh_token_lifetime` value on this struct.
    */
    #[inline]
    pub fn create_refresh_header_value(&self, claims: &Claims) -> AuthResult<HeaderValue> {
        self.create_header_value(claims, self.refresh_token_lifetime)
    }

    /**
        Creates a access token header value.

        Internally it calls [`Self::create_header_value`] while passing the previously defined
        `access_token_lifetime` value on this struct.
    */
    #[inline]
    pub fn create_access_header_value(&self, claims: &Claims) -> AuthResult<HeaderValue> {
        self.create_header_value(claims, self.access_token_lifetime)
    }

    /**
        Creates a token and wraps it in a [`HeaderValue`].

        Internally it calls [`Self::create_signed_token`] while
        passing the `claims` as well as the `token_lifetime`.
    */
    pub fn create_header_value(
        &self,
        claims: &Claims,
        token_lifetime: Duration,
    ) -> AuthResult<HeaderValue> {
        let token = self.create_signed_token(claims, token_lifetime)?;
        Ok(HeaderValue::from_str(&token)
            .expect("Token should not contain ASCII characters (33-127)"))
    }

    /**
        Creates a Bearer [`HeaderValue`] wrapping a token.

        This value is typically set as the Authorization header, also known as Bearer Authentication.

        Internally it it calls [`Self::create_signed_token`]
        while passing the previously defined value of the `access_token_lifetime` on this struct.
    */
    pub fn create_bearer_header_value(&self, claims: &Claims) -> AuthResult<HeaderValue> {
        let token = self.create_signed_token(claims, self.access_token_lifetime)?;
        Ok(HeaderValue::from_str(&format!("Bearer {token}"))
            .expect("Token should not contain ASCII characters (33-127)"))
    }

    /**
        Creates a access token cookie.

        Internally it calls [`Self::create_cookie`] while passing the previously defined
        `access_token_name` and `access_token_lifetime` values on this struct.
    */
    #[inline]
    pub fn create_access_cookie(&self, claims: &Claims) -> AuthResult<Cookie<'static>> {
        self.create_cookie(claims, &self.access_token_name, self.access_token_lifetime)
    }

    /**
        Creates a refresh token cookie.

        Internally it calls [`Self::create_cookie`] while passing the previously defined
        `refresh_token_name` and `refresh_token_lifetime` values on this struct.
    */
    #[inline]
    pub fn create_refresh_cookie(&self, claims: &Claims) -> AuthResult<Cookie<'static>> {
        self.create_cookie(
            claims,
            &self.refresh_token_name,
            self.refresh_token_lifetime,
        )
    }

    /**
        Creates a token and wraps it in a [`Cookie`].

        Internally it calls [`Self::create_signed_token`] while
        passing the `claims` as well as the `token_lifetime`.

        * `cookie_name` the name of the resulting cookie
    */
    pub fn create_cookie(
        &self,
        claims: &Claims,
        cookie_name: &str,
        token_lifetime: Duration,
    ) -> AuthResult<Cookie<'static>> {
        let token = self.create_signed_token(claims, token_lifetime)?;
        let mut cookie = self.cookie_builder.clone().finish();
        cookie.set_name(cookie_name.to_string());
        cookie.set_value(token);
        Ok(cookie)
    }

    /**
        Creates a signed token using the previously defined
        [`TimeOptions`], [`Header`] and [`jwt_compact::Algorithm::SigningKey`]
        values on this struct.

        * `claims` reference to an object of the generic type `Claims` which will be incorporated inside of the JWT string

        * `token_lifetime` duration for which the token is valid for
    */
    pub fn create_signed_token(
        &self,
        claims: &Claims,
        token_lifetime: Duration,
    ) -> AuthResult<String> {
        let token_claims = TokenClaims::new(claims).set_duration_and_issuance(
            &self.time_options,
            TimeDelta::from_std(token_lifetime).unwrap(),
        );

        self.algorithm
            .token(&self.header, &token_claims, &self.signing_key)
            .map_err(AuthError::TokenCreation)
    }
}

impl<Claims, Algo: Clone> Clone for TokenSigner<Claims, Algo>
where
    Algo: Algorithm,
    Algo::SigningKey: Clone,
{
    #[inline]
    fn clone(&self) -> TokenSigner<Claims, Algo> {
        TokenSigner {
            access_token_name: Clone::clone(&self.access_token_name),
            access_token_lifetime: Clone::clone(&self.access_token_lifetime),
            refresh_token_name: Clone::clone(&self.refresh_token_name),
            refresh_token_lifetime: Clone::clone(&self.refresh_token_lifetime),
            cookie_builder: Clone::clone(&self.cookie_builder),
            header: Clone::clone(&self.header),
            algorithm: Clone::clone(&self.algorithm),
            signing_key: Clone::clone(&self.signing_key),
            time_options: Clone::clone(&self.time_options),
            claims_marker: Clone::clone(&self.claims_marker),
        }
    }
}
