use std::marker::PhantomData;

use actix_web::cookie::Cookie;
use chrono::Duration;
use derive_builder::Builder;
use jwt_compact::{AlgorithmExt, Claims as TokenClaims, Header, TimeOptions};
use serde::Serialize;

use crate::{AuthError, AuthResult};

/**
    Used in the creation process of access and refresh tokens.

    The [`crate::Authority`] uses it to automatically refresh the auth token.

    It holds the private key as well as configuration option.
    ## Example
    ```rust
    use actix_jwt_auth_middleware::CookieSigner;
    use serde::Serialize;
    use exonum_crypto::KeyPair;
    use jwt_compact::{alg::Ed25519, TimeOptions};
    use chrono::Duration;

    #[derive(Serialize, Clone)]
    struct User {
        id: u32
    }

    let key_pair = KeyPair::random();

    let cookie_signer = CookieSigner::<User, _>::new()
        .signing_key(key_pair.secret_key().clone())
        .access_token_name("my_access_token")
        // makes the refresh token be valid for 2 hours
        .refresh_token_lifetime(Duration::minutes(120))
        // the access token can still be used up to 10 seconds after it expired
        .time_options(TimeOptions::from_leeway(Duration::seconds(10)))
        .algorithm(Ed25519)
        .build()
        .unwrap();

    let cookie = cookie_signer.create_access_token_cookie(&User{
        id: 1
    }).unwrap();
    ```
    Please referee to the [`CookieSignerBuilder`] for a detailed description of Options available on this struct.
*/
#[derive(Builder, Clone)]
pub struct CookieSigner<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm,
    Algorithm::SigningKey: Clone,
{
    #[builder(default = "\"access_token\"")]
    pub(crate) access_token_name: &'static str,
    /**
        This will control how long a access token is valid for.

        Increasing this value will result in less calls to the `refresh_authorizer` function but it will also increase the time for a revocation of a token to take effect.

        Defaults to `Duration::seconds(60)`
    */
    #[builder(default = "Duration::seconds(60)")]
    access_token_lifetime: Duration,
    #[builder(default = "\"refresh_token\"")]
    pub(crate) refresh_token_name: &'static str,
    /**
        This will control how long a client can not interact with the server and still get a refresh of the access token.
        This will of course only have an effect if the `renew_access_token_automatically` flag is set to true.

        Defaults to `Duration::minutes(30)`
    */
    #[builder(default = "Duration::minutes(30)")]
    refresh_token_lifetime: Duration,
    /**
        JWT Header used in the creation of access and refresh tokens.

        Please referee to the structs own documentation for more details.

        Defaults to `Header::default()`
    */
    #[builder(default)]
    header: Header,
    /**
        The Cryptographic signing algorithm used in the process of creation of access and refresh tokens.

        Please referee to the [`Supported algorithms`](https://docs.rs/jwt-compact/latest/jwt_compact/#supported-algorithms) section of the `jwt-compact` crate
        for a comprehensive list of the supported algorithms.
    */
    pub(crate) algorithm: Algorithm,
    /**
        Key used to sign access and refresh tokens.
    */
    signing_key: Algorithm::SigningKey,
    /**
        Used in the creating of the `token`, the current timestamp is taken from this, but please referee to the Structs documentation.

        Defaults to `TimeOptions::from_leeway(Duration::seconds(0))`
    */
    #[builder(default = "TimeOptions::from_leeway(Duration::seconds(0))")]
    pub(crate) time_options: TimeOptions,
    #[doc(hidden)]
    #[builder(setter(skip), default = "PhantomData")]
    _claims: PhantomData<Claims>,
}

impl<Claims, Algorithm> CookieSigner<Claims, Algorithm>
where
    Algorithm: jwt_compact::Algorithm + Clone,
    Algorithm::SigningKey: Clone,
    Claims: Serialize + Clone,
{
    /**
        Returns a new [CookieSignerBuilder]
    */
    pub fn new() -> CookieSignerBuilder<Claims, Algorithm> {
        CookieSignerBuilder::default()
    }

    /**
        A shorthand for creating a access token.

        Internally it calls [`Self::create_signed_cookie`] while
        passing the `access_token_name` as well as the `access_token_lifetime`.
    */
    pub fn create_access_token_cookie(&self, claims: &Claims) -> AuthResult<Cookie<'static>> {
        self.create_signed_cookie(claims, self.access_token_name, self.access_token_lifetime)
    }

    /**
        A shorthand for creating a refresh token.

        Internally it calls [`Self::create_signed_cookie`] while
        passing the `refresh_token_name` as well as the `refresh_token_lifetime`.
    */
    pub fn create_refresh_token_cookie(&self, claims: &Claims) -> AuthResult<Cookie<'static>> {
        self.create_signed_cookie(claims, self.refresh_token_name, self.refresh_token_lifetime)
    }

    /**
        Creates a cookie containing a jwt token.

        * `claims` reference to an object of the generic type `Claims` which will be incorporated inside of the jwt string

        * `token_name` the name of the resulting cookie

        * `token_lifetime` how long the token is valid for
    */
    pub fn create_signed_cookie(
        &self,
        claims: &Claims,
        token_name: &'static str,
        token_lifetime: Duration,
    ) -> AuthResult<Cookie<'static>> {
        let token_claims =
            TokenClaims::new(claims).set_duration_and_issuance(&self.time_options, token_lifetime);

        let token = self
            .algorithm
            .token(self.header.clone(), &token_claims, &self.signing_key)
            .map_err(|err| AuthError::TokenCreation(err))?;

        Ok(Cookie::build(token_name, token).secure(true).finish())
    }
}
