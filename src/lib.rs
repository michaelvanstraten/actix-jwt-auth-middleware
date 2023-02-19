/*!
This crate builds upon the [`jwt-compact`](https://github.com/slowli/jwt-compact) crate
to provide a jwt authentication middleware for the [`actix-web`](https://github.com/actix/actix-web) framework.

The jwt implementation supports the revocation for tokens via `access` and `refresh` tokens.

It provides multiple cryptographic signing and verifying algorithms such as `HS256`, `HS384`, `HS512`, `EdDSA` and `ES256`.
For more infos on that mater please refer to the [`Supported algorithms`](https://docs.rs/jwt-compact/latest/jwt_compact/#supported-algorithms) section of the [`jwt-compact`](https://github.com/slowli/jwt-compact) crate.

# Features
- easy use of custom jwt claims
- automatic extraction of the custom claims
- verify only mode (only `public key` required)
- automatic renewal of `access` token (customizable)
- easy way to set expiration time of `access` and `refresh` tokens
- simple `UseJWT` trait for protecting a `App`, `Resource` or `Scope` (experimental [#91611](https://github.com/rust-lang/rust/issues/91611))
- refresh authorizer function that has access to application state

# Crate Features
- `use_jwt_traits` - enables the `.use_jwt()` shorthand for wrapping a `App`, `Resource` or `Scope`

This crate tightly integrates into the actix-web ecosystem,
this makes it easy to Automatic extract the jwt claims from a valid token.

```rust
# use actix_jwt_auth_middleware::{FromRequest};
# use actix_web::{get, Responder};
# use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Clone, FromRequest)]
struct UserClaims {
    id: u32,
    role: Role,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
enum Role {
    Admin,
    RegularUser,
}
#[get("/hello")]
async fn hello(user_claims: UserClaims) -> impl Responder {
    format!(
        "Hello user with id: {}, i see you are a {:?}!",
            user_claims.id, user_claims.role
    )
}
```

For this your custom claim type has to implement the [`FromRequest`](actix_web::FromRequest) trait
or it has to be annotated with the `#[derive(actix-jwt-auth-middleware::FromRequest)]` macro which implements this trait for your type.

# Simple Example
```rust no_run
# use actix_jwt_auth_middleware::use_jwt::UseJWTOnApp;
# use actix_jwt_auth_middleware::{AuthResult, Authority, FromRequest, TokenSigner};
# use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
# use exonum_crypto::KeyPair;
# use jwt_compact::alg::Ed25519;
# use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Clone, Debug, FromRequest)]
struct User {
    id: u32,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::random();

    HttpServer::new(move || {
        let authority = Authority::<User, Ed25519, _, _>::new()
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
            .expect("");

        App::new()
            .service(login)
            .use_jwt(authority, web::scope("").service(hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;

    Ok(())
}

#[get("/login")]
async fn login(token_signer: web::Data<TokenSigner<User, Ed25519>>) -> AuthResult<HttpResponse> {
    let user = User { id: 1 };
    Ok(HttpResponse::Ok()
        .cookie(token_signer.create_access_cookie(&user)?)
        .cookie(token_signer.create_refresh_cookie(&user)?)
        .body("You are now logged in"))
}

#[get("/hello")]
async fn hello(user: User) -> impl Responder {
    format!("Hello there, i see your user id is {}.", user.id)
}
```
For more examples please referee to the `examples` directory.
*/

#![cfg_attr(
    feature = "use_jwt_on_resource",
    feature(return_position_impl_trait_in_trait),
    allow(incomplete_features)
)]

#[doc(inline)]
pub use actix_jwt_auth_middleware_derive::FromRequest;
/// Convinience `UseJWT` traits
pub mod use_jwt;
pub use authority::*;
pub use errors::*;
pub use middleware::*;
pub use token_signer::*;

mod authority;
mod errors;
mod helper_macros;
mod middleware;
mod token_signer;
mod validate;
