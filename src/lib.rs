/*!
This crate implements a JSON Webtoken (JWT) middleware for the actix-web framework.

For the moment it uses Curve25519 implemented in the [ed25519_dalek](ed25519_dalek) crate for the signing process of the token but i will be working on a generalization soon.

## Features

Automatic insertion and extraction of claims into the [Extensions](http::Extensions) object on the request.
For this your type has to implement the [FromRequest](actix_web::FromRequest) trait or it has to be annotated with the `#[derive(actix-jwt-auth-middleware::FromRequest)]` macro which implements this trait for your type.

```rust
#[derive(Serialize, Deserialize, Clone, FromRequest)]
struct UserClaims {
    id: u32,
    role: Role,
}

#[derive(Serialize, Deserialize, Clone)]
enum Role {
    Admin,
    BaseUser,
}

#[get("/hello")]
async fn hello(user_claims: UserClaims) -> impl Responder {
    format!("Hello user with id: {}!", user_claims.id)
}
```

Guard functions on top of JWT authentication.

Your guard function has to implement the [Handler](actix_web::Handler) trait and return a type that is partially equatable to a boolean.
Luckily the Handler trait is implemented for functions (up to an arity of 12) by actix_web.

The Application State can also be accessed with the guard function, for this use the [web::Data<T>](actix_web::web::Data<T>) extractor where T is the type of the state.

```rust
async fn verify_service_request(user_claims: UserClaims) -> bool {
    match user_claims.role {
        Role::Admin => true,
        Role::BaseUser => false,
    }
}
```

## Example

```rust
use actix_jwt_auth_middleware::{AuthError, AuthService, Authority, FromRequest};
use actix_web::{
    get,
    web::{self, Data},
    App, HttpResponse, HttpServer, Responder,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, FromRequest)]
struct UserClaims {
    id: u32,
    role: Role,
}

#[derive(Serialize, Deserialize, Clone)]
enum Role {
    Admin,
    BaseUser,
}

async fn verify_service_request(user_claims: UserClaims) -> bool {
    match user_claims.role {
        Role::Admin => true,
        Role::BaseUser => false,
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // we initialize a new Authority passing the underling type the JWT token should destructure into.
    let auth_authority = Authority::<UserClaims>::default();
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(auth_authority.clone()))
            .service(login)
            .service(login_as_base_user)
            // in order to wrap the entire app scope excluding the login handlers we have add a new service
            // with an empty scope first
            .service(web::scope("").service(hello).wrap(AuthService::new(
                auth_authority.clone(),
                // we pass the guard function to use with this auth service
                verify_service_request,
            )))
    })
    .bind(("127.0.0.1", 42069))?
    .run()
    .await
}

#[get("/hello")]
async fn hello(user_claims: UserClaims) -> impl Responder {
    format!("Hello user with id: {}!", user_claims.id)
}

// calling this route will give you access to the rest of the apps scopes
#[get("/login")]
async fn login(auth_authority: Data<Authority<UserClaims>>) -> Result<HttpResponse, AuthError> {
    let cookie = auth_authority.create_signed_cookie(UserClaims {
        id: 69,
        role: Role::Admin,
    })?;

    Ok(HttpResponse::Accepted()
        .cookie(cookie)
        .body("You are now logged in"))
}

// calling this route will not give you access to the rest of the apps scopes because you are not an admin
#[get("/login-as-base-user")]
async fn login_as_base_user(
    auth_authority: Data<Authority<UserClaims>>,
) -> Result<HttpResponse, AuthError> {
    let cookie = auth_authority.create_signed_cookie(UserClaims {
        id: 69,
        role: Role::BaseUser,
    })?;

    Ok(HttpResponse::Accepted()
        .cookie(cookie)
        .body("You are now logged in"))
}
```
*/

mod authority;
mod errors;
mod middleware;
mod service;

#[doc(inline)]
pub use actix_jwt_auth_middleware_derive::FromRequest;

pub use authority::*;
pub use errors::*;
use middleware::*;
pub use service::*;
