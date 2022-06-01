//! # Actix-jwt-auth-middleware
//!
//! This crate implements a JSON Webtoken (JWT) middleware for the actix-web framework.
//!
//! For the moment it uses Curve25519 implemented in the ```ed25519_dalek``` crate for the signing process of the token but i will be working on a generalization soon.
//!
//! ## Features
//!
//! Automatic insertion and extraction of claims into the ```actix_web::Extensions``` object on the request. For this your type has to implement the ```actix_web::FromRequest``` trait or it has to be annotated with the ```#[derive(actix-jwt-auth-middleware::FromRequest)]``` macro which implements this trait for your type.
//!
//! ```rust
//! #[derive(Serialize, Deserialize, Clone, FromRequest)]
//! struct UserClaims {
//!     id: u32,
//!     role: Role,
//! }
//!
//! #[derive(Serialize, Deserialize, Clone)]
//! enum Role {
//!     Admin,
//!     BaseUser,
//! }
//!
//!
//! #[get("/hello")]
//! async fn hello(user_claims: UserClaims) -> impl Responder {
//!     format!("Hello user with id: {}!", user_claims.id)
//! }
//! ```
//!
//! Simple Guard functions on top of JWT authentication
//!
//! ```rust
//! Authority::<UserClaims>::default_with_guard_fn(
//!     |user_claims| match user_claims.role {
//!         Role::Admin => true,
//!         Role::BaseUser => false,
//!     }
//! );
//! ```
//!
//! ## Example 
//!
//! ```rust
//! use actix_jwt_auth_middleware::{AuthError, AuthService, Authority};
//! use actix_web::{
//!     get,
//!     web::{self, Data},
//!     App, HttpResponse, HttpServer,
//! };
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct UserClaims {
//!     id: u32,
//!     role: Role,
//! }
//!
//! #[derive(Serialize, Deserialize)]
//! enum Role {
//!     Admin,
//!     BaseUser,
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // we initialize a new Authority with a guard function
//!     let auth_authority =
//!         Authority::<UserClaims>::default_with_guard_fn(|user_claims| match user_claims.role {
//!             Role::Admin => true,
//!             Role::BaseUser => false,
//!         });
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .app_data(Data::new(auth_authority.clone()))
//!             .service(login)
//!             .service(login_as_base_user)
//!             // in order to wrap the entire app scope excluding the login handlers we have add a new service first
//!             .service(
//!                 web::scope("")
//!                     .wrap(AuthService::new(auth_authority.clone()))
//!                     .route(
//!                         "/hello",
//!                         web::get().to(|| async { "I see you are logged in" }),
//!                     ),
//!             )
//!     })
//!     .bind(("127.0.0.1", 8080))?
//!     .run()
//!     .await
//! }
//!
//! // calling this route will give you access to the rest of the apps scopes
//! #[get("/login")]
//! async fn login(auth_authority: Data<Authority<UserClaims>>) -> Result<HttpResponse, AuthError> {
//!     let cookie = auth_authority.create_signed_cookie(UserClaims {
//!         id: 69,
//!         role: Role::Admin,
//!     })?;
//!
//!     Ok(HttpResponse::Accepted()
//!         .cookie(cookie)
//!         .body("You are now logged in"))
//! }
//!
//! // calling this route will not give you access to the rest of the apps scopes because you are not an admin
//! #[get("/login-as-base-user")]
//! async fn login_as_base_user(
//!     auth_authority: Data<Authority<UserClaims>>,
//! ) -> Result<HttpResponse, AuthError> {
//!     let cookie = auth_authority.create_signed_cookie(UserClaims {
//!         id: 69,
//!         role: Role::BaseUser,
//!     })?;
//!
//!     Ok(HttpResponse::Accepted()
//!         .cookie(cookie)
//!         .body("You are now logged in"))
//! }
//! ```

mod authority;
mod errors;
mod middleware;
mod service;

pub use authority::*;
pub use errors::*;
use middleware::*;
pub use service::*;
pub use actix_jwt_auth_middleware_macros::FromRequest;