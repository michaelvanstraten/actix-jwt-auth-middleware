use actix_jwt_auth_middleware::use_jwt::UseJWTOnApp;
use actix_jwt_auth_middleware::{AuthResult, Authority, FromRequest, TokenSigner};

use actix_state_guards::UseStateGuardOnScope;

use actix_web::error::InternalError;
use actix_web::http::StatusCode;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use exonum_crypto::KeyPair;
use jwt_compact::alg::Ed25519;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, FromRequest)]
struct User {
    role: Role,
    id: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, FromRequest, PartialEq)]
enum Role {
    Basic,
    Admin,
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

        App::new().service(login).use_jwt(
            authority,
            web::scope("").service(hello).use_state_guard(
                |user: User| async move {
                    if user.role == Role::Admin {
                        Ok(())
                    } else {
                        Err(InternalError::new(
                            "You are not an Admin",
                            StatusCode::UNAUTHORIZED,
                        ))
                    }
                },
                web::scope("").service(admin),
            ),
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;

    Ok(())
}

#[get("/login")]
async fn login(
    user: web::Query<User>,
    cookie_signer: web::Data<TokenSigner<User, Ed25519>>,
) -> AuthResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .cookie(cookie_signer.create_access_cookie(&user)?)
        .cookie(cookie_signer.create_refresh_cookie(&user)?)
        .body("You are now logged in"))
}

/*
    Your Claim type can be extracted from within the wrapped services.

    Note:    your Claim type has to implement the FromRequest trait
             or you have to annotated with the FromRequest derive macro provided in this crate.

*/
#[get("/hello")]
async fn hello(user: User) -> impl Responder {
    format!("Hello there, i see your user id is {}.", user.id)
}

#[get("/admin")]
async fn admin() -> impl Responder {
    format!("You are an Admin, you must be importent")
}
