use actix_jwt_auth_middleware::use_jwt::UseJWTRestOnApp;
use actix_jwt_auth_middleware::AuthResult;
use actix_jwt_auth_middleware::ApiAuthority;
use actix_jwt_auth_middleware::TokenSigner;
use actix_jwt_auth_middleware::FromRequest;

use actix_web::get;
use actix_web::web;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;
use actix_web::Responder;
use exonum_crypto::KeyPair;
use jwt_compact::alg::Ed25519;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone, Debug, FromRequest)]
struct User {
    id: u32,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::random();

    let authority = ApiAuthority::<User, _>::new()
        .verifying_key(key_pair.public_key().clone())
        .algorithm(Ed25519)
        .build()?;

    Ok(HttpServer::new(move || {
        App::new()
            .service(login)
            .use_jwt_rest(authority.clone(), web::scope("").service(hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?)
}

#[get("/login")]
async fn login(cookie_signer: web::Data<TokenSigner<User, Ed25519>>) -> AuthResult<HttpResponse> {
    let user = User { id: 1 };
    Ok(HttpResponse::Ok()
        .cookie(cookie_signer.create_access_cookie(&user)?)
        .cookie(cookie_signer.create_refresh_cookie(&user)?)
        .body("You are now logged in"))
}

// Your Claim type can be extracted from within the wrapped services.
//
// Note:    your Claim type has to implement the FromRequest trait
//          or you have to annotated with the FromRequest derive macro provided in this crate.
//
#[get("/hello")]
async fn hello(user: User) -> impl Responder {
    web::Json(user)
}
