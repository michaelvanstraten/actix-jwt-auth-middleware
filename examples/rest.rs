use actix_jwt_auth_middleware::AuthResult;
use actix_jwt_auth_middleware::AuthenticationService;
use actix_jwt_auth_middleware::Authority;
use actix_jwt_auth_middleware::CookieSigner;
use actix_jwt_auth_middleware::FromRequest;
use actix_web::get;
use actix_web::web;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;
use actix_web::Responder;
use exonum_crypto::KeyPair;
use jwt_compact::alg::Ed25519;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, FromRequest)]
struct User {
    id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::random();

    let cookie_signer = CookieSigner::new()
        .signing_key(key_pair.secret_key().clone())
        .algorithm(Ed25519)
        .build()?;

    let authority = Authority::<User, _, _, _>::new()
        .refresh_authorizer(|| async move { Ok(()) })
        .cookie_signer(Some(cookie_signer.clone()))
        .verifying_key(key_pair.public_key().clone())
        .enable_header_tokens(true)
        .build()?;

    Ok(HttpServer::new(move || {
        App::new()
            .service(login)
            // we inject the cookie_signer here into the application state
            // in oder to later create a signer jwt cookie
            // from within the login function
            .app_data(web::Data::new(cookie_signer.clone()))
            .service(
                // we need this scope so we can exclude the login service
                // from being wrapped by the jwt middleware
                web::scope("")
                    .service(hello)
                    .wrap(AuthenticationService::new(authority.clone())),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?)
}

#[get("/login")]
async fn login(cookie_signer: web::Data<CookieSigner<User, Ed25519>>) -> AuthResult<HttpResponse> {
    let user = User { id: 1 };

    let access_token = cookie_signer.create_access_token_cookie(&user)?;
    let refresh_token = cookie_signer.create_refresh_token_cookie(&user)?;

    let access_token_value = access_token.value();
    let refresh_token_value = refresh_token.value();

    Ok(HttpResponse::Ok().json(Tokens {
        access_token: access_token_value.to_string(),
        refresh_token: refresh_token_value.to_string(),
    }))
}

#[get("/hello")]
// what ever claim type was wrapped, can be extracted from within the wrapped services.
//
// Note:    your claim type has to implement the FromRequest trait
//          or you have to annotated with the FromRequest derive macro provided in this crate.
//
async fn hello(user: User) -> impl Responder {
    format!("Hello there, i see your user id is {}.", user.id)
}
