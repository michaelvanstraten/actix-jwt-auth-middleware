use actix_jwt_auth_middleware::{
    Authority, CookieSigner, FromRequest, UseJWTOnApp,
};
use actix_web::{get, web, App, HttpServer, Responder};
use exonum_crypto::KeyPair;
use jwt_compact::alg::Ed25519;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, FromRequest)]
#[serde(tag = "role")]
enum Role {
    Admin,
    User,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::random();

    let authority = Authority::<Role, _, _, _>::new()
        .re_authorizer(|| async move { Ok(()) })
        .cookie_signer(
            CookieSigner::new()
                .signing_key(key_pair.secret_key().clone())
                .algorithm(Ed25519)
                .build()?,
        )
        .verifying_key(key_pair.public_key().clone())
        .build()?;

    Ok(HttpServer::new(move || {
        App::new()
            .use_jwt(authority.clone())
            .service(
                web::scope("/admin-only")
                    .route(
                        "/",
                        web::get().to(|| async { "You are definitely a admin!" }),
                    ),
            )
    })
    .bind(("127.0.0.1", 42069))?
    .run()
    .await?)
}

#[get("/hello")]
async fn hello(role: Role) -> impl Responder {
    format!("Hello there, i see you are a {role:?}.")
}
