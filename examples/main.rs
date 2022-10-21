use actix_jwt_auth_middleware::{AuthError, AuthService, Authority, FromRequest, JWTRequired};
use actix_web::{
    get,
    web::{self, Data},
    App, HttpResponse, HttpServer, Responder,
};
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
async fn main() -> std::io::Result<()> {
    let key_pair = KeyPair::random();

    let authority = Authority::<Role, _, _, _>::new()
                            .re_authorizer(|_: Role| async move { Ok(()) })
                            .signing_key(key_pair.secret_key().clone())
                            .verifying_key(key_pair.public_key().clone())
                            .algorithm(Ed25519)
                            .build()
                            .unwrap();

    HttpServer::new(move || {
        App::new()
            .service(
                web::scope("")
                    .service(hello)
                    .jwt_required(authority.clone())
            )
            .service(
                web::scope("/admin-only")
                    .jwt_required(authority.clone())
                    .route(
                        "/",
                        web::get().to(|| async { "You are definitely a admin!" }),
                    )
            )
    })
    .bind(("127.0.0.1", 42069))?
    .run()
    .await
}

#[get("/hello")]
async fn hello(role: Role) -> impl Responder {
    format!("Hello there, i see you are a {role:?}.")
}

// calling this route will log you in as a Admin/User dependent on the path.
// #[get("/login/{role}")]
// async fn login(
//     auth_authority: Data<Authority<Role, Ed25519, _, _>>,
//     role: web::Path<Role>,
// ) -> Result<HttpResponse, AuthError> {
//     let cookie = auth_authority.create_signed_cookie(role.into_inner())?;

//     Ok(HttpResponse::Accepted()
//         .cookie(cookie)
//         .body("You are now logged in"))
// }
