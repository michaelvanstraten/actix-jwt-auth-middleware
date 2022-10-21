use actix_jwt_auth_middleware::{AuthError, AuthService, Authority, FromRequest};
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

    let auth_authority = Authority::<Role, _, _, _>::new()
                            .re_authorizer(|_: Role| async move { Ok(()) })
                            .algorithm(Ed25519)
                            .build()
                            .unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(auth_authority.clone()))
            // .service(login)
            // in order to wrap the entire app scope excluding the login handlers we have add a new service
            // with an empty scope first
            .service(
                web::scope("")
                    .service(hello)
                    // .wrap(AuthService::new(auth_authority.clone(), || async { true })),
            )
            .service(
                web::scope("admin-only")
                    .route(
                        "/",
                        web::get().to(|| async { "You are definitely a admin!" }),
                    )
                    .wrap(AuthService::new(
                        auth_authority.clone(),
                        |role: Role| async move { role.eq(&Role::Admin) },
                    )),
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
