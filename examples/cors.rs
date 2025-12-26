use actix_cors::Cors;
use actix_web::{get, http, web, App, HttpRequest, HttpResponse, HttpServer};

#[get("/index.html")]
async fn index(req: HttpRequest) -> &'static str {
    "<p>Hello World!</p>"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("https://www.rust-lang.org")
            .allowed_origin_fn(|origin, _req_head| {
                origin.as_bytes().ends_with(b".rust-lang.org")
            })
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .service(index)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await;

    Ok(())
}
