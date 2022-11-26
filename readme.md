# actix-jwt-auth-middleware

This crate build upon the [jwt-compact](https://github.com/slowli/jwt-compact) crate
to provide a jwt authentication middleware for the [actix-web](https://github.com/actix/actix-web) framework.

The jwt implementation support the revocation for tokens via `auth` and `refresh` tokens.

It provides multiple cryptographic signing and verifying algorithms such as `HS256`, `HS384`, `HS512`, `EdDSA` and `ES256`.
For more infos on that mater please refer to the [jwt-compact](https://github.com/slowli/jwt-compact) crate.

## Features
- easy use of custom jwt claims
- automatic extractor of the custom claims
- verify only mode (only `public key` required)
- automatic renewal of `auth` token (customizable)
- easy way to set expiration time of `auth` and `refresh` tokens
- simple `UseJWT` trait for protecting a `App`, `Resource` or `Scope` (experimental feature)
- refresh authorizer function that has access to application state

It is tightly integrates into the actix-web ecosystem,
this makes it easy to Automatic extract the jwt claims from a valid token.

```rust
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
        format!("Hello user with id: {}, i see you are a {:?}!", user_claims.id, user_claims.role)
    }
```

For this your custom claim type has to implement the [FromRequest](actix_web::FromRequest) trait
or it has to be annotated with the `#[derive(actix-jwt-auth-middleware::FromRequest)]` macro which implements this trait for your type.

## Simple Example

```rust
    let key_pair = KeyPair::random();
    let authority = Authority::<Role, _, _, _>::new()
        .re_authorizer(|| async move { Ok(()) })
        .cookie_signer(Some(
            CookieSigner::new()
                .signing_key(key_pair.secret_key().clone())
                .algorithm(Ed25519)
                .build()?,
        ))
        .verifying_key(key_pair.public_key().clone())
        .build()?;

    HttpServer::new(move || {
        App::new()
            .use_jwt(authority.clone())
            .service(greet)
    })
    .bind(("127.0.0.1", 42069))?
    .run()
    .await?
```

For more example please referee to the `examples` directory.

License: MIT
