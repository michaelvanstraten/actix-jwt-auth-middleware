# actix-jwt-auth-middleware-macros

This crate provides a derive macro for the `actix_web::FromRequest` trait

## Example

```rust
use actix-jwt-auth-middleware-macros::FromRequest;
#[derive(Clone, FromRequest)]
struct UserClaims {
    id: u32,
    role: Role,
}
```