/*!
This crate provides a derive macro for the [FromRequest](actix_web::FromRequest) trait.
*/

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use syn::DeriveInput;
use syn::Ident;

/**
This macro implements the [FromRequest](actix_web::FromRequest) trait for the annotated type.

## Example

```rust
use actix-jwt-auth-middleware-macros::FromRequest;
#[derive(Clone, FromRequest)]
struct UserClaims {
    id: u32,
    role: Role,
}
*/
#[proc_macro_derive(FromRequest)]
pub fn from_request(tokenstream: TokenStream) -> TokenStream {
    let abstract_syntax_tree = parse_macro_input!(tokenstream as DeriveInput);
    let type_identifier = abstract_syntax_tree.ident;

    let lower_case_identifier = Ident::new(
        &type_identifier.to_string().to_lowercase(),
        type_identifier.span(),
    );

    let error = format!(
        "could not extract type \"{}\" from HttpRequest extensions",
        type_identifier.to_string()
    );

    quote!(
        // stolen from https://stackoverflow.com/questions/63673447/how-can-i-pass-structs-from-an-actix-middleware-to-the-handler

        impl actix_web::FromRequest for #type_identifier { // works
            type Error = actix_web::Error;
            type Future = std::future::Ready<Result<Self, Self::Error>>;
            fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
                std::future::ready(
                    match <actix_web::HttpRequest as actix_web::HttpMessage>::extensions(req).get::<#type_identifier>() {
                        Some(#lower_case_identifier) => Ok(#lower_case_identifier.clone()),
                        None => Err(actix_web::error::ErrorBadRequest(#error))
                    }
                )
            }
        }
    )
    .into()
}
