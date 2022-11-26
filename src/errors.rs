use actix_web::{body::BoxBody, http::StatusCode, HttpResponse, ResponseError};
use jwt_compact::{CreationError, ParseError, ValidationError};

pub type AuthResult<T> = Result<T, AuthError>;

/**
    Crate wide error type

    if #[cfg(debug_assertions)] is true the wrapped errors in (TokenCreation, TokenValidation, TokenParse, Internal) are in included in the error message.
*/

#[derive(Debug)]
pub enum AuthError {
    Unauthorized,
    NoCookieSigner,
    TokenCreation(CreationError),
    TokenValidation(ValidationError),
    TokenParse(ParseError),
    Internal(actix_web::Error),
}

impl Into<AuthError> for CreationError {
    fn into(self) -> AuthError {
        AuthError::TokenCreation(self)
    }
}

impl Into<AuthError> for ParseError {
    fn into(self) -> AuthError {
        AuthError::TokenParse(self)
    }
}

impl Into<AuthError> for ValidationError {
    fn into(self) -> AuthError {
        AuthError::TokenValidation(self)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(debug_assertions))]
        {
            f.write_str(&match self {
                AuthError::Unauthorized => "You are not authorized to interact with this scope",
                AuthError::TokenValidation(_) => "It seems your token could not be verified",
                AuthError::TokenParse(_) => "It seems there has been an error parsing your token",
                AuthError::Internal(_)
                | AuthError::NoCookieSigner
                | AuthError::TokenCreation(_) => "There has been an internal error.",
            })
        }

        #[cfg(debug_assertions)]
        match self {
            AuthError::Unauthorized => {
                f.write_str("You are not authorized to interact with this Scope")
            }
            AuthError::TokenCreation(err) => f.write_fmt(format_args!(
                "There was an internal error creating your token.\n\t Error: \"{err}\""
            )),
            AuthError::TokenValidation(err) => f.write_fmt(format_args!(
                "It seems your token could not be verified.\n\t Error: \"{err}\""
            )),
            AuthError::TokenParse(err) => f.write_fmt(format_args!(
                "It seems there has been an error parsing your token.\n\t Error: \"{err}\""
            )),
            AuthError::Internal(err) => f.write_fmt(format_args!(
                "There has been a internal error relating to actix web. \n\t Error \"{err}\""
            )),
            AuthError::NoCookieSigner => f.write_str("It appears that no new token could be created because no cookie signer was configured. Please configure a CookieSigner."),
        }
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::Unauthorized | AuthError::TokenValidation(_) => StatusCode::UNAUTHORIZED,
            AuthError::TokenCreation(_) | AuthError::NoCookieSigner => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AuthError::TokenParse(_) => StatusCode::BAD_REQUEST,
            AuthError::Internal(err) => err.as_response_error().status_code(),
        }
    }
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}
