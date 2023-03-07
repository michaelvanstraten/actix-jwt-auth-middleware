use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::{Error as ActixWebError, HttpResponse, ResponseError};
use jwt_compact::{CreationError, ParseError, ValidationError};

pub type AuthResult<T> = Result<T, AuthError>;

/**
    Crate wide error type

    if `#[cfg(debug_assertions)]` is true
    the wrapped errors in (Internal, RefreshAuthorizerDenied, TokenCreation, TokenParse, TokenValidation)
    are in included in the error message.
*/
#[derive(Debug)]
pub enum AuthError {
    NoToken,
    NoTokenSigner,
    RefreshAuthorizerCall(ActixWebError),
    RefreshAuthorizerDenied(ActixWebError),
    TokenCreation(CreationError),
    TokenParse(ParseError),
    TokenValidation(ValidationError),
}

impl PartialEq for AuthError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::TokenCreation(_), Self::TokenCreation(_))
            | (Self::TokenValidation(_), Self::TokenValidation(_))
            | (Self::TokenParse(_), Self::TokenParse(_))
            | (Self::RefreshAuthorizerCall(_), Self::RefreshAuthorizerCall(_)) => true,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
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
        const NO_TOKEN_MESSAGE: &str = "An error occurred, no cookie containing a jwt was found in the request. Please first authenticate with this application.";

        #[cfg(not(debug_assertions))]
        match self {
            AuthError::NoToken => f.write_str(NO_TOKEN_MESSAGE),
            AuthError::RefreshAuthorizerDenied(err) => f.write_str(&err.to_string()),
            AuthError::TokenParse(_) | AuthError::TokenValidation(_) => {
                f.write_str("An error occurred, the provided jwt could not be processed.")
            }
            AuthError::RefreshAuthorizerCall(_)
            | AuthError::NoTokenSigner
            | AuthError::TokenCreation(_) => {
                f.write_str("An internal error occurred. Please try again later.")
            }
        }
        #[cfg(debug_assertions)]
        match self {
            AuthError::NoToken => f.write_str(NO_TOKEN_MESSAGE),
            AuthError::NoTokenSigner => f.write_str(
                "An error occurred because no CookieSigner was configured on the Authority struct.",
            ),
            AuthError::TokenCreation(err) => f.write_fmt(format_args!(
                "An error occurred creating the jwt.\n\t Error: \"{err}\""
            )),
            AuthError::TokenValidation(err) => f.write_fmt(format_args!(
                "An error occurred validating the jwt.\n\t Error: \"{err}\""
            )),
            AuthError::TokenParse(err) => f.write_fmt(format_args!(
                "An error occurred parsing the jwt.\n\t Error: \"{err}\""
            )),
            AuthError::RefreshAuthorizerDenied(err) | AuthError::RefreshAuthorizerCall(err) => {
                f.write_str(&err.to_string())
            }
        }
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::TokenCreation(_) | AuthError::NoTokenSigner => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AuthError::TokenParse(_) => StatusCode::BAD_REQUEST,
            AuthError::NoToken | AuthError::TokenValidation(_) => StatusCode::UNAUTHORIZED,
            AuthError::RefreshAuthorizerCall(err) | AuthError::RefreshAuthorizerDenied(err) => {
                err.as_response_error().status_code()
            }
        }
    }
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            AuthError::RefreshAuthorizerDenied(err) | AuthError::RefreshAuthorizerCall(err) => {
                err.error_response()
            }
            _ => HttpResponse::build(self.status_code()).body(self.to_string()),
        }
    }
}
