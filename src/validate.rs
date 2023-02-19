use crate::{AuthError, AuthResult};

use jwt_compact::{Algorithm, AlgorithmExt, TimeOptions, Token, UntrustedToken};
use serde::de::DeserializeOwned;

pub(crate) fn validate_jwt<T, Algo, Claims>(
    value: &T,
    algorithm: &Algo,
    verifying_key: &Algo::VerifyingKey,
    time_options: &TimeOptions,
) -> AuthResult<Token<Claims>>
where
    T: AsRef<str>,
    Algo: Algorithm,
    Claims: DeserializeOwned,
{
    match UntrustedToken::new(&value) {
        Ok(untrusted_token) => {
            match algorithm.validate_integrity::<Claims>(&untrusted_token, verifying_key) {
                Ok(token) => match token.claims().validate_expiration(time_options) {
                    Ok(_) => Ok(token),
                    Err(err) => Err(AuthError::TokenValidation(err)),
                },
                Err(err) => Err(err.into()),
            }
        }
        Err(err) => Err(err.into()),
    }
}
