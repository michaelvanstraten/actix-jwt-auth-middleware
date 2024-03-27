use crate::AuthError;
use crate::AuthResult;

use jwt_compact::Algorithm;
use jwt_compact::AlgorithmExt;
use jwt_compact::TimeOptions;
use jwt_compact::Token;
use jwt_compact::UntrustedToken;
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
            match algorithm
                .validator(verifying_key)
                .validate(&untrusted_token)
            {
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
