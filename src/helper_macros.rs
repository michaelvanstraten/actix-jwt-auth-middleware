macro_rules! pull_from_token_signer {
    ($self:ident ,$field_name:ident) => {
        match $self.token_signer {
            Some(Some(ref value)) => value.$field_name.clone(),
            _ => {
                return ::derive_builder::export::core::result::Result::Err(
                    ::derive_builder::export::core::convert::Into::into(
                        ::derive_builder::UninitializedFieldError::from(stringify!($field_name)),
                    ),
                );
            }
        }
    };

    ($self:ident, $field_name:ident, $alternative:expr) => {
        match $self.token_signer {
            Some(Some(ref value)) => value.$field_name.clone(),
            _ => $alternative,
        }
    };
}

macro_rules! return_token_update {
    () => {
        Ok(Some(TokenUpdate {
            access_cookie: None,
            refresh_cookie: None,
        }))
    };

    ($access_cookie:expr) => {
        Ok(Some(TokenUpdate {
            access_cookie: Some($access_cookie),
            refresh_cookie: None,
        }))
    };

    ($access_cookie:expr, $refresh_cookie:expr) => {
        Ok(Some(TokenUpdate {
            access_cookie: Some($access_cookie),
            refresh_cookie: Some($refresh_cookie),
        }))
    };
}

pub(crate) use pull_from_token_signer;
pub(crate) use return_token_update;
