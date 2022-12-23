use actix_jwt_auth_middleware::{AuthError, Authority, CookieSigner};
use actix_web::{cookie::Cookie, test::TestRequest};
use chrono::{Duration, Utc};
use exonum_crypto::KeyPair;
use jwt_compact::{
    alg::Ed25519, Claims, Header, ParseError, TimeOptions, ValidationError::Expired as TokenExpired,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct TestClaims {}

lazy_static! {
    static ref KEY_PAIR: KeyPair = KeyPair::random();
    static ref TIME_OPTIONS: TimeOptions = TimeOptions::from_leeway(Duration::min_value());
    static ref HEADER: Header = Header::default();
    static ref CLAIMS: Claims<TestClaims> = Claims::new(TestClaims {});
    static ref COOKIE_SIGNER: CookieSigner<TestClaims, Ed25519> = CookieSigner::new()
        .algorithm(Ed25519)
        .signing_key(KEY_PAIR.secret_key().clone())
        .build()
        .unwrap();
}

#[actix_web::test]
async fn valid_access_token() {
    let authority: Authority<TestClaims, _, _, _> = Authority::new()
        .algorithm(Ed25519)
        .verifying_key(KEY_PAIR.public_key())
        .time_options(*TIME_OPTIONS)
        .refresh_authorizer(|| async { Ok(()) })
        .build()
        .unwrap();

    let req = TestRequest::default()
        .cookie(
            COOKIE_SIGNER
                .create_access_token_cookie(&TestClaims {})
                .unwrap(),
        )
        .to_srv_request();

    assert!(authority.verify_service_request(req).await.is_ok())
}

#[actix_web::test]
async fn valid_access_token_header() {
    let authority: Authority<TestClaims, _, _, _> = Authority::new()
        .algorithm(Ed25519)
        .verifying_key(KEY_PAIR.public_key())
        .time_options(*TIME_OPTIONS)
        .refresh_authorizer(|| async { Ok(()) })
        .enable_header_tokens(true)
        .build()
        .unwrap();

    let cookie =  COOKIE_SIGNER
        .create_access_token_cookie(&TestClaims {})
        .unwrap();  

    let req = TestRequest::default()
        .insert_header((
            cookie.name(),
                cookie.value(),
        ))
        .to_srv_request();

    assert!(authority.verify_service_request(req).await.is_ok())
}

#[actix_web::test]
async fn deactivated_access_token_header() {
    let authority: Authority<TestClaims, _, _, _> = Authority::new()
        .algorithm(Ed25519)
        .verifying_key(KEY_PAIR.public_key())
        .time_options(*TIME_OPTIONS)
        .refresh_authorizer(|| async { Ok(()) })
        .build()
        .unwrap();

    let cookie =  COOKIE_SIGNER
        .create_access_token_cookie(&TestClaims {})
        .unwrap();  

    let req = TestRequest::default()
        .insert_header((
            cookie.name(),
            cookie.value(),
        ))
        .to_srv_request();

    assert_eq!(
        authority
            .verify_service_request(req)
            .await
            .expect_err("Testing no token case"),
        AuthError::NoCookie
    )

}

#[actix_web::test]
async fn valid_refresh_token() {
    let authority: Authority<TestClaims, _, _, _> = Authority::new()
        .verifying_key(KEY_PAIR.public_key())
        .cookie_signer(Some(COOKIE_SIGNER.clone()))
        .refresh_authorizer(|| async { Ok(()) })
        .build()
        .unwrap();

    let req = TestRequest::default()
        .cookie(
            COOKIE_SIGNER
                .create_refresh_token_cookie(&TestClaims {})
                .unwrap(),
        )
        .to_srv_request();

    assert!(authority.verify_service_request(req).await.is_ok())
}

#[actix_web::test]
async fn no_token() {
    let authority: Authority<TestClaims, _, _, _> = Authority::new()
        .algorithm(Ed25519)
        .verifying_key(KEY_PAIR.public_key())
        .time_options(*TIME_OPTIONS)
        .refresh_authorizer(|| async { Ok(()) })
        .build()
        .unwrap();

    let req = TestRequest::default().to_srv_request();

    assert_eq!(
        authority
            .verify_service_request(req)
            .await
            .expect_err("Testing no token case"),
        AuthError::NoCookie
    )
}

#[actix_web::test]
async fn expired_token() {
    let authority: Authority<TestClaims, _, _, _> = Authority::new()
        .algorithm(Ed25519)
        .time_options(TimeOptions::new(Duration::seconds(0), || {
            Utc::now() + Duration::minutes(5)
        }))
        .verifying_key(KEY_PAIR.public_key())
        .renew_access_token_automatically(false)
        .refresh_authorizer(|| async { Ok(()) })
        .build()
        .unwrap();

    let req = TestRequest::default()
        .cookie(
            COOKIE_SIGNER
                .create_access_token_cookie(&TestClaims {})
                .unwrap(),
        )
        .to_srv_request();

    assert_eq!(
        authority
            .verify_service_request(req)
            .await
            .expect_err("Testing expired token case"),
        AuthError::TokenValidation(TokenExpired)
    )
}

#[actix_web::test]
async fn nonce_token() {
    let authority: Authority<TestClaims, _, _, _> = Authority::new()
        .algorithm(Ed25519)
        .time_options(TimeOptions::new(Duration::seconds(0), || {
            Utc::now() + Duration::minutes(5)
        }))
        .verifying_key(KEY_PAIR.public_key())
        .renew_access_token_automatically(false)
        .refresh_authorizer(|| async { Ok(()) })
        .build()
        .unwrap();

    let req = TestRequest::default()
        .cookie(Cookie::build("access_token", "not-a-valid-token").finish())
        .to_srv_request();

    assert_eq!(
        authority
            .verify_service_request(req)
            .await
            .expect_err("Testing not parsable token case"),
        AuthError::TokenParse(ParseError::InvalidTokenStructure)
    )
}
