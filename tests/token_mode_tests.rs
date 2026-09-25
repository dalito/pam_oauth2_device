mod test_logger;
mod utils;

use oauth2::AccessToken;
use pam_oauth2_device::logger::Logger;
use pam_oauth2_device::oauth_device::OAuthClient;
use utils::{mock_config, Mock};

use test_logger::{TestLogger, LOGGER};

fn token() -> AccessToken {
    AccessToken::new("mocking_access_token".to_string())
}

#[test]
fn a_token_issued_to_this_client_is_accepted() {
    let (mut mock, oauth_client) = Mock::builder()
        .username(Some("test"))
        .scope(Some("openid"))
        .init(Some("openid"));
    mock.http_introspect_with_status(200);

    let introspection = oauth_client.introspect(&token()).unwrap();

    assert!(oauth_client.issued_to_me(&introspection));
}

#[test]
fn a_token_issued_to_another_client_is_refused() {
    let (mut mock, oauth_client) = Mock::builder()
        .username(Some("test"))
        .scope(Some("openid"))
        .introspected_client_id(Some("another"))
        .init(Some("openid"));
    let logger = LOGGER.lock().unwrap();
    mock.http_introspect_with_status(200);

    let introspection = oauth_client.introspect(&token()).unwrap();

    assert!(!oauth_client.issued_to_me(&introspection));
    assert_eq!(logger.msg(), "Token issued to another client: another");
}

#[test]
fn a_token_naming_no_client_is_refused() {
    let (mut mock, oauth_client) = Mock::builder()
        .username(Some("test"))
        .scope(Some("openid"))
        .introspected_client_id(None)
        .init(Some("openid"));
    let logger = LOGGER.lock().unwrap();
    mock.http_introspect_with_status(200);

    let introspection = oauth_client.introspect(&token()).unwrap();

    assert!(!oauth_client.issued_to_me(&introspection));
    assert_eq!(logger.msg(), "No client_id provided in token");
}

#[test]
fn revocation_posts_the_token_with_body_credentials_over_http() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    let revoke = mock.http_revoke_with_status(200);

    oauth_client.revoke(&token()).unwrap();

    revoke.assert();
}

#[test]
fn a_refused_revocation_is_an_error_that_does_not_carry_the_token() {
    let (mut mock, oauth_client) = Mock::builder().init(None);
    let logger = LOGGER.lock().unwrap();
    mock.http_revoke_with_status(401);

    let result = oauth_client.revoke(&token());

    assert!(result.is_err());
    let _ =
        result.map_err(|err| TestLogger::handle_error(err, "Failed to revoke sign-in password"));
    assert!(logger
        .msg()
        .starts_with("Failed to revoke sign-in password"));
    assert!(!logger.msg().contains("mocking_access_token"));
}

#[test]
fn revocation_needs_a_configured_url() {
    let server = mockito::Server::new();
    let mut config = mock_config(&server.url(), None);
    config.oauth_token_revoke_url = None;
    let oauth_client = OAuthClient::new(&config).unwrap();

    assert!(oauth_client.revoke(&token()).is_err());
}
