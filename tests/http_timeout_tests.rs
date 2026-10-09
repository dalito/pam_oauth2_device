mod utils;

use std::net::TcpListener;
use std::time::{Duration, Instant};

use oauth2::AccessToken;
use pam_oauth2_device::config::Config;
use pam_oauth2_device::oauth_device::OAuthClient;

/// A server that completes the TCP handshake and never answers.
///
/// The kernel accepts connections into the backlog without `accept()`, so a
/// request is sent and its reply never comes, as from an OAuth server that hangs.
fn silent_server() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (listener, url)
}

fn client_with_timeout(url: &String, seconds: u64) -> OAuthClient {
    let mut config = utils::mock_config(url, None);
    config.http_timeout = Duration::from_secs(seconds);
    OAuthClient::new(&config).unwrap()
}

fn assert_gives_up<T>(result: Result<T, Box<dyn std::error::Error>>, started: Instant) {
    let elapsed = started.elapsed();
    let err = result.err().expect("a silent server must fail the request");
    assert!(
        elapsed < Duration::from_secs(5),
        "gave up after {elapsed:?}"
    );
    let chain = format!("{err:?}");
    assert!(chain.contains("Timeout was reached"), "{chain}");
}

#[test]
fn introspection_gives_up_on_a_silent_server() {
    let (_listener, url) = silent_server();
    let client = client_with_timeout(&url, 1);

    let started = Instant::now();
    let result = client.introspect(&AccessToken::new("token".to_string()));

    assert_gives_up(result, started);
}

#[test]
fn revocation_gives_up_on_a_silent_server() {
    let (_listener, url) = silent_server();
    let client = client_with_timeout(&url, 1);

    let started = Instant::now();
    let result = client.revoke(&AccessToken::new("token".to_string()));

    assert_gives_up(result, started);
}

#[test]
fn the_device_code_request_gives_up_on_a_silent_server() {
    let (_listener, url) = silent_server();
    let client = client_with_timeout(&url, 1);

    let started = Instant::now();
    let result = client.device_code();

    assert_gives_up(result, started);
}

#[test]
fn the_timeout_defaults_to_ten_seconds() {
    let config: Config = serde_json::from_str(
        r#"{
            "client_id": "c",
            "client_secret": "s",
            "oauth_auth_url": "http://cared/o/authorize/",
            "oauth_device_url": "http://cared/o/device-authorization/",
            "oauth_token_url": "http://cared/o/token/",
            "oauth_token_introspect_url": "http://cared/o/introspect/"
        }"#,
    )
    .unwrap();

    assert_eq!(config.http_timeout, Duration::from_secs(10));
}
