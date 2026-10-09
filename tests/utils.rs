use chrono::{DateTime, Duration, Utc};
use mockito::{Server, ServerGuard};
use pam_oauth2_device::config::{Config, Messages};
use pam_oauth2_device::oauth_device::OAuthClient;
use url::Url;

macro_rules! builder_setter {
    ($field:ident, optional $type:ty) => {
        pub(crate) fn $field(mut self, $field: Option<$type>) -> Self {
            self.0.$field = $field.map(|s| s.to_owned());
            self
        }
    };
    ($field:ident, $type:ty) => {
        pub(crate) fn $field(mut self, $field: $type) -> Self {
            self.0.$field = $field;
            self
        }
    };
}

pub(crate) struct Mock {
    pub server: ServerGuard,
    username: Option<String>,
    scope: Option<String>,
    active: bool,
    exp: Option<DateTime<Utc>>,
    introspected_client_id: Option<String>,
}

#[allow(dead_code)]
impl Mock {
    pub(crate) fn builder() -> MockBuilder {
        MockBuilder(Self {
            server: Server::new(),
            username: None,
            scope: None,
            active: true,
            exp: Some(chrono::Utc::now() + Duration::seconds(3600)),
            introspected_client_id: Some("test".to_string()),
        })
    }
}

pub(crate) struct MockBuilder(Mock);

#[allow(dead_code)]
impl MockBuilder {
    builder_setter!(active, bool);
    builder_setter!(username, optional & str);
    builder_setter!(scope, optional & str);
    builder_setter!(exp, optional DateTime<Utc>);
    builder_setter!(introspected_client_id, optional & str);

    pub(crate) fn init(self, pam_scopes: Option<&str>) -> (Mock, OAuthClient) {
        let config = mock_config(&self.0.server.url(), pam_scopes);
        let oauth_client = OAuthClient::new(&config)
            .unwrap_or_else(|err| panic!("Failed to create OAuth client: {}", err));
        let mock = Mock {
            server: self.0.server,
            username: self.0.username,
            scope: self.0.scope,
            active: self.0.active,
            exp: self.0.exp,
            introspected_client_id: self.0.introspected_client_id,
        };
        (mock, oauth_client)
    }
}

#[allow(dead_code)]
pub(crate) fn mock_config(url: &String, scope: Option<&str>) -> Config {
    let scope = scope.map(|s| s.to_owned());
    Config {
        client_id: "test".to_string(),
        client_secret: "test".to_string(),
        oauth_auth_url: Url::parse(&format!("{}/{}", url, "auth")).unwrap(),
        oauth_device_url: Url::parse(&format!("{}/{}", url, "device")).unwrap(),
        oauth_token_url: Url::parse(&format!("{}/{}", url, "token")).unwrap(),
        oauth_token_introspect_url: Url::parse(&format!("{}/{}", url, "introspect")).unwrap(),
        oauth_token_revoke_url: Some(Url::parse(&format!("{}/{}", url, "revoke")).unwrap()),
        oauth_device_token_polling_timeout: None,
        http_timeout: std::time::Duration::from_secs(10),
        scopes: scope.unwrap_or_default(),
        qr_enabled: false,
        messages: Messages::default(),
    }
}

#[allow(dead_code)]
impl Mock {
    pub(crate) fn http_device_basic(&mut self) {
        self.server
            .mock("POST", "/device")
            .with_status(200)
            .with_body(
                r#"{
            "device_code": "mocking_device_code",
            "user_code": "mocking_user_code",
            "verification_uri": "https://mocking.uri/",
            "expires_in": 3600,
            "interval": 5
        }"#,
            )
            .create();
    }

    pub(crate) fn http_device_complete(&mut self) {
        self.server
            .mock("POST", "/device")
            .with_status(200)
            .with_body(
                r#"{
            "device_code": "mocking_device_code",
            "user_code": "mocking_user_code",
            "verification_uri": "https://mocking.uri/",
            "verification_uri_complete": "https://mocking.uri/mocking_user_code",
            "expires_in": 3600,
            "interval": 5
        }"#,
            )
            .create();
    }

    #[allow(dead_code)]
    pub(crate) fn http_token_with_status(&mut self, status: usize) {
        let body = match status {
            200..=299 => {
                r#"{
        "access_token": "mocking_access_token",
        "refresh_token": "mocking_refresh_token",
        "id_token": "mocking_id_token",
        "token_type": "Bearer",
        "expires_in": 86400
            }"#
            }
            _ => {
                r#"{
        "error": "access_denied",
        "error_description": "Authorization for user is still pending."
            }"#
            }
        };
        self.server
            .mock("POST", "/token")
            .with_status(status)
            .with_body(body)
            .create();
    }

    #[allow(dead_code)]
    pub(crate) fn http_introspect_with_status(&mut self, status: usize) {
        let username = self
            .username
            .as_ref()
            .map(|u| format!(r#""{}""#, u))
            .unwrap_or("null".to_string());
        let scope = self
            .scope
            .as_ref()
            .map(|u| format!(r#""{}""#, u))
            .unwrap_or("null".to_string());
        let exp = self
            .exp
            .as_ref()
            .map(|e| format!("{}", e.timestamp()))
            .unwrap_or("null".to_string());
        let client_id = self
            .introspected_client_id
            .as_ref()
            .map(|c| format!(r#""{}""#, c))
            .unwrap_or("null".to_string());
        let body = match status {
            200..=299 => format!(
                r#"{{
        "active": {},
        "scope": {},
        "client_id": {},
        "username": {},
        "token_type": "Bearer",
        "exp": {},
        "iat": 1713949569,
        "nbf": 1713949569,
        "aud": "test",
        "iss": "test"
            }}"#,
                self.active, scope, client_id, username, exp
            ),
            _ => {
                format!(
                    r#"{{
        "error": "invalid_client",
        "error_description": "This client authentication was invalid"
            }}"#
                )
            }
        };
        self.server
            .mock("POST", "/introspect")
            .with_status(status)
            .with_body(body)
            .create();
    }

    #[allow(dead_code)]
    pub(crate) fn http_revoke_with_status(&mut self, status: usize) -> mockito::Mock {
        self.server
            .mock("POST", "/revoke")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("token".into(), "mocking_access_token".into()),
                mockito::Matcher::UrlEncoded("token_type_hint".into(), "access_token".into()),
                mockito::Matcher::UrlEncoded("client_id".into(), "test".into()),
                mockito::Matcher::UrlEncoded("client_secret".into(), "test".into()),
            ]))
            .with_status(status)
            .create()
    }
}
