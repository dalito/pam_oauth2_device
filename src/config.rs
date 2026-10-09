use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Error as IOError, Read};
use std::result::Result;
use std::time::Duration;
use url::Url;

#[serde_with::serde_as]
#[derive(Serialize, Deserialize)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub oauth_auth_url: Url,
    pub oauth_device_url: Url,
    pub oauth_token_url: Url,
    pub oauth_token_introspect_url: Url,
    #[serde(default)]
    pub oauth_token_revoke_url: Option<Url>,
    #[serde(default)]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub oauth_device_token_polling_timeout: Option<Duration>,

    /// Upper bound on each HTTP request to the OAuth server, connect included.
    #[serde(default = "default_http_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    pub http_timeout: Duration,

    #[serde(default = "default_scopes")]
    pub scopes: String,

    #[serde(default = "default_true")]
    pub qr_enabled: bool,

    #[serde(default)]
    pub messages: Messages,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Messages {
    #[serde(default = "Messages::default_complete")]
    pub prompt_complete: String,
    #[serde(default = "Messages::default_no_qr_complete")]
    pub prompt_no_qr_complete: String,
    #[serde(default = "Messages::default_incomplete")]
    pub prompt_incomplete: String,
    #[serde(default = "Messages::default_no_qr_incomplete")]
    pub prompt_no_qr_incomplete: String,
    #[serde(default = "Messages::default_code")]
    pub prompt_code: String,
    #[serde(default = "Messages::default_enter")]
    pub prompt_enter: String,
}

impl Messages {
    fn default_complete() -> String {
        "Scan the QR code above or open the following link in your web browser:".to_string()
    }
    fn default_no_qr_complete() -> String {
        "Open the following link in your web browser:".to_string()
    }
    fn default_incomplete() -> String {
        "Scan the QR code above or open the following link in your web browser:".to_string()
    }
    fn default_no_qr_incomplete() -> String {
        "Open the following link in your web browser:".to_string()
    }
    fn default_code() -> String {
        "Once you're in, enter the following code:".to_string()
    }
    fn default_enter() -> String {
        "Press \"ENTER\" after successful authentication...".to_string()
    }
}

impl Default for Messages {
    fn default() -> Self {
        Self {
            prompt_complete: Messages::default_complete(),
            prompt_no_qr_complete: Messages::default_no_qr_complete(),
            prompt_incomplete: Messages::default_incomplete(),
            prompt_no_qr_incomplete: Messages::default_no_qr_incomplete(),
            prompt_code: Messages::default_code(),
            prompt_enter: Messages::default_enter(),
        }
    }
}

pub fn read_config(path: &str) -> Result<Config, IOError> {
    let mut config_file = File::open(path)?;
    let mut buff = String::new();
    config_file.read_to_string(&mut buff)?;

    let config: Config = serde_json::from_str(&buff)?;
    Ok(config)
}

fn default_scopes() -> String {
    "openid profile".to_string()
}

fn default_true() -> bool {
    true
}

fn default_http_timeout() -> Duration {
    Duration::from_secs(10)
}
