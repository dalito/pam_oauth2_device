pub mod config;
pub mod logger;
pub mod oauth_device;
pub mod prompt;

use crate::config::read_config;
use crate::oauth_device::*;
use oauth2::AccessToken;
use oauth2::{TokenIntrospectionResponse, TokenResponse};
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF, PAM_TEXT_INFO};

use crate::prompt::UserPrompt;
use logger::{DefaultLogger, Logger};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use std::collections::HashMap;
use std::ffi::CStr;

pub struct PamOAuth2Device;
pam::pam_hooks!(PamOAuth2Device);

macro_rules! try_or_handle {
    ($res:expr, $error_message:expr, $pam_error:expr) => {
        match $res {
            Ok(o) => o,
            Err(e) => {
                DefaultLogger::handle_error(e, $error_message);
                return $pam_error;
            }
        }
    };
}

impl PamHooks for PamOAuth2Device {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let args = parse_args(&args);
        let default_log_path = "/tmp/pam_oauth2_device.log".to_string();
        let default_log_level = "info".to_string();
        let log_path = args.get("logs").unwrap_or(&default_log_path);
        let log_level = args.get("log_level").unwrap_or(&default_log_level);
        DefaultLogger::init(&log_path, &log_level);

        let default_config_path = "/etc/pam_oauth2_device/config.json".to_string();
        let config_path = args.get("config").unwrap_or(&default_config_path);
        let config = try_or_handle!(
            read_config(&config_path).map_err(|err| err.into()),
            "Failed to parse config file",
            PamResultCode::PAM_SYSTEM_ERR
        );

        let local_username = pam_try!(pamh.get_user(None));

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => {
                log::error!("No conv available");
                return PamResultCode::PAM_CONV_ERR;
            }
            Err(err) => {
                log::error!("Couldn't get pam_conv");
                return err;
            }
        };

        log::info!("Trying to authenticate user: {local_username}");

        let oauth_client = try_or_handle!(
            OAuthClient::new(&config),
            "Failed to build OAuth client",
            PamResultCode::PAM_SYSTEM_ERR
        );
        log::debug!("OAuth Client: {:#?}", oauth_client);

        if args.get("mode").map(String::as_str) == Some("token") {
            return authenticate_token(&conv, &oauth_client, &local_username);
        }

        let device_code_resp = try_or_handle!(
            oauth_client.device_code(),
            "Failed to recive device code response",
            PamResultCode::PAM_AUTH_ERR
        );
        log::debug!("Device Code response: {:#?}", device_code_resp);

        let mut user_prompt = UserPrompt::new(&device_code_resp, &config.messages);
        if config.qr_enabled {
            log::debug!("Generating QR code...");
            user_prompt.generate_qr();
        }
        log::debug!("User prompt: {:#?}", user_prompt);

        // Render user prompt
        // Split across two PAM messages for iRODS pam_interactive.
        //
        // pam_interactive derives a JSON Pointer from the raw text of a
        // Waiting/WaitingPw prompt by concatenating "/" with it, without the
        // RFC 6901 escaping of "/" and "~". Any slash in the text therefore
        // becomes a path separator, and the JSON Patch it applies next throws
        // out_of_range.403 on the absent parent. A device flow's text always
        // carries a URL, so this is unconditional rather than occasional.
        //
        // PAM_TEXT_INFO maps to state Next, which pam_interactive only
        // displays. The address and code travel there, and the prompt that
        // collects the reply is kept free of slashes.
        pam_try!(conv.send(PAM_TEXT_INFO, &user_prompt.to_string()));
        pam_try!(conv.send(
            PAM_PROMPT_ECHO_OFF,
            "Press ENTER when you have approved the login"
        ));

        let token = try_or_handle!(
            oauth_client.get_token(&device_code_resp, config.oauth_device_token_polling_timeout),
            "Failed to recive user token",
            PamResultCode::PAM_AUTH_ERR
        );
        log::debug!("Token response: {:#?}", token);

        let token = try_or_handle!(
            oauth_client.introspect(&token.access_token()),
            "Failed to introspect user token",
            PamResultCode::PAM_AUTH_ERR
        );
        log::debug!("Introspect response: {:#?}", token);

        if oauth_client.validate_token(&token, &local_username) {
            let remote_username = token.username().unwrap(); //it is safe cause of token validatiaon
            log::info!(
                "Authentication successful for remote user: {} -> local user: {}",
                remote_username,
                local_username
            );
            return PamResultCode::PAM_SUCCESS;
        }

        log::warn!("Login failed for user: {local_username}");

        PamResultCode::PAM_AUTH_ERR
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn sm_chauthtok(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
    fn sm_open_session(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
    fn sm_close_session(
        _pamh: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}

/// Sign in with a single-use token the client sends as its password.
///
/// iRODS `pam_password` runs this stack through `irodsPamAuthCheck`, whose
/// conversation answers an echo-off prompt with what the client sent. The
/// token must pass the device path's own checks and name this module's client,
/// and it is revoked before success is returned, so a failed revocation fails
/// the login and a token signs in at most once.
fn authenticate_token(
    conv: &Conv,
    oauth_client: &OAuthClient,
    local_username: &str,
) -> PamResultCode {
    let reply = match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
        Ok(Some(reply)) => reply,
        Ok(None) => {
            log::warn!("No password supplied for user: {local_username}");
            return PamResultCode::PAM_AUTH_ERR;
        }
        Err(code) => return code,
    };
    let Ok(secret) = reply.as_str() else {
        log::warn!("Password for user {local_username} is not UTF-8");
        return PamResultCode::PAM_AUTH_ERR;
    };
    let token = AccessToken::new(secret.to_string());

    let introspection = try_or_handle!(
        oauth_client.introspect(&token),
        "Failed to introspect sign-in password",
        PamResultCode::PAM_AUTH_ERR
    );
    if !(oauth_client.validate_token(&introspection, local_username)
        && oauth_client.issued_to_me(&introspection))
    {
        log::warn!("Login failed for user: {local_username}");
        return PamResultCode::PAM_AUTH_ERR;
    }

    try_or_handle!(
        oauth_client.revoke(&token),
        "Failed to revoke sign-in password",
        PamResultCode::PAM_AUTH_ERR
    );
    log::info!("Password sign-in for user: {local_username}");
    PamResultCode::PAM_SUCCESS
}

fn parse_args(args: &[&CStr]) -> HashMap<String, String> {
    args.iter()
        .map(|&s| {
            let s = s.to_string_lossy().into_owned();
            let mut parts = s.splitn(2, '=');
            (
                parts.next().unwrap_or_default().to_string(),
                parts.next().unwrap_or_default().to_string(),
            )
        })
        .collect()
}
