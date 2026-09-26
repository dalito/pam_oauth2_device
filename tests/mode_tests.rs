use std::collections::HashMap;

use pam_oauth2_device::{sign_in_mode, Mode};

fn args(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn no_mode_argument_selects_the_device_flow() {
    assert_eq!(sign_in_mode(&args(&[("config", "/x")])), Ok(Mode::Device));
}

#[test]
fn mode_token_selects_token_mode() {
    assert_eq!(sign_in_mode(&args(&[("mode", "token")])), Ok(Mode::Token));
}

#[test]
fn an_unknown_mode_is_refused_with_its_value() {
    assert_eq!(
        sign_in_mode(&args(&[("mode", "Token")])),
        Err("Token".to_string())
    );
}

#[test]
fn an_empty_mode_is_refused() {
    assert_eq!(sign_in_mode(&args(&[("mode", "")])), Err(String::new()));
}
