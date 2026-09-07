use base64::{Engine, engine::general_purpose::STANDARD as base64engine};
use ed25519_dalek::SigningKey;
use log::{info, warn};

use crate::AcquireConfig;
use crate::constants::{ERROR_PARSE_KEY, WARNING_GENERATED_SIGNING_KEY_};
use zff::Signature;

pub fn create_signing_key(config: &AcquireConfig) -> Result<Option<SigningKey>, String> {
    if !config.sign_data {
        info!("Signing of data has been disabled.");
        return Ok(None);
    }
    match &config.sign_key {
        // A key the user supplied is already in their possession; echoing it
        // back into the log would only put a copy somewhere it does not belong.
        Some(value) => {
            let sign_key = Signature::new_signingkey_from_base64(value.trim())
                .map_err(|_| ERROR_PARSE_KEY.to_string())?;
            info!("Public signature key is {}", base64engine.encode(sign_key.verifying_key()));
            Ok(Some(sign_key))
        },
        // A generated key exists nowhere else, so it has to be surfaced here or
        // it is lost. It is announced as a secret rather than logged in passing.
        None => {
            let sign_key = Signature::new_signing_key();
            warn!("{}{}", WARNING_GENERATED_SIGNING_KEY_, base64engine.encode(sign_key.to_bytes()));
            info!("Public signature key is {}", base64engine.encode(sign_key.verifying_key()));
            Ok(Some(sign_key))
        },
    }
}
