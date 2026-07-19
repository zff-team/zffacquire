use base64::{Engine, engine::general_purpose::STANDARD as base64engine};
use ed25519_dalek::SigningKey;
use log::{info, debug};

use crate::AcquireConfig;
use crate::constants::ERROR_PARSE_KEY;
use zff::Signature;

pub fn create_signing_key(config: &AcquireConfig) -> Result<Option<SigningKey>, String> {
    if !config.sign_data {
        info!("Signing of data has been disabled.");
        return Ok(None);
    }
    let sign_key = match &config.sign_key {
        None => Signature::new_signing_key(),
        Some(value) => match Signature::new_signingkey_from_base64(value.trim()) {
            Ok(keypair) => keypair,
            Err(_) => return Err(ERROR_PARSE_KEY.to_string()),
        }
    };
    if config.sign_key.is_some() {
        debug!("Using private sign key {}", base64engine.encode(sign_key.to_bytes()));
    } else {
        info!("Private signature key is {}", base64engine.encode(sign_key.to_bytes()));
    }
    info!("Public signature key is {}", base64engine.encode(sign_key.verifying_key()));
    Ok(Some(sign_key))
}
