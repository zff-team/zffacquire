use std::path::Path;

use log::{info, debug};
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};

use zff::{
    VirtualObjectSource,
    EncryptionAlgorithm,
    CompressionAlgorithm,
    KDFScheme,
    PBEScheme,
    header::{
        CompressionHeader,
        EncryptionHeader,
        DescriptionHeader,
        ObjectType,
        KDFParameters,
        PBKDF2SHA256Parameters,
        ScryptParameters,
        Argon2idParameters,
        PBEHeader,
        ObjectHeader,
        ObjectFlags,
    },
    constants::INITIAL_OBJECT_NUMBER,
    encryption::*,
};

use crate::AcquireConfig;
use crate::utils::{hrs_parser, get_os_string};
use crate::constants::*;
#[cfg(target_os = "linux")]
use crate::device::get_device_info;

pub fn parse_chunk_size(s: &str) -> Result<u64, String> {
    hrs_parser(s).ok_or_else(|| format!("{}: {}", ERROR_UNPARSABLE_CHUNKMAP_SIZE_VALUE, s))
}

pub fn compression_header(config: &AcquireConfig) -> Result<CompressionHeader, String> {
    if config.compression_level > 9 {
        return Err(format!("Invalid compression level {}: must be 1-9", config.compression_level));
    }
    if config.compression_level < 1 {
        return Err(format!("Invalid compression level {}: must be 1-9", config.compression_level));
    }
    if config.compression_algorithm == CompressionAlgorithm::None {
        info!("Data will not be compressed");
    } else {
        info!("Data will be compressed with {} and level {}", config.compression_algorithm, config.compression_level);
    }
    Ok(CompressionHeader::new(config.compression_algorithm.clone(), config.compression_level, config.compression_threshold))
}

pub fn encryption_header(
    kdf: KDFScheme,
    pbe: PBEScheme,
    encryption_algorithm: EncryptionAlgorithm,
    password: &str,
) -> Result<EncryptionHeader, String> {
    info!("Using password based encryption with {}-{}.", kdf, pbe);
    info!("Using {} encryption algorithm.", encryption_algorithm);

    let encryption_key = match encryption_algorithm {
        EncryptionAlgorithm::AES128GCM => gen_random_key(128),
        EncryptionAlgorithm::AES256GCM => gen_random_key(256),
        EncryptionAlgorithm::CHACHA20POLY1305 => gen_random_key(256),
        _ => return Err(ERROR_UNKNOWN_ENCRYPTION_ALGORITHM.to_string()),
    };
    debug!("Using encryption key {}", base64engine.encode(encryption_key.clone()));

    let pbe_nonce = gen_random_iv();
    debug!("Used pbe: nonce {}", base64engine.encode(pbe_nonce));

    let salt = gen_random_salt();
    debug!("Used salt: {}", base64engine.encode(salt));

    let (pbe_header, encrypted_encryption_key) = match kdf {
        KDFScheme::PBKDF2SHA256 => {
            let iterations = 310000;
            let kdf_parameters = KDFParameters::PBKDF2SHA256Parameters(PBKDF2SHA256Parameters::new(iterations, salt));
            let pbe_header = PBEHeader::new(kdf, pbe.clone(), kdf_parameters, pbe_nonce);
            let encrypted_encryption_key = match pbe {
                PBEScheme::AES128CBC => encrypt_pbkdf2sha256_aes128cbc(iterations, &salt, pbe_nonce, password.trim(), &encryption_key)
                    .map_err(|_| ERROR_ENCRYPT_KEY.to_string())?,
                PBEScheme::AES256CBC => encrypt_pbkdf2sha256_aes256cbc(iterations, &salt, pbe_nonce, password.trim(), &encryption_key)
                    .map_err(|_| ERROR_ENCRYPT_KEY.to_string())?,
                _ => return Err(ERROR_UNKNOWN_PASSWORD_KDF.to_string()),
            };
            (pbe_header, encrypted_encryption_key)
        },
        KDFScheme::Scrypt => {
            let logn = SCRYPT_LOGN_RECOMMENDED;
            let r = SCRYPT_R_RECOMMENDED;
            let p = SCRYPT_P_RECOMMENDED;
            let kdf_parameters = KDFParameters::ScryptParameters(ScryptParameters::new(logn, r, p, salt));
            let pbe_header = PBEHeader::new(kdf, pbe.clone(), kdf_parameters, pbe_nonce);
            let encrypted_encryption_key = match pbe {
                PBEScheme::AES128CBC => encrypt_scrypt_aes128cbc(logn, r, p, &salt, pbe_nonce, password.trim(), &encryption_key)
                    .map_err(|_| ERROR_ENCRYPT_KEY.to_string())?,
                PBEScheme::AES256CBC => encrypt_scrypt_aes256cbc(logn, r, p, &salt, pbe_nonce, password.trim(), &encryption_key)
                    .map_err(|_| ERROR_ENCRYPT_KEY.to_string())?,
                _ => return Err(ERROR_UNKNOWN_PASSWORD_KDF.to_string()),
            };
            (pbe_header, encrypted_encryption_key)
        },
        KDFScheme::Argon2id => {
            let mem_cost = ARGON_MEM_COST_RECOMMENDED;
            let lanes = ARGON_LANES_RECOMMENDED;
            let iterations = ARGON_ITERATIONS_RECOMMENDED;
            let kdf_parameters = KDFParameters::Argon2idParameters(Argon2idParameters::new(mem_cost, lanes, iterations, salt));
            let pbe_header = PBEHeader::new(kdf, pbe.clone(), kdf_parameters, pbe_nonce);
            let encrypted_encryption_key = match pbe {
                PBEScheme::AES128CBC => encrypt_argon2_aes128cbc(mem_cost, lanes, iterations, &salt, &pbe_nonce, password.trim(), &encryption_key)
                    .map_err(|_| ERROR_ENCRYPT_KEY.to_string())?,
                PBEScheme::AES256CBC => encrypt_argon2_aes256cbc(mem_cost, lanes, iterations, &salt, &pbe_nonce, password.trim(), &encryption_key)
                    .map_err(|_| ERROR_ENCRYPT_KEY.to_string())?,
                _ => return Err(ERROR_UNKNOWN_PASSWORD_KDF.to_string()),
            };
            (pbe_header, encrypted_encryption_key)
        },
        _ => return Err(ERROR_UNKNOWN_PASSWORD_KDF.to_string()),
    };

    let mut encryption_header = EncryptionHeader::new(pbe_header, encryption_algorithm, encrypted_encryption_key);
    encryption_header.decrypt_encryption_key(password)
        .map_err(|e| format!("{}: {}", ERROR_ENCRYPT_KEY, e))?;
    Ok(encryption_header)
}

pub fn object_description_header(config: &AcquireConfig) -> DescriptionHeader {
    let mut description_header = DescriptionHeader::new_empty();
    if let Some(value) = &config.case_number {
        description_header.set_case_number(value);
    };
    if let Some(value) = &config.evidence_number {
        description_header.set_evidence_number(value);
    };
    if let Some(value) = &config.examiner_name {
        description_header.set_examiner_name(value);
    };
    if let Some(value) = &config.notes {
        description_header.set_notes(value);
    };
    for (key, value) in &config.custom_descriptions {
        description_header.custom_identifier_value(key, value);
    }
    description_header.custom_identifier_value(TOOLNAME_KEY, TOOLNAME_VALUE);
    description_header.custom_identifier_value(TOOLVERSION_KEY, TOOLVERSION_VALUE);
    let os = get_os_string();
    debug!("Detected OS: {}", os);
    description_header.set_operating_system(os);
    if let Some(ref notes) = config.description_notes {
        description_header.set_notes(notes);
    }
    description_header
}

pub fn populate_physical_device_info(
    description_header: &mut DescriptionHeader,
    input_path: &Path,
) {
    if let Some(path_str) = input_path.to_str() {
        description_header.set_input_source(path_str);
    }
    #[cfg(target_os = "linux")]
    if let Some(info) = get_device_info(input_path) {
        if let Some(val) = info.logical_sector_size {
            description_header.set_logical_sector_size(val);
        }
        if let Some(val) = info.physical_sector_size {
            description_header.set_physical_sector_size(val);
        }
        if let Some(val) = info.model {
            description_header.set_model(val);
        }
        if let Some(val) = info.serial_number {
            description_header.set_serial_number(val);
        }
        if let Some(val) = info.firmware {
            description_header.set_firmware(val);
        }
        if let Some(val) = info.media_type {
            description_header.set_media_type(val);
        }
    }
}

pub fn populate_logical_source_info(
    description_header: &mut DescriptionHeader,
    input_paths: &[std::path::PathBuf],
) {
    let sources: Vec<String> = input_paths
        .iter()
        .filter_map(|p| p.to_str().map(|s| s.to_string()))
        .collect();
    if !sources.is_empty() {
        description_header.set_input_source(sources.join(","));
    }
}

pub fn setup_object_flags(config: &AcquireConfig, is_passive: bool) -> ObjectFlags {
    ObjectFlags {
        encryption: config.encrypt,
        sign_hash: (config.sign_data || config.sign_key.is_some()),
        passive_object: is_passive,
    }
}

pub fn create_object_header(
    config: &AcquireConfig,
    encryption_header: Option<EncryptionHeader>,
    is_passive: bool,
) -> Result<ObjectHeader, String> {
    let flags = setup_object_flags(config, is_passive);
    let chunk_size = parse_chunk_size(&config.chunk_size)?;
    debug!("Set chunk_size at {}", chunk_size);
    Ok(ObjectHeader::new(
        INITIAL_OBJECT_NUMBER,
        encryption_header,
        chunk_size,
        compression_header(config)?,
        object_description_header(config),
        ObjectType::Physical,
        flags,
    ))
}

pub fn create_vos<V: VirtualObjectSource + 'static>(input: V) -> Box<dyn VirtualObjectSource> {
    Box::new(input)
}
