use zff::VirtualObjectSource;

// - Parent
use super::*;

pub fn compression_header(args: &Cli) -> CompressionHeader {
    let compression_algorithm = match args.compression_algorithm {
        CompressionAlgorithmValues::None => CompressionAlgorithm::None,
        CompressionAlgorithmValues::Zstd => CompressionAlgorithm::Zstd,
        CompressionAlgorithmValues::Lz4 => CompressionAlgorithm::Lz4,
    };

    if args.compression_level > 9 {
        error!("Invalid value for '--compression-level <COMPRESSION_LEVEL>': number <{}> too large to fit in target type. (Possible values are 1-9)", args.compression_level);
        exit(EXIT_STATUS_ERROR);    
    } else if args.compression_level  < 1 {
        error!("Invalid value for '--compression-level <COMPRESSION_LEVEL>': number <{}> too small to fit in target type. (Possible values are 1-9)", args.compression_level);
        exit(EXIT_STATUS_ERROR);
    }
    
    if compression_algorithm == CompressionAlgorithm::None {
        info!("Data will not be compressed");
    } else {
        info!("Data will be compressed with {} and level {}", compression_algorithm, args.compression_level);
    }

    CompressionHeader::new(compression_algorithm, args.compression_level, args.compression_threshold)
}

pub fn ask_password(args: &Cli) -> Option<String> {
    if !args.encrypt {
        info!("Object will not be encrypted.");
        return None;
    }
    let password = match rpassword::prompt_password("Enter the encryption password: ") {
        Ok(pw) => pw,
        Err(e) => {
            error!("An error occured while trying to read your password...please use only UTF8 valid characters:\n{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    let verify_pw = match rpassword::prompt_password("Re-enter the encryption password (verify): ") {
        Ok(pw) => pw,
        Err(e) => {
            error!("An error occured while trying to read your password...please use only UTF8 valid characters:\n{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    if password != verify_pw {
        error!("Passwords didn't match.");
        exit(EXIT_STATUS_ERROR);
    }

    Some(password)
}


/// returns the encryption header and the encryption key.
pub fn encryption_header<S: Into<String>>(args: &Cli, password: S) -> Option<EncryptionHeader> {
    let password = password.into();
    let (kdf, pbes) = match args.password_kdf {
        PasswordKdfValues::Pbkdf2Sha256Aes128 => (KDFScheme::PBKDF2SHA256, PBEScheme::AES128CBC),
        PasswordKdfValues::Pbkdf2Sha256Aes256 => (KDFScheme::PBKDF2SHA256, PBEScheme::AES256CBC),
        PasswordKdfValues::ScryptAes128 => (KDFScheme::Scrypt, PBEScheme::AES128CBC),
        PasswordKdfValues::ScryptAes256 => (KDFScheme::Scrypt, PBEScheme::AES256CBC),
        PasswordKdfValues::Argon2idAes128 => (KDFScheme::Argon2id, PBEScheme::AES256CBC),
        PasswordKdfValues::Argon2idAes256 => (KDFScheme::Argon2id, PBEScheme::AES256CBC),
    };
    info!("Using password based encryption with {}-{}.", kdf, pbes);

    let encryption_algorithm = match args.encryption_algorithm {
        EncryptionAlgorithmValues::AES128GCM => EncryptionAlgorithm::AES128GCM,
        EncryptionAlgorithmValues::AES256GCM => EncryptionAlgorithm::AES256GCM,
        EncryptionAlgorithmValues::CHACHA20POLY1305 => EncryptionAlgorithm::CHACHA20POLY1305,
    };
    info!("Using {} encrpytion algorithm.", encryption_algorithm);

    let encryption_key = match encryption_algorithm {
        EncryptionAlgorithm::AES128GCM => gen_random_key(128),
        EncryptionAlgorithm::AES256GCM => gen_random_key(256),
        EncryptionAlgorithm::CHACHA20POLY1305 => gen_random_key(256),
        _ => {
            error!("{}", ERROR_UNKNOWN_ENCRYPTION_ALGORITHM);
            exit(EXIT_STATUS_ERROR)
        },
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
            let pbe_header = PBEHeader::new(kdf, pbes.clone(), kdf_parameters, pbe_nonce);
            let encrypted_encryption_key = match pbes {
                PBEScheme::AES128CBC => match encrypt_pbkdf2sha256_aes128cbc(
                    iterations,
                    &salt,
                    pbe_nonce,
                    password.trim(),
                    &encryption_key,
                    ) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    },
                },
                PBEScheme::AES256CBC => match encrypt_pbkdf2sha256_aes256cbc(
                    iterations,
                    &salt,
                    pbe_nonce,
                    password.trim(),
                    &encryption_key,
                    ) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                _ => {
                    error!("{}", ERROR_UNKNOWN_PASSWORD_KDF);
                    exit(EXIT_STATUS_ERROR)
                },
            };
            (pbe_header, encrypted_encryption_key)
        },
        KDFScheme::Scrypt => {
            let logn = SCRYPT_LOGN_RECOMMENDED;
            let r = SCRYPT_R_RECOMMENDED;
            let p = SCRYPT_P_RECOMMENDED;
            let kdf_parameters = KDFParameters::ScryptParameters(ScryptParameters::new(logn, r, p, salt));
            let pbe_header = PBEHeader::new(kdf, pbes.clone(), kdf_parameters, pbe_nonce);
            let encrypted_encryption_key = match pbes {
                PBEScheme::AES128CBC => match encrypt_scrypt_aes128cbc(logn, r, p, &salt, pbe_nonce, password.trim(), &encryption_key) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                PBEScheme::AES256CBC => match encrypt_scrypt_aes256cbc(logn, r, p, &salt, pbe_nonce, password.trim(), &encryption_key) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                _ => {
                    error!("{}", ERROR_UNKNOWN_PASSWORD_KDF);
                    exit(EXIT_STATUS_ERROR)
                },
            };
            (pbe_header, encrypted_encryption_key)
        },
        KDFScheme::Argon2id => {
            let mem_cost = ARGON_MEM_COST_RECOMMENDED;
            let lanes = ARGON_LANES_RECOMMENDED;
            let iterations = ARGON_ITERATIONS_RECOMMENDED;
            let kdf_parameters = KDFParameters::Argon2idParameters(Argon2idParameters::new(mem_cost, lanes, iterations, salt));
            let pbe_header = PBEHeader::new(kdf, pbes.clone(), kdf_parameters, pbe_nonce);
            let encrypted_encryption_key = match pbes {
                PBEScheme::AES128CBC => match encrypt_argon2_aes128cbc(
                    mem_cost, lanes, iterations, &salt, &pbe_nonce, password.trim(), &encryption_key) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                PBEScheme::AES256CBC => match encrypt_argon2_aes256cbc(
                    mem_cost, lanes, iterations, &salt, &pbe_nonce, password.trim(), &encryption_key) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                _ => {
                    error!("{}", ERROR_UNKNOWN_PASSWORD_KDF);
                    exit(EXIT_STATUS_ERROR)
                },
            };
            (pbe_header, encrypted_encryption_key)
        },
        _ => {
            error!("{}", ERROR_UNKNOWN_PASSWORD_KDF);
            exit(EXIT_STATUS_ERROR)
        },
    };
    let mut encryption_header = EncryptionHeader::new(pbe_header, encryption_algorithm, encrypted_encryption_key);
    match encryption_header.decrypt_encryption_key(password) {
        Ok(_) => (),
        Err(e) => {
            error!("{ERROR_ENCRYPT_KEY}:\n{e}");
            exit(EXIT_STATUS_ERROR);
        }
    }
    Some(encryption_header)
}

pub fn object_description_header(args: &Cli) -> DescriptionHeader {

    let mut description_header = DescriptionHeader::new_empty();
    if let Some(value) = &args.case_number {
        description_header.set_case_number(value);
    };
    if let Some(value) = &args.evidence_number {
        description_header.set_evidence_number(value);
    };
    if let Some(value) = &args.examiner_name {
        description_header.set_examiner_name(value);
    };
    if let Some(value) = &args.notes {
        description_header.set_notes(value);
    };
    for (key, value) in &args.custom_descriptions {
        description_header.custom_identifier_value(key, value);
    }

    // add tool-specific stuff
    description_header.custom_identifier_value(TOOLNAME_KEY, TOOLNAME_VALUE);
    description_header.custom_identifier_value(TOOLVERSION_KEY, TOOLVERSION_VALUE);

    description_header
}

pub fn setup_object_flags(args: &Cli) -> ObjectFlags {
    ObjectFlags {
        encryption: args.encrypt,
        sign_hash: (args.sign_data || args.sign_key.is_some()),
        passive_object: object_is_passive(args),
    }
}

pub fn create_object_header(args: &Cli, encryption_header: Option<EncryptionHeader>) -> ObjectHeader {
    let flags = setup_object_flags(args);

    let chunk_size = chunk_size(args);
    debug!("Set chunk_size at {}", chunk_size.bytes_as_hrb());

    ObjectHeader::new(
        INITIAL_OBJECT_NUMBER,
        encryption_header,
        chunk_size,
        header_creation::compression_header(args),
        header_creation::object_description_header(args),
        ObjectType::Physical,
        flags,
        )
}

pub fn create_vos<V: VirtualObjectSource + 'static>(input: V) -> Box<dyn VirtualObjectSource> {
    Box::new(input)
}