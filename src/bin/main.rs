// - STD
use std::{
    process::exit,
    path::PathBuf,
    collections::HashMap,
};

// - extern crates
extern crate clap;
extern crate rand;
extern crate zff;

// - modules
mod res;

// - internal
use crate::res::{
    get_physical_input_file,
    hrs_parser,
    parse_key_val,
    concat_prefix_path,
    constants::*,
};

#[cfg(target_family = "windows")]
use crate::res::list_devices::print_devices_table;

use zff::{
    header::{CompressionHeader, EncryptionHeader, DescriptionHeader, ObjectType},
    header::{KDFParameters, PBKDF2SHA256Parameters, ScryptParameters, Argon2idParameters, PBEHeader, DeduplicationChunkMap, ObjectHeader, ObjectFlags},
    EncryptionAlgorithm,
    CompressionAlgorithm,
    KDFScheme,
    PBEScheme,
    Encryption,
    Signature,
    HashType,
    io::zffwriter::{ZffWriterOptionalParameter, ZffWriter, ZffWriterOutput},
    
    constants::{
        DEFAULT_COMPRESSION_RATIO_THRESHOLD,
        INITIAL_OBJECT_NUMBER,
    },
};

// - external
use clap::{
    Parser,
    Subcommand,
    ValueEnum,
    //builder::TypedValueParser as _,
};
use rand::Rng;
use ed25519_dalek::SigningKey;
use log::{LevelFilter, error, debug, info};
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};

#[derive(Parser)]
#[clap(about, version, author, override_usage="zffacquire <SUBCOMMAND> [OPTIONS]")]
struct Cli {

    /// A general description of all data, which are inside the zff file(s).
    #[clap(short='D', long="description-notes", global=true, required=false)]
    description_notes: Option<String>,

    /// sets the compression algorithm. Default is zstd.
    #[clap(short='z', long="compression-algorithm", global=true, required=false, value_enum, default_value="zstd")]
    compression_algorithm: CompressionAlgorithmValues,

    /// sets the compression level. Default is 3. This option doesn't has any effect while using the lz4 compression algorithm.
    #[clap(short='l', long="compression-level", global=true, required=false, default_value="3")]
    compression_level: u8,

    /// The compression ratio threshold. Default is 1.05.
    #[clap(short='T', long="compression-threshold", global=true, required=false, default_value=DEFAULT_COMPRESSION_RATIO_THRESHOLD)]
    compression_threshold: f32,

    /// The segment size of the output-file(s). Default is 0 (=the output image will never be splitted into segments).
    #[clap(short='s', long="segment-size", global=true, required=false)]
    segment_size: Option<String>,

    /// The chunk size. Default is 32kB. The chunksize have to be greater than the segment size. This option will be ignored by the extend subcommand.
    #[clap(short='C', long, global=true, required=false, default_value="32KB")]
    chunk_size: String,

    /// The chunk map size. Default is 32kB.
    #[clap(short='M', long, global=true, required=false, default_value="32KB")]
    chunkmap_size: String,

    /// This option activates the deduplication feature using an on-disk buffer (currently, a temporary redb-database will be used).
    #[clap(short='r', long, global=true, required=false, conflicts_with="in_memory_chunk_deduplication")]
    on_disk_chunk_deduplication: Option<PathBuf>,

    /// This option activates the deduplication feature using an in-memory buffer.
    #[clap(short='m', long, global=true, required=false, conflicts_with="on_disk_chunk_deduplication")]
    in_memory_chunk_deduplication: bool,

    /// encrypts the the zff object.
    #[clap(short='p', long="encrypt", global=true, required=false)]
    encrypt: bool,

    //TODO: Depends on "encrypt"...this has to be configured through clap.
    /// Sets the key derivation function for the password. Default is [scrypt-aes256].
    #[clap(short='K', long="password-kdf", global=true, required=false, value_enum, default_value="scrypt-aes256")]
    password_kdf: PasswordKdfValues,

    //TODO: Depends on "encrypt"...this has to be configured through clap.
    /// Sets the encryption algorithm. Default is [chacha20poly1305].
    #[clap(short='E', long="encryption-algorithm", global=true, required=false, value_enum, default_value="chacha20poly1305")]
    encryption_algorithm: EncryptionAlgorithmValues,

    /// This option adds an additional hash algorithm to calculate. You can use this option multiple times. If no algorithm is selected, zffacquire automatically calculates [blake3] hash values.
    #[clap(short='d', long="hash-algorithm", global=true, required=false, value_enum, default_value="blake3")]
    hash_algorithm: Vec<HashAlgorithmValues>,

    /// Sign hash values of data with an autogenerated or given secret EdDSA key.
    #[clap(short='S', long="sign-data", global=true)]
    sign_data: bool,

    /// Your secret EdDSA key, base64 formatted. Could be a Secret key or a keypair.
    #[clap(short='k', long="eddsa-key", global=true, required=false)]
    sign_key: Option<String>,

    /// The case number.
    #[clap(short='c', long="case-number", global=true, required=false)]
    case_number: Option<String>,

    /// The evidence number.
    #[clap(short='e', long="evidence-number", global=true, required=false)]
    evidence_number: Option<String>,

    /// Examiner's name.
    #[clap(short='x', long="examiner-name", global=true, required=false)]
    examiner_name: Option<String>,

    /// Some notes.
    #[clap(short='n', long="notes", global=true, required=false)]
    notes: Option<String>,

    /// Custom description values
    #[arg(short = 'O', long="custom-description", value_parser = parse_key_val::<String, String>, global=true, required=false)]
    custom_descriptions: Vec<(String, String)>,

    /// The Loglevel
    #[clap(short='L', long="log-level", value_enum, default_value="full-info", global=true, required=false)]
    log_level: LogLevel,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// acquire a physical image
    #[clap(arg_required_else_help=true)]
    Physical {
        /// The input file. This should be your device to dump. This field is REQUIRED.
        /// You can use all devices which are available by using the "zffacquire list-devices" command.
        /// E.g. "/dev/sda" or "/dev/nvme0n1" in Linux systems.
        /// On windows systems, you have to use the device names which are listed by the "zffacquire list-devices" command,
        /// e.g. "disk0" for "\\.\PhysicalDrive0" or "volume1" for "\\.\HarddiskVolume1".
        #[clap(short='i', long="inputfile", required=true)]
        inputfile: PathBuf,

        /// The the name/path of the output-file WITHOUT file extension. E.g. "/home/ph0llux/sda_dump". File extension will be added automatically. This field is REQUIRED.
        #[clap(short='o', long="outputfile", global=true, required=false)]
        outputfile: String,
    },
    /// acquire logical folder
    #[clap(arg_required_else_help=true)]
    Logical {
        /// The input folders. You can use this option multiple times. This field is REQUIRED.
        #[clap(short='i', long="inputfiles", required=true)]
        inputfiles: Vec<PathBuf>,

        /// The the name/path of the output-file WITHOUT file extension. E.g. "/home/ph0llux/sda_dump". File extension will be added automatically. This field is REQUIRED.
        #[clap(short='o', long="outputfile", global=true, required=false)]
        outputfile: String,
    },

    /// extends an existing zff file
    #[clap(arg_required_else_help=true)]
    Extend {
        /// Your zXX files, which should be extended.
        #[clap(short='a', long="append", global=true)]
        append_files: Vec<PathBuf>,

        #[clap(subcommand)]
        extend_command: ExtendSubcommands,
    },

    #[cfg(target_family = "windows")]
    /// List all available physical devices,
    /// which can be used as input for the physical subcommand.
    #[clap()]
    ListDevices { },
}

#[derive(Subcommand)]
enum ExtendSubcommands {
    /// acquire a physical image. 
    #[clap(arg_required_else_help=true)]
    Physical {
        /// The input file. This should be your device to dump. This field is REQUIRED.
        #[clap(short='i', long="inputfile", required=true)]
        inputfile: PathBuf,
    },
    /// acquire logical folder
    #[clap(arg_required_else_help=true)]
    Logical {
        /// The input folders. You can use this option multiple times. This field is REQUIRED.
        #[clap(short='i', long="inputfiles", required=true)]
        inputfiles: Vec<PathBuf>,
    },
}

#[derive(ValueEnum, Clone, PartialEq)]
enum LogLevel {
    Error,
    Warn,
    Info,
    FullInfo,
    Debug,
    FullDebug,
    Trace
}

#[derive(ValueEnum, Clone)]
enum HashAlgorithmValues {
    Blake2b512,
    SHA256,
    SHA512,
    SHA3_256,
    Blake3,
}

#[derive(ValueEnum, Clone)]
enum CompressionAlgorithmValues {
    /// No compression is used
    None,
    /// The zstd algorithm
    Zstd,
    /// The lz4 algorithm
    Lz4,
}

#[derive(ValueEnum, Clone)]
enum PasswordKdfValues {
    Pbkdf2Sha256Aes128,
    Pbkdf2Sha256Aes256,
    ScryptAes128,
    ScryptAes256,
    Argon2idAes128,
    Argon2idAes256,
}

#[derive(ValueEnum, Clone)]
enum EncryptionAlgorithmValues {
    AES128GCM,
    AES256GCM,
    CHACHA20POLY1305,
}

fn signer(args: &Cli) -> Option<SigningKey> {
    if !args.sign_data {
        info!("Signing of data has been disabled.");
        return None;
    }

    let sign_key = match &args.sign_key {
        None => Signature::new_signing_key(),
        Some(value) => match Signature::new_signingkey_from_base64(value.trim()) {
            Ok(keypair) => keypair,
            Err(_) => {
                error!("{}", ERROR_PARSE_KEY);
                exit(EXIT_STATUS_ERROR);
            }
        }
    };
    if args.sign_key.is_some() {
        debug!("Using private sign key {}", base64engine.encode(sign_key.to_bytes()));
    } else {
        info!("Private signature key is {}", base64engine.encode(sign_key.to_bytes()));
    }
    info!("Public signature key is {}", base64engine.encode(sign_key.verifying_key()));
    Some(sign_key)
}

fn compression_header(args: &Cli) -> CompressionHeader {
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
        info!("Data will be compressed with {} and level {}", compression_algorithm.to_string(), args.compression_level);
    }

    CompressionHeader::new(compression_algorithm, args.compression_level, args.compression_threshold)
}

/// returns the encryption header and the encryption key.
fn encryption_header(args: &Cli) -> Option<EncryptionHeader> {
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
        EncryptionAlgorithm::AES128GCM => Encryption::gen_random_key(128),
        EncryptionAlgorithm::AES256GCM => Encryption::gen_random_key(256),
        EncryptionAlgorithm::CHACHA20POLY1305 => Encryption::gen_random_key(256),
        _ => {
            error!("{}", ERROR_UNKNOWN_ENCRYPTION_ALGORITHM);
            exit(EXIT_STATUS_ERROR)
        },
    };
    debug!("Using encryption key {}", base64engine.encode(encryption_key.clone()));

    let pbe_nonce = Encryption::gen_random_iv();
    debug!("Used pbe: nonce {}", base64engine.encode(pbe_nonce));

    let salt = Encryption::gen_random_salt();
    debug!("Used salt: {}", base64engine.encode(salt));
    
    let (pbe_header, encrypted_encryption_key) = match kdf {
        KDFScheme::PBKDF2SHA256 => {
            let iterations = 310000;
            let kdf_parameters = KDFParameters::PBKDF2SHA256Parameters(PBKDF2SHA256Parameters::new(iterations, salt));
            let pbe_header = PBEHeader::new(kdf, pbes.clone(), kdf_parameters, pbe_nonce);
            let encrypted_encryption_key = match pbes {
                PBEScheme::AES128CBC => match Encryption::encrypt_pbkdf2sha256_aes128cbc(
                    iterations,
                    &salt,
                    &pbe_nonce,
                    password.trim(),
                    &encryption_key,
                    ) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    },
                },
                PBEScheme::AES256CBC => match Encryption::encrypt_pbkdf2sha256_aes256cbc(
                    iterations,
                    &salt,
                    &pbe_nonce,
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
                PBEScheme::AES128CBC => match Encryption::encrypt_scrypt_aes128cbc(logn, r, p, &salt, &pbe_nonce, password.trim(), &encryption_key) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                PBEScheme::AES256CBC => match Encryption::encrypt_scrypt_aes256cbc(logn, r, p, &salt, &pbe_nonce, password.trim(), &encryption_key) {
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
                PBEScheme::AES128CBC => match Encryption::encrypt_argon2_aes128cbc(
                    mem_cost, lanes, iterations, &salt, &pbe_nonce, password.trim(), &encryption_key) {
                    Ok(val) => val,
                    Err(_) => {
                        error!("{}", ERROR_ENCRYPT_KEY);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                PBEScheme::AES256CBC => match Encryption::encrypt_argon2_aes256cbc(
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

fn object_description_header(args: &Cli) -> DescriptionHeader {

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

fn setup_optional_parameter(args: &Cli) -> ZffWriterOptionalParameter {
    let mut rng = rand::thread_rng();

    let description_notes = &args.description_notes;
    let sign_keypair = signer(args);
    let target_segment_size = if let Some(segment_size) = &args.segment_size {
        match hrs_parser(segment_size) {
            Some(val) => Some(val),
            None => {
                error!("{}{}", ERROR_UNPARSABLE_SEGMENT_SIZE_VALUE, segment_size);
                exit(EXIT_STATUS_ERROR);
            }
        }
    } else {
        None
    };

    let chunkmap_size = match hrs_parser(&args.chunkmap_size) {
        Some(val) => Some(val),
        None => {
            error!("{}{}", ERROR_UNPARSABLE_CHUNKMAP_SIZE_VALUE, &args.chunkmap_size);
            exit(EXIT_STATUS_ERROR);
        }
    };

    let deduplication_chunkmap = if args.in_memory_chunk_deduplication {
        Some(DeduplicationChunkMap::new_in_memory_map())
    } else if let Some(path) = &args.on_disk_chunk_deduplication {
        let map = match DeduplicationChunkMap::new_from_path(path) {
            Ok(map) => map,
            Err(e) => {
                error!("cannot create deduplication chunkmap: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        Some(map)
    } else {
        None
    };

    let unique_identifier = rng.gen();

    ZffWriterOptionalParameter {
        signature_key: sign_keypair,
        target_segment_size,
        chunkmap_size,
        deduplication_chunkmap,
        unique_identifier,
        description_notes: description_notes.clone(),
    }
}

fn main() {
    let args = Cli::parse();

    let log_level = match args.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::FullInfo => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::FullDebug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    if args.log_level == LogLevel::FullInfo || args.log_level == LogLevel::FullDebug {
        env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();
    } else {
        env_logger::builder()
        .format_timestamp_nanos()
        .filter_module(env!("CARGO_PKG_NAME"), log_level)
        .init();
    };

    debug!("Started zffacquire");

    #[cfg(target_family = "windows")]
    match args.command {
        Commands::ListDevices {  } => {
            print_devices_table();
            exit(EXIT_STATUS_SUCCESS);
        },
        _ => (),
    }
        

    let mut hash_types = Vec::new();
    for htype in &args.hash_algorithm {
        match htype {
            HashAlgorithmValues::Blake2b512 => hash_types.push(HashType::Blake2b512),
            HashAlgorithmValues::SHA256 => hash_types.push(HashType::SHA256),
            HashAlgorithmValues::SHA512 => hash_types.push(HashType::SHA512),
            HashAlgorithmValues::SHA3_256 => hash_types.push(HashType::SHA3_256),
            HashAlgorithmValues::Blake3 => hash_types.push(HashType::Blake3),
        }
    }

    let encryption_header = encryption_header(&args);
    let optional_parameter = setup_optional_parameter(&args);

    let flags = ObjectFlags {
        encryption: encryption_header.is_some(),
        sign_hash: optional_parameter.signature_key.is_some(),
    };

    let chunk_size = match hrs_parser(&args.chunk_size) {
        Some(val) => val,
        None => {
            error!("Cannot parse {}, please enter a valid size (e.g. 32K, 40k, 10M, ...)", args.chunk_size);
            exit(EXIT_STATUS_ERROR);
        }
    };

    let mut obj_header = ObjectHeader::new(
        INITIAL_OBJECT_NUMBER,
        encryption_header,
        chunk_size,
        compression_header(&args),
        object_description_header(&args),
        ObjectType::Physical,
        flags,
        );

    let mut logical_objects = HashMap::new();
    let mut physical_objects = HashMap::new();

    let zffwriter_output = match &args.command {
        #[cfg(target_family = "windows")]
        Commands::ListDevices {  } => {
            unreachable!()
        },
        Commands::Physical { inputfile, outputfile } => {
             let file = match get_physical_input_file(inputfile.clone()) {
                Ok(file) => file,
                Err(e) => {
                    let inputfile = inputfile.to_string_lossy();
                    error!("Following error occurred while trying to open {inputfile}:\n{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };

            physical_objects.insert(obj_header, file);

            ZffWriterOutput::NewContainer(outputfile.into())
        },
        Commands::Logical { inputfiles, outputfile } => {
            let inputfiles: Vec<PathBuf> = inputfiles.iter().map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX ,x)).collect();
            obj_header.object_type = ObjectType::Logical;
        

            logical_objects.insert(obj_header, inputfiles);
            
            ZffWriterOutput::NewContainer(outputfile.into())
        },
        Commands::Extend { extend_command, append_files } => {
            match extend_command {
                //setup logical objects.
                ExtendSubcommands::Logical { inputfiles } => {
                    let inputfiles: Vec<PathBuf> = inputfiles.iter().map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX ,x)).collect();
                    obj_header.object_type = ObjectType::Logical;
                    logical_objects.insert(obj_header, inputfiles);
                },
                //setup physical objects.
                ExtendSubcommands::Physical { inputfile } => {
                    let file = match get_physical_input_file(inputfile.clone()) {
                        Ok(file) => file,
                        Err(e) => {
                            let inputfile = inputfile.to_string_lossy();
                            error!("Following error occurred while trying to open {inputfile}:\n{e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    physical_objects.insert(obj_header, file);
                },
            };

            ZffWriterOutput::ExtendContainer(append_files.to_vec())
        },
    };

    let mut zw = match ZffWriter::new(
        physical_objects,
        logical_objects,
        hash_types,
        zffwriter_output,
        optional_parameter,
        ) {
        Ok(zw) => zw,
        Err(e) => {
            error!("An error occured while trying to create the ZffWriter object:\n{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    if let Err(e) = zw.generate_files() {
        error!("An error occured while filling the zff container:\n {e}");
        exit(EXIT_STATUS_ERROR);
    };
    info!("Zff file(s) successfully created");
    exit(EXIT_STATUS_SUCCESS);
}