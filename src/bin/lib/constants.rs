//Error messages
pub(crate) const ERROR_OPEN_INPUT_FILE: &str = "Could not open input file: ";
pub(crate) const ERROR_ENCRYPT_KEY: &str = "Could not encrypt/decrypt your key with the given password. This is an application bug.";
pub(crate) const ERROR_UNKNOWN_ENCRYPTION_ALGORITHM: &str = "The given encryption algorithm is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub(crate) const ERROR_UNKNOWN_PASSWORD_KDF: &str = "The given password key derivation function is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub(crate) const ERROR_PARSE_KEY: &str = "Could not parse your given base64 formatted secret key / keypair.";
pub(crate) const ERROR_UNPARSABLE_SEGMENT_SIZE_VALUE: &str = "Error: can not parse the given segment size value: ";
pub(crate) const ERROR_UNPARSABLE_CHUNKMAP_SIZE_VALUE: &str = "Error: can not parse the given chunkmap size value: ";
pub(crate) const ERROR_GENERATE_FILES: &str = "An error occurred while trying to generate the zff file segment(s): ";
pub(crate) const ERROR_CREATE_OBJECT_ENCODER: &str ="An error occurred while trying to generate the object encoder: ";
pub(crate) const ERROR_EXTEND_FILES: &str = "An error occurred while trying to extend the current files: ";
pub(crate) const WARNING_UNACCESSABLE_LOGICAL_FILE: &str = "Could not open/read file: ";

pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// uncategorized
pub(crate) const HRS_PARSER_BASE: u64 = 1024;


// scrypt parameters
pub(crate) const SCRYPT_LOGN_RECOMMENDED: u8 = 15;
pub(crate) const SCRYPT_R_RECOMMENDED: u32 = 1;
pub(crate) const SCRYPT_P_RECOMMENDED: u32 = 1;

// argon2 parameters
pub(crate) const ARGON_MEM_COST_RECOMMENDED: u32 = 1000000;
pub(crate) const ARGON_LANES_RECOMMENDED: u32 = 4;
pub(crate) const ARGON_ITERATIONS_RECOMMENDED: u32 = 8;

// custom description header entry keys
pub(crate) const DESCRIPTION_HEADER_CUSTOM_KEY_SIGNATURE_PUBKEY: &str = "signature_public_key";
pub(crate) const TOOLNAME_KEY: &str = "extraction_tool_name";
pub(crate) const TOOLNAME_VALUE: &str = env!("CARGO_PKG_NAME");
pub(crate) const TOOLVERSION_KEY: &str = "extraction_tool_version";
pub(crate) const TOOLVERSION_VALUE: &str = env!("CARGO_PKG_VERSION");

// serializer struct/field names
pub(crate) const SER_INFORMATION: &str = "Information";
pub(crate) const SER_CHUNK_SIZE: &str = "chunk_size";
pub(crate) const SER_SEGMENT_SIZE: &str = "segment_size";
pub(crate) const SER_UNIQUE_SEGMENT_IDENTIFIER: &str = "unique_segment_identifier";
pub(crate) const SER_OBJECT_TYPE: &str ="object_type";
pub(crate) const SER_EXISTING_CONTAINER_EXTENDED: &str = "existing_zff_container_extended";
pub(crate) const SER_PRIVATE_KEY: &str = "auto-generated_signature_private_key";
pub(crate) const SER_PUBLIC_KEY: &str = "signature_public_key";
pub(crate) const SER_PBESCHEME: &str = "pbe_scheme";
pub(crate) const SER_ALGORITHM: &str = "algorithm";
pub(crate) const SER_LEVEL: &str = "level";
pub(crate) const SER_THRESHOLD: &str = "threshold";


pub(crate) const SER_EVIDENCE_NUMBER: &str = "evidence-number";
pub(crate) const SER_EXAMINER_NAME: &str = "examiner-name";
pub(crate) const SER_CASE_NUMBER: &str = "case-number";
pub(crate) const SER_NOTES: &str = "notes";

pub(crate) const SER_AES128GCMSIV: &str = "AES128GCMSIV";
pub(crate) const SER_AES256GCMSIV: &str = "AES256GCMSIV";

pub(crate) const SER_KDF_SCHEME_PBKDF2_: &str = "PBKDF2SHA256-";
pub(crate) const SER_KDF_SCHEME_SCRYPT_: &str = "Scrypt-";
pub(crate) const SER_KDF_SCHEME_UNKNOWN_: &str = "unknown kdf scheme /";

pub(crate) const SER_PBESCHEME_AES128CBC: &str = "AES128CBC";
pub(crate) const SER_PBESCHEME_AES256CBC: &str = "AES256CBC";
pub(crate) const SER_PBESCHEME_UNKNOWN: &str = "unknown pbe encryption scheme";

pub(crate) const SER_COMPRESSION_INFORMATION: &str = "compression_information";
pub(crate) const SER_ENCRYPTION_INFORMATION: &str = "encryption_information";
pub(crate) const SER_OBJECT_DESCRIPTION_INFORMATION: &str = "object_description_information";

// other
pub(crate) const BYTES: &str = "bytes";