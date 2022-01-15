//Error messages
pub(crate) const ERROR_OPEN_INPUT_FILE: &'static str = "Could not open input file: ";
pub(crate) const ERROR_ENCRYPT_KEY: &'static str = "Could not encrypt your key with the given password. This is a bug.";
pub(crate) const ERROR_UNKNOWN_ENCRYPTION_ALGORITHM: &'static str = "The given encryption algorithm is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub(crate) const ERROR_UNKNOWN_PASSWORD_KDF: &'static str = "The given password key derivation function is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub(crate) const ERROR_PARSE_KEY: &'static str = "Could not parse your given base64 formatted secret key / keypair.";
pub(crate) const ERROR_UNPARSABLE_SEGMENT_SIZE_VALUE: &'static str = "Error: can not parse the given segment size value: ";
pub(crate) const ERROR_GENERATE_FILES: &'static str = "An error occurred while trying to generate the zff file segment(s): ";

pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// uncategorized
pub(crate) const HRS_PARSER_BASE: u64 = 1024;