pub const ERROR_ENCRYPT_KEY: &str =
    "Could not encrypt/decrypt your key with the given password. This is an application bug.";
pub const ERROR_UNKNOWN_ENCRYPTION_ALGORITHM: &str =
    "The given encryption algorithm is unknown/not supported by this application.";
pub const ERROR_UNKNOWN_COMPRESSION_ALGORITHM: &str =
    "The given compression algorithm is unknown/not supported by this application.";
pub const ERROR_UNKNOWN_PASSWORD_KDF: &str =
    "The given password key derivation function is unknown/not supported by this application.";
pub const ERROR_PARSE_KEY: &str =
    "Could not parse your given base64 formatted secret key / keypair.";
pub const ERROR_UNPARSABLE_SIZE_VALUE_OVERFLOW_: &str =
    "Error: the given size value is too large: ";
pub const WARNING_GENERATED_SIGNING_KEY_: &str = "A new signature key was generated. Store the following private key now, \
it is not written to the container and cannot be recovered from it: ";
pub const ERROR_UNPARSABLE_SEGMENT_SIZE_VALUE: &str =
    "Error: can not parse the given segment size value: ";
pub const ERROR_UNPARSABLE_CHUNKMAP_SIZE_VALUE: &str =
    "Error: can not parse the given chunkmap size value: ";
pub const ERROR_CANONICALIZE_INPUT_FILE_: &str =
    "An error occurred while trying to canonicalize following inputfile: ";
pub const ERROR_STRIPPING_PREFIX_INPUT_FILE_: &str =
    "An error occurred while trying to strip the path-prefix of following inputfile: ";
pub const ERROR_GETTING_WINDOWS_VOLUME_LIST_: &str =
    "An error occurred while trying to get the list of Windows volumes.";
pub const EXIT_STATUS_ERROR: i32 = 1;
pub const EXIT_STATUS_SUCCESS: i32 = 0;
pub const HRS_PARSER_BASE: u64 = 1024;
pub const ZSTD_COMPRESSION_LEVEL_MIN: u8 = 1;
pub const ZSTD_COMPRESSION_LEVEL_MAX: u8 = 22;
pub const UNIX_BASE: &str = "/";
pub const UNIX_BASE_DEV: &str = "/dev/";
pub const UDEV_SUBSYSTEM_BLOCK: &str = "block";
pub const UDEV_ATTRIBUTE_SIZE: &str = "size";
pub const HARDDISKVOLUME_LOWERCASE_PREFIX: &str = "harddiskvolume";
pub const PHYSICALDISK_LOWERCASE_PREFIX: &str = "physicaldrive";
pub const SCRYPT_LOGN_RECOMMENDED: u8 = 15;
pub const SCRYPT_R_RECOMMENDED: u32 = 1;
pub const SCRYPT_P_RECOMMENDED: u32 = 1;
pub const ARGON_MEM_COST_RECOMMENDED: u32 = 1000000;
pub const ARGON_LANES_RECOMMENDED: u32 = 4;
pub const ARGON_ITERATIONS_RECOMMENDED: u32 = 8;
// The values belong to whichever binary is acquiring, not to this library, so
// they travel in AcquireConfig::tool rather than being baked in here.
pub const TOOLNAME_KEY: &str = "tn";
pub const TOOLVERSION_KEY: &str = "tv";
pub const INPUTFILES_PATH_PREFIX: &str = "/";
