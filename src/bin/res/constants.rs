//Error messages
pub(crate) const ERROR_ENCRYPT_KEY: &str = "Could not encrypt/decrypt your key with the given password. This is an application bug.";
pub(crate) const ERROR_UNKNOWN_ENCRYPTION_ALGORITHM: &str = "The given encryption algorithm is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub(crate) const ERROR_UNKNOWN_PASSWORD_KDF: &str = "The given password key derivation function is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub(crate) const ERROR_PARSE_KEY: &str = "Could not parse your given base64 formatted secret key / keypair.";
pub(crate) const ERROR_UNPARSABLE_SEGMENT_SIZE_VALUE: &str = "Error: can not parse the given segment size value: ";
pub(crate) const ERROR_UNPARSABLE_CHUNKMAP_SIZE_VALUE: &str = "Error: can not parse the given chunkmap size value: ";
pub(crate) const ERROR_CANONICALIZE_INPUT_FILE_: &str = "An error occurred while trying to canonicalize following inputfile: ";
pub(crate) const ERROR_STRIPPING_PREFIX_INPUT_FILE_: &str = "An error occurred while trying to stripping the path-prefix of following inputfile: ";
pub(crate) const ERROR_GETTING_WINDOWS_VOLUME_LIST_: &str = "An error occurred while trying to get the list of Windows volumes.";

pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// uncategorized
pub(crate) const HRS_PARSER_BASE: u64 = 1024;
#[cfg(target_family = "unix")]
pub(crate) const UNIX_BASE: &str = "/";
#[cfg(target_family = "windows")]
pub(crate) const HARDDISKVOLUME_PREFIX: &str = "\\\\?\\HarddiskVolume";
pub (crate) const HARDDISKVOLUME_LOWERCASE_PREFIX: &str = "harddiskvolume";
pub (crate) const PHYSICALDISK_LOWERCASE_PREFIX: &str = "physicaldrive";

// scrypt parameters
pub(crate) const SCRYPT_LOGN_RECOMMENDED: u8 = 15;
pub(crate) const SCRYPT_R_RECOMMENDED: u32 = 1;
pub(crate) const SCRYPT_P_RECOMMENDED: u32 = 1;

// argon2 parameters
pub(crate) const ARGON_MEM_COST_RECOMMENDED: u32 = 1000000;
pub(crate) const ARGON_LANES_RECOMMENDED: u32 = 4;
pub(crate) const ARGON_ITERATIONS_RECOMMENDED: u32 = 8;

// custom description header entry keys
pub(crate) const TOOLNAME_KEY: &str = "tn";
pub(crate) const TOOLNAME_VALUE: &str = env!("CARGO_PKG_NAME");
pub(crate) const TOOLVERSION_KEY: &str = "tv";
pub(crate) const TOOLVERSION_VALUE: &str = env!("CARGO_PKG_VERSION");

// External
// workaround for snap package
pub(crate) const INPUTFILES_PATH_PREFIX: &str = "/";