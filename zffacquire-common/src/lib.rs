mod config;
mod header;
mod io;
mod signing;
mod traits;
mod utils;
pub mod constants;

#[cfg(target_os = "linux")]
pub mod device;

pub use config::{AcquireConfig, ToolIdentification};
pub use header::{
    compression_header, encryption_header, object_description_header,
    populate_physical_device_info, populate_logical_source_info,
    setup_object_flags, create_object_header, create_vos, parse_chunk_size,
};
pub use io::{concat_prefix_path, get_physical_input_file, get_size_of_inputfile, open_files};
pub use signing::create_signing_key;
// Re-exported so consumers can hold on to a key created by create_signing_key
// without taking a direct dependency on the ed25519 crate and risking a
// version skew with the one zff signs with.
pub use ed25519_dalek::SigningKey;
pub use traits::HumanReadable;
pub use utils::{hrs_parser, parse_key_val, get_os_string};

pub use zff::{
    EncryptionAlgorithm,
    CompressionAlgorithm,
    KDFScheme,
    PBEScheme,
    HashType,
    ReadAt,
    LogicalObjectSource,
    LogicalObjectSourceFilesystem,
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
    io::{
        ZffCreationParameters,
        zffwriter::{ZffWriter, ZffFilesOutput, SegmentationState},
    },
    constants::{
        DEFAULT_COMPRESSION_RATIO_THRESHOLD,
        INITIAL_OBJECT_NUMBER,
        FIRST_FILE_EXTENSION,
    },
    file_extension_next_value,
    encryption::*,
};
