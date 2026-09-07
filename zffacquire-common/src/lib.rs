mod config;
pub mod constants;
mod header;
mod io;
mod signing;
mod traits;
mod utils;

#[cfg(target_os = "linux")]
pub mod device;

pub use config::{AcquireConfig, ToolIdentification};
pub use header::{
    compression_header, create_object_header, create_vos, encryption_header,
    object_description_header, parse_chunk_size, populate_logical_source_info,
    populate_physical_device_info, setup_object_flags,
};
pub use io::{concat_prefix_path, get_physical_input_file, get_size_of_inputfile, open_files};
pub use signing::create_signing_key;
// Re-exported so consumers can hold on to a key created by create_signing_key
// without taking a direct dependency on the ed25519 crate and risking a
// version skew with the one zff signs with.
pub use ed25519_dalek::SigningKey;
pub use traits::HumanReadable;
pub use utils::{get_os_string, hrs_parser, parse_key_val};

pub use zff::{
    CompressionAlgorithm, EncryptionAlgorithm, HashType, KDFScheme, LogicalObjectSource,
    LogicalObjectSourceFilesystem, PBEScheme, ReadAt,
    constants::{DEFAULT_COMPRESSION_RATIO_THRESHOLD, FIRST_FILE_EXTENSION, INITIAL_OBJECT_NUMBER},
    encryption::*,
    file_extension_next_value,
    header::{
        Argon2idParameters, CompressionHeader, DescriptionHeader, EncryptionHeader, KDFParameters,
        ObjectFlags, ObjectHeader, ObjectType, PBEHeader, PBKDF2SHA256Parameters, ScryptParameters,
    },
    io::{
        ZffCreationParameters,
        zffwriter::{SegmentationState, ZffFilesOutput, ZffWriter},
    },
};

#[cfg(target_os = "linux")]
pub mod memory_reader;
