// - STD
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::{collections::HashMap, path::PathBuf, process::exit};

// - modules
mod res;

// - internal (from common crate)
#[cfg(target_os = "linux")]
use crate::res::{
    get_memory_reader,
    memory_reader::{MemoryReaderType, memory_size},
};
use zffacquire_common::{
    HumanReadable, concat_prefix_path, constants::*,
    create_object_header as common_create_object_header, create_signing_key, create_vos,
    encryption_header as common_encryption_header, get_physical_input_file, get_size_of_inputfile,
    hrs_parser, open_files, parse_key_val, populate_logical_source_info,
    populate_physical_device_info,
};

#[cfg(target_family = "windows")]
use crate::res::list_devices::print_devices_table;

use crate::res::{setup_output_writer, setup_output_writer_from_path};

use zff::header::DeduplicationMetadata;
use zff::io::zffreader::ZffReader;
use zff::io::zffwriter::SegmentationState;
use zff::{
    CompressionAlgorithm, EncryptionAlgorithm, HashType, KDFScheme, PBEScheme, ReadAt,
    VirtualObjectSourceLogicalTar,
    constants::{DEFAULT_COMPRESSION_RATIO_THRESHOLD, FIRST_FILE_EXTENSION, INITIAL_OBJECT_NUMBER},
    file_extension_next_value,
    header::{DeduplicationChunkMap, ObjectHeader, ObjectType},
    io::{
        ZffCreationParameters,
        zffwriter::{ZffFilesOutput, ZffWriter},
    },
};
use zff::{LogicalObjectSource, LogicalObjectSourceFilesystem};

// - external
use clap::{Parser, Subcommand, ValueEnum};
use ewf::{self, EwfReader};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
#[cfg(target_os = "linux")]
use log::warn;
use log::{LevelFilter, debug, error, info};
use rand::RngExt;
use zffacquire_common::SigningKey;

#[derive(Parser)]
#[clap(
    about,
    version,
    author,
    override_usage = "zffacquire <SUBCOMMAND> [OPTIONS]"
)]
struct Cli {
    /// Note describing the container as a whole. Distinct from --notes, which
    /// describes the acquired object; setting one does not affect the other.
    #[clap(
        short = 'D',
        long = "description-notes",
        global = true,
        required = false
    )]
    description_notes: Option<String>,
    #[clap(
        short = 'z',
        long = "compression-algorithm",
        global = true,
        required = false,
        value_enum,
        default_value = "zstd"
    )]
    compression_algorithm: CompressionAlgorithmValues,
    #[clap(
        short = 'l',
        long = "compression-level",
        global = true,
        required = false,
        default_value = "3"
    )]
    compression_level: u8,
    #[clap(short='T', long="compression-threshold", global=true, required=false, default_value=DEFAULT_COMPRESSION_RATIO_THRESHOLD)]
    compression_threshold: f32,
    #[clap(short = 's', long = "segment-size", global = true, required = false)]
    segment_size: Option<String>,
    #[clap(
        short = 'C',
        long,
        global = true,
        required = false,
        default_value = "32KB"
    )]
    chunk_size: String,
    #[clap(
        short = 'M',
        long,
        global = true,
        required = false,
        default_value = "32KB"
    )]
    chunkmap_size: String,
    #[clap(short = 'p', long = "encrypt", global = true, required = false)]
    encrypt: bool,
    /// Read the encryption password from this file instead of prompting, for
    /// unattended acquisition. The first line is used, without its line ending;
    /// "-" reads the password from stdin. The file is never written to.
    #[clap(
        long = "password-file",
        global = true,
        required = false,
        requires = "encrypt"
    )]
    password_file: Option<PathBuf>,
    #[clap(
        short = 'r',
        long,
        global = true,
        required = false,
        conflicts_with = "in_memory_chunk_deduplication",
        group = "deduplication"
    )]
    on_disk_chunk_deduplication: Option<PathBuf>,
    #[clap(
        short = 'm',
        long,
        global = true,
        required = false,
        conflicts_with = "on_disk_chunk_deduplication",
        group = "deduplication"
    )]
    in_memory_chunk_deduplication: bool,
    #[clap(
        short = 'K',
        long = "password-kdf",
        global = true,
        required = false,
        value_enum,
        default_value = "argon2id-aes256",
        requires = "encrypt"
    )]
    password_kdf: PasswordKdfValues,
    #[clap(
        short = 'E',
        long = "encryption-algorithm",
        global = true,
        required = false,
        value_enum,
        default_value = "aes256gcm",
        requires = "encrypt"
    )]
    encryption_algorithm: EncryptionAlgorithmValues,
    #[clap(
        short = 'd',
        long = "hash-algorithm",
        global = true,
        required = false,
        value_enum,
        default_value = "blake3"
    )]
    hash_algorithm: Vec<HashAlgorithmValues>,
    #[clap(short = 'S', long = "sign-data", global = true)]
    sign_data: bool,
    #[clap(short = 'k', long = "eddsa-key", global = true, required = false)]
    sign_key: Option<String>,
    #[clap(short = 'c', long = "case-number", global = true, required = false)]
    case_number: Option<String>,
    #[clap(short = 'e', long = "evidence-number", global = true, required = false)]
    evidence_number: Option<String>,
    #[clap(short = 'x', long = "examiner-name", global = true, required = false)]
    examiner_name: Option<String>,
    /// Note stored in the acquired object's description header. Distinct from
    /// --description-notes, which describes the container.
    #[clap(short = 'n', long = "notes", global = true, required = false)]
    notes: Option<String>,
    #[arg(short = 'O', long="custom-description", value_parser = parse_key_val::<String, String>, global=true, required=false)]
    custom_descriptions: Vec<(String, String)>,
    #[clap(
        short = 'L',
        long = "log-level",
        value_enum,
        default_value = "info",
        global = true,
        required = false
    )]
    log_level: LogLevel,
    #[clap(
        short = 'U',
        long = "uncompress-input",
        global = true,
        required = false
    )]
    uncompress_input: bool,
    #[clap(
        short = 'P',
        long = "progress-bar",
        global = true,
        required = false,
        default_value = "false"
    )]
    progress_bar: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[clap(arg_required_else_help = true)]
    Physical {
        #[clap(short = 'i', long = "inputfile", required = true)]
        inputfile: PathBuf,
        #[clap(short = 'o', long = "outputfile", global = true, required = false)]
        outputfile: Option<String>,
    },
    #[clap(arg_required_else_help = true)]
    Logical {
        #[clap(short = 'i', long = "inputfiles", required = true)]
        inputfiles: Vec<PathBuf>,
        #[clap(short = 'o', long = "outputfile", global = true, required = false)]
        outputfile: Option<String>,
    },
    #[cfg(target_os = "linux")]
    Memory {
        #[clap(short = 'o', long = "outputfile", global = true, required = false)]
        outputfile: Option<String>,
    },
    #[clap(arg_required_else_help = true)]
    Extend {
        #[clap(short='a', long="append", global=true, value_delimiter = ' ', num_args = 1..)]
        append_files: Vec<PathBuf>,
        #[clap(subcommand)]
        extend_command: ExtendSubcommands,
    },
    #[clap(arg_required_else_help = true)]
    Convert {
        #[clap(subcommand)]
        convert_command: ConvertSubcommands,
    },
    #[cfg(target_family = "windows")]
    ListDevices {},
}

#[derive(Subcommand)]
enum ConvertSubcommands {
    #[clap(arg_required_else_help = true)]
    Tar {
        #[clap(short = 'i', long = "inputfile", required = true)]
        inputfile: PathBuf,
        #[clap(short = 'o', long = "outputfile", global = true, required = false)]
        outputfile: String,
    },
    #[clap(arg_required_else_help = true)]
    Ewf {
        #[clap(short = 'i', long = "input-segment-files", required = true)]
        input_segments: Vec<PathBuf>,
        #[clap(short = 'o', long = "outputfile", global = true, required = false)]
        outputfile: Option<String>,
    },
}

#[derive(Subcommand)]
enum ExtendSubcommands {
    #[clap(arg_required_else_help = true)]
    Physical {
        #[clap(short = 'i', long = "inputfile", required = true)]
        inputfile: PathBuf,
    },
    #[clap(arg_required_else_help = true)]
    Logical {
        #[clap(short = 'i', long = "inputfiles", required = true)]
        inputfiles: Vec<PathBuf>,
    },
    #[cfg(target_os = "linux")]
    #[clap(arg_required_else_help = true)]
    Memory {},
}

#[derive(ValueEnum, Clone, PartialEq)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
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
    None,
    Zstd,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProgressBarValue {
    TotalSize(u64),
    NumberOfFiles(u64),
}

impl Cli {
    fn to_acquire_config(&self) -> zffacquire_common::AcquireConfig {
        let (kdf_scheme, pbe_scheme) = match self.password_kdf {
            PasswordKdfValues::Pbkdf2Sha256Aes128 => {
                (KDFScheme::PBKDF2SHA256, PBEScheme::AES128CBC)
            }
            PasswordKdfValues::Pbkdf2Sha256Aes256 => {
                (KDFScheme::PBKDF2SHA256, PBEScheme::AES256CBC)
            }
            PasswordKdfValues::ScryptAes128 => (KDFScheme::Scrypt, PBEScheme::AES128CBC),
            PasswordKdfValues::ScryptAes256 => (KDFScheme::Scrypt, PBEScheme::AES256CBC),
            PasswordKdfValues::Argon2idAes128 => (KDFScheme::Argon2id, PBEScheme::AES128CBC),
            PasswordKdfValues::Argon2idAes256 => (KDFScheme::Argon2id, PBEScheme::AES256CBC),
        };
        let encryption_algorithm = match self.encryption_algorithm {
            EncryptionAlgorithmValues::AES128GCM => EncryptionAlgorithm::AES128GCM,
            EncryptionAlgorithmValues::AES256GCM => EncryptionAlgorithm::AES256GCM,
            EncryptionAlgorithmValues::CHACHA20POLY1305 => EncryptionAlgorithm::CHACHA20POLY1305,
        };
        let hash_algorithms = self
            .hash_algorithm
            .iter()
            .map(|h| match h {
                HashAlgorithmValues::Blake2b512 => HashType::Blake2b512,
                HashAlgorithmValues::SHA256 => HashType::SHA256,
                HashAlgorithmValues::SHA512 => HashType::SHA512,
                HashAlgorithmValues::SHA3_256 => HashType::SHA3_256,
                HashAlgorithmValues::Blake3 => HashType::Blake3,
            })
            .collect();
        zffacquire_common::AcquireConfig {
            tool: zffacquire_common::tool_identification!(),
            compression_algorithm: match self.compression_algorithm {
                CompressionAlgorithmValues::None => CompressionAlgorithm::None,
                CompressionAlgorithmValues::Zstd => CompressionAlgorithm::Zstd,
                CompressionAlgorithmValues::Lz4 => CompressionAlgorithm::Lz4,
            },
            compression_level: self.compression_level,
            compression_threshold: self.compression_threshold,
            encrypt: self.encrypt,
            kdf_scheme,
            pbe_scheme,
            encryption_algorithm,
            hash_algorithms,
            sign_data: self.sign_data,
            sign_key: self.sign_key.clone(),
            case_number: self.case_number.clone(),
            evidence_number: self.evidence_number.clone(),
            examiner_name: self.examiner_name.clone(),
            notes: self.notes.clone(),
            custom_descriptions: self.custom_descriptions.clone(),
            segment_size: self.segment_size.clone(),
            chunk_size: self.chunk_size.clone(),
            chunkmap_size: self.chunkmap_size.clone(),
            description_notes: self.description_notes.clone(),
            uncompress_input: self.uncompress_input,
        }
    }
}

/// Reads the password from a file (or stdin for "-"), for unattended runs.
///
/// Only the first line is taken, so a trailing newline in the file is not part
/// of the password.
fn read_password_file(path: &Path) -> Result<String, String> {
    let mut content = String::new();
    if path == Path::new("-") {
        std::io::stdin()
            .read_to_string(&mut content)
            .map_err(|e| format!("Could not read the password from stdin: {e}"))?;
    } else {
        content = std::fs::read_to_string(path)
            .map_err(|e| format!("Could not read the password file {}: {e}", path.display()))?;
    }
    let password = content.lines().next().unwrap_or_default().to_string();
    if password.is_empty() {
        return Err("The given password file is empty.".to_string());
    }
    Ok(password)
}

fn ask_password(args: &Cli) -> Option<String> {
    if !args.encrypt {
        info!("Object will not be encrypted.");
        return None;
    }
    if let Some(path) = &args.password_file {
        match read_password_file(path) {
            Ok(password) => return Some(password),
            Err(e) => {
                error!("{e}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    }
    let password = match rpassword::prompt_password("Enter the encryption password: ") {
        Ok(pw) => pw,
        Err(e) => {
            error!(
                "An error occured while trying to read your password...please use only UTF8 valid characters:\n{e}"
            );
            exit(EXIT_STATUS_ERROR);
        }
    };
    let verify_pw = match rpassword::prompt_password("Re-enter the encryption password (verify): ")
    {
        Ok(pw) => pw,
        Err(e) => {
            error!(
                "An error occured while trying to read your password...please use only UTF8 valid characters:\n{e}"
            );
            exit(EXIT_STATUS_ERROR);
        }
    };
    if password != verify_pw {
        error!("Passwords didn't match.");
        exit(EXIT_STATUS_ERROR);
    }
    Some(password)
}

fn main() {
    let args = Cli::parse();
    let config = args.to_acquire_config();

    let multi = MultiProgress::with_draw_target(ProgressDrawTarget::stderr());

    let log_level = match args.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    let logger = env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .build();

    if let Err(e) = LogWrapper::new(multi.clone(), logger).try_init() {
        eprintln!("Could not initialize the logger: {e}");
        exit(EXIT_STATUS_ERROR);
    }

    debug!("Started zffacquire");
    let pid = std::process::id();
    info!("Using PID: {pid}");

    #[cfg(target_family = "windows")]
    if let Commands::ListDevices {} = args.command {
        print_devices_table();
        exit(EXIT_STATUS_SUCCESS);
    }

    let hash_types = config.hash_algorithms.clone();
    debug!("Following hash algorithms will be used: {:?}", hash_types);

    let chunk_size_val = match hrs_parser(&args.chunk_size) {
        Some(val) => val,
        None => {
            error!(
                "Cannot parse {}, please enter a valid size (e.g. 32K, 40k, 10M, ...)",
                args.chunk_size
            );
            exit(EXIT_STATUS_ERROR);
        }
    };

    let password = ask_password(&args);

    let encryption_hdr = match password {
        Some(ref password) => match common_encryption_header(
            config.kdf_scheme.clone(),
            config.pbe_scheme.clone(),
            config.encryption_algorithm.clone().clone(),
            password,
        ) {
            Ok(hdr) => Some(hdr),
            Err(e) => {
                error!("Failed to create encryption header: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        None => None,
    };

    let sign_keypair = match create_signing_key(&config) {
        Ok(key) => key,
        Err(e) => {
            error!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    let mut optional_parameter = setup_optional_parameter(&args, sign_keypair.clone());

    let mut obj_header =
        match common_create_object_header(&config, encryption_hdr, object_is_passive(&args)) {
            Ok(hdr) => hdr,
            Err(e) => {
                error!("Failed to create object header: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };

    let mut logical_objects: HashMap<ObjectHeader, Box<dyn LogicalObjectSource>> = HashMap::new();
    let mut physical_objects = HashMap::new();
    let mut virtual_objects = HashMap::new();

    let mut progressbar_value;

    let zff_files_output = match &args.command {
        #[cfg(target_family = "windows")]
        Commands::ListDevices {} => {
            unreachable!()
        }
        Commands::Physical {
            inputfile,
            outputfile,
        } => {
            setup_deduplication_map(&args, &mut optional_parameter, None);
            let inputfile_size = match get_size_of_inputfile(inputfile.clone()) {
                Ok(size) => size,
                Err(e) => {
                    let inputfile = inputfile.to_string_lossy();
                    error!(
                        "Following error occurred while trying to get the size of {inputfile}:\n{e}"
                    );
                    exit(EXIT_STATUS_ERROR);
                }
            };
            progressbar_value = ProgressBarValue::TotalSize(inputfile_size);

            let file = match get_physical_input_file(inputfile.clone(), args.uncompress_input) {
                Ok(file) => file,
                Err(e) => {
                    let inputfile = inputfile.to_string_lossy();
                    error!("Following error occurred while trying to open {inputfile}:\n{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };

            populate_physical_device_info(&mut obj_header.description_header, inputfile);
            physical_objects.insert(obj_header, file);

            if let Some(outputfile) = outputfile {
                let mut outputfile = PathBuf::from(outputfile);
                outputfile.set_extension(FIRST_FILE_EXTENSION);
                ZffFilesOutput::NewContainer(outputfile)
            } else {
                optional_parameter.target_segment_size = None;
                ZffFilesOutput::Stream
            }
        }
        Commands::Logical {
            inputfiles,
            outputfile,
        } => {
            setup_deduplication_map(&args, &mut optional_parameter, None);
            let inputfiles: Vec<PathBuf> = inputfiles
                .iter()
                .map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX, x))
                .collect();
            obj_header.object_type = ObjectType::Logical;

            populate_logical_source_info(&mut obj_header.description_header, &inputfiles);

            progressbar_value = ProgressBarValue::NumberOfFiles(inputfiles.len() as u64);
            let logical_object_source = match LogicalObjectSourceFilesystem::try_from(inputfiles) {
                Ok(source) => source,
                Err(e) => {
                    error!("Failed to initialize logical object for filesystem data: {e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };
            logical_objects.insert(obj_header, Box::new(logical_object_source));

            if let Some(outputfile) = outputfile {
                let mut outputfile = PathBuf::from(outputfile);
                outputfile.set_extension(FIRST_FILE_EXTENSION);
                ZffFilesOutput::NewContainer(outputfile)
            } else {
                optional_parameter.target_segment_size = None;
                ZffFilesOutput::Stream
            }
        }
        #[cfg(target_os = "linux")]
        Commands::Memory { outputfile } => {
            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
            if ret != 0 {
                warn!("remove limit on locked memory failed, ret is: {}", ret);
            }

            let mem_size = match memory_size() {
                Ok(size) => size,
                Err(e) => {
                    error!("Could not calculate system memory size: {e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };
            progressbar_value = ProgressBarValue::TotalSize(mem_size);

            let memory_reader = match get_memory_reader(MemoryReaderType::Emd) {
                Ok(memory_reader) => memory_reader,
                Err(e) => {
                    error!("Failed to create ebpf based memory reader: {e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };
            physical_objects.insert(obj_header, memory_reader);

            if let Some(outputfile) = outputfile {
                let mut outputfile = PathBuf::from(outputfile);
                outputfile.set_extension(FIRST_FILE_EXTENSION);
                ZffFilesOutput::NewContainer(outputfile)
            } else {
                optional_parameter.target_segment_size = None;
                ZffFilesOutput::Stream
            }
        }
        Commands::Extend {
            extend_command,
            append_files,
        } => {
            setup_deduplication_map(&args, &mut optional_parameter, Some(append_files.to_vec()));
            match extend_command {
                ExtendSubcommands::Logical { inputfiles } => {
                    let inputfiles: Vec<PathBuf> = inputfiles
                        .iter()
                        .map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX, x))
                        .collect();
                    obj_header.object_type = ObjectType::Logical;

                    populate_logical_source_info(&mut obj_header.description_header, &inputfiles);
                    progressbar_value = ProgressBarValue::NumberOfFiles(inputfiles.len() as u64);
                    let logical_object_source =
                        match LogicalObjectSourceFilesystem::try_from(inputfiles) {
                            Ok(source) => source,
                            Err(e) => {
                                error!(
                                    "Failed to initialize logical object for filesystem data: {e}"
                                );
                                exit(EXIT_STATUS_ERROR);
                            }
                        };
                    logical_objects.insert(obj_header, Box::new(logical_object_source));
                }
                ExtendSubcommands::Physical { inputfile } => {
                    let inputfile_size = match get_size_of_inputfile(inputfile.clone()) {
                        Ok(size) => size,
                        Err(e) => {
                            let inputfile = inputfile.to_string_lossy();
                            error!(
                                "Following error occurred while trying to get the size of {inputfile}:\n{e}"
                            );
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    progressbar_value = ProgressBarValue::TotalSize(inputfile_size);
                    let file = match get_physical_input_file(
                        inputfile.clone(),
                        args.uncompress_input,
                    ) {
                        Ok(file) => file,
                        Err(e) => {
                            let inputfile = inputfile.to_string_lossy();
                            error!(
                                "Following error occurred while trying to open {inputfile}:\n{e}"
                            );
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    populate_physical_device_info(&mut obj_header.description_header, inputfile);
                    physical_objects.insert(obj_header, file);
                }
                #[cfg(target_os = "linux")]
                ExtendSubcommands::Memory {} => {
                    let rlim = libc::rlimit {
                        rlim_cur: libc::RLIM_INFINITY,
                        rlim_max: libc::RLIM_INFINITY,
                    };
                    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
                    if ret != 0 {
                        warn!("remove limit on locked memory failed, ret is: {}", ret);
                    }

                    let mem_size = match memory_size() {
                        Ok(size) => size,
                        Err(e) => {
                            error!("Could not calculate system memory size: {e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    progressbar_value = ProgressBarValue::TotalSize(mem_size);

                    let memory_reader = match get_memory_reader(MemoryReaderType::Emd) {
                        Ok(memory_reader) => memory_reader,
                        Err(e) => {
                            error!("Failed to create ebpf based memory reader: {e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    physical_objects.insert(obj_header, memory_reader);
                }
            };

            ZffFilesOutput::ExtendContainer(append_files.to_vec())
        }
        Commands::Convert { convert_command } => {
            setup_deduplication_map(&args, &mut optional_parameter, None);
            match convert_command {
                ConvertSubcommands::Ewf {
                    input_segments,
                    outputfile,
                } => {
                    obj_header.description_header.custom_identifier_value(
                        "zffacquire::ewf_image",
                        file_names(input_segments).join(", "),
                    );
                    let mut ewf_reader = match EwfReader::open_segments(input_segments) {
                        Ok(reader) => reader,
                        Err(e) => {
                            error!("An error occured while trying to open ewf segment(s): {e}");
                            exit(EXIT_STATUS_ERROR)
                        }
                    };
                    let ewf_size = match ewf_reader
                        .seek(std::io::SeekFrom::End(0))
                        .and_then(|size| ewf_reader.rewind().map(|_| size))
                    {
                        Ok(size) => size,
                        Err(e) => {
                            error!(
                                "An error occured while trying to determine the size of the ewf image: {e}"
                            );
                            exit(EXIT_STATUS_ERROR)
                        }
                    };
                    info!("EWF image size: {}", ewf_size.bytes_as_hrb());
                    progressbar_value = ProgressBarValue::TotalSize(ewf_size);

                    physical_objects.insert(obj_header, Box::new(ewf_reader));

                    if let Some(outputfile) = outputfile {
                        let mut outputfile = PathBuf::from(outputfile);
                        outputfile.set_extension(FIRST_FILE_EXTENSION);
                        ZffFilesOutput::NewContainer(outputfile)
                    } else {
                        optional_parameter.target_segment_size = None;
                        ZffFilesOutput::Stream
                    }
                }
                ConvertSubcommands::Tar {
                    inputfile,
                    outputfile,
                } => {
                    obj_header.description_header.custom_identifier_value(
                        "zffacquire::tar_archive::virtual_mapped_object",
                        file_names(std::slice::from_ref(inputfile)).join(", "),
                    );
                    let fd = match File::open(inputfile) {
                        Ok(fd) => fd,
                        Err(e) => {
                            error!(
                                "Unable to open inputfile {}: {e}",
                                inputfile.to_string_lossy()
                            );
                            exit(EXIT_STATUS_ERROR)
                        }
                    };

                    let inputfile = match phollpers::compression::decompress(fd) {
                        Ok(reader) => reader,
                        Err(e) => {
                            error!("Unable to read inputfile: {e}");
                            exit(EXIT_STATUS_ERROR)
                        }
                    };
                    progressbar_value = ProgressBarValue::NumberOfFiles(1);

                    let mut outputfile = PathBuf::from(outputfile);
                    outputfile.set_extension(FIRST_FILE_EXTENSION);

                    info!("Reading tar source file. This could take a few minutes ...");
                    let mut converter_objects = HashMap::new();
                    converter_objects.insert(obj_header, inputfile);

                    let zff_files_output = ZffFilesOutput::NewContainer(outputfile);

                    // The intermediate container consumes these parameters, so the
                    // writer for the virtual object further down is given a second
                    // set -- carrying the same signature key, so both objects in
                    // the container are signed by the same key.
                    let intermediate_parameter = std::mem::replace(
                        &mut optional_parameter,
                        setup_optional_parameter(&args, sign_keypair.clone()),
                    );
                    let mut zs = match ZffWriter::new(
                        converter_objects,
                        HashMap::new(),
                        HashMap::new(),
                        hash_types.clone(),
                        intermediate_parameter,
                        zff_files_output,
                    ) {
                        Ok(zw) => zw,
                        Err(e) => {
                            error!(
                                "An error occured while trying to create the ZffWriter object:\n{e}"
                            );
                            exit(EXIT_STATUS_ERROR);
                        }
                    };

                    let segment_filepaths = match zs.generate_files() {
                        Ok(filenames) => filenames,
                        Err(e) => {
                            error!("An error occured while filling the zff container:\n {e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };

                    let reader_vec = match open_files(&segment_filepaths) {
                        Ok(files) => files,
                        Err(e) => {
                            error!("{e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };

                    let mut zffreader = match ZffReader::with_reader(reader_vec) {
                        Ok(reader) => reader,
                        Err(e) => {
                            error!("An error occurred while trying to create the ZffReader: {e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    match zffreader.initialize_object(INITIAL_OBJECT_NUMBER) {
                        Ok(_) => debug!(
                            "Successfully initialized passive object {INITIAL_OBJECT_NUMBER}"
                        ),
                        Err(e) => {
                            error!(
                                "Could not inititalize object {INITIAL_OBJECT_NUMBER} due following error: {e}"
                            );
                            exit(EXIT_STATUS_ERROR);
                        }
                    }
                    if let Some(ref password) = password {
                        match zffreader.decrypt_object(INITIAL_OBJECT_NUMBER, password) {
                            Ok(o_type) => debug!(
                                "Passive object {INITIAL_OBJECT_NUMBER} ({o_type} object) decrypted successfully"
                            ),
                            Err(e) => {
                                error!(
                                    "Could not decrypt passive object {INITIAL_OBJECT_NUMBER}: {e}"
                                );
                                exit(EXIT_STATUS_ERROR)
                            }
                        }
                    }

                    let virtual_encryption_header = match password {
                        Some(ref password) => match common_encryption_header(
                            config.kdf_scheme.clone(),
                            config.pbe_scheme.clone(),
                            config.encryption_algorithm.clone().clone(),
                            password,
                        ) {
                            Ok(hdr) => Some(hdr),
                            Err(e) => {
                                error!("Failed to create virtual encryption header: {e}");
                                exit(EXIT_STATUS_ERROR);
                            }
                        },
                        None => None,
                    };

                    let vos_tar = match VirtualObjectSourceLogicalTar::new(
                        zffreader,
                        INITIAL_OBJECT_NUMBER,
                        None,
                        hash_types.clone(),
                    ) {
                        Ok(vos_tar) => create_vos(vos_tar),
                        Err(e) => {
                            error!(
                                "An error occured while trying to create the virtual object writer: {e}"
                            );
                            exit(EXIT_STATUS_ERROR)
                        }
                    };
                    let mut obj_header = match common_create_object_header(
                        &config,
                        virtual_encryption_header,
                        false,
                    ) {
                        Ok(hdr) => hdr,
                        Err(e) => {
                            error!("Failed to create object header: {e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    obj_header.flags.passive_object = false;
                    obj_header.object_type = ObjectType::Virtual;

                    virtual_objects.insert(obj_header, vos_tar);

                    ZffFilesOutput::ExtendContainer(segment_filepaths)
                }
            }
        }
    };

    let mut zs = match ZffWriter::new(
        physical_objects,
        logical_objects,
        virtual_objects,
        hash_types,
        optional_parameter,
        zff_files_output.clone(),
    ) {
        Ok(zs) => zs,
        Err(e) => {
            error!("An error occured while trying to create the ZffStreamer object:\n{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    let pb = if args.progress_bar {
        let pb = match progressbar_value {
            ProgressBarValue::TotalSize(total_size) => {
                info!("Total size to dump: {}", total_size.bytes_as_hrb());
                let pb = multi.add(ProgressBar::new(total_size));
                pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{decimal_bytes_per_sec}] [{wide_bar:.green/blue}] [{decimal_bytes}/{decimal_total_bytes}] [{percent}%] ({eta})")
                .unwrap()
                .progress_chars("=>-"));
                pb
            }
            ProgressBarValue::NumberOfFiles(_) => {
                let number_of_files_readable = zs.files_left_total();
                progressbar_value = ProgressBarValue::NumberOfFiles(number_of_files_readable);
                info!("Number of files to dump: {}", number_of_files_readable);
                let pb = multi.add(ProgressBar::new(number_of_files_readable));
                pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.green/blue}] [{pos}/{len} Files] [{percent}%] ({eta})")
                .unwrap()
                .progress_chars("=>-"));
                pb
            }
        };
        Some(pb)
    } else {
        None
    };
    let mut buffer = vec![0u8; chunk_size_val as usize];

    // When an existing container is extended, zff appends to the segment that
    // carries the main footer -- the last one, not necessarily the first path
    // given with -a. It reports that choice through output_path(), so the
    // writer is derived from the writer's own view of the output rather than
    // from the paths on the command line.
    let mut outputfile_path = zs.output_path().unwrap_or_default();
    let mut output_writer = setup_output_writer(&zff_files_output, zs.output_path().as_deref());

    let mut current_extension = outputfile_path
        .extension()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_string();

    loop {
        if let Some(ref pb) = pb {
            match progressbar_value {
                ProgressBarValue::TotalSize(_) => {
                    pb.set_position(zs.current_chunk_number() * chunk_size_val)
                }
                ProgressBarValue::NumberOfFiles(total_files) => {
                    pb.set_position(total_files - zs.files_left_total())
                }
            }
        }

        match zs.read(&mut buffer) {
            Ok(0) => match zs.next_segment() {
                SegmentationState::SegmentFinished => {
                    current_extension = match file_extension_next_value(current_extension) {
                        Ok(val) => val,
                        Err(e) => {
                            error!(
                                "An error occured while trying to set next segment file extension:\n{e}"
                            );
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    outputfile_path.set_extension(&current_extension);
                    output_writer = setup_output_writer_from_path(&outputfile_path);
                }
                SegmentationState::LastSegmentFinished => break,
                SegmentationState::SegmentNotFinished => (),
            },
            Ok(n) => match output_writer.write_all(&buffer[..n]) {
                Ok(_) => (),
                Err(e) => {
                    error!("An error occured while trying to write to the output file:\n{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            },
            Err(e) => {
                error!("An error occured while trying to read from the input file:\n{e}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    }
    match progressbar_value {
        ProgressBarValue::TotalSize(total_size) => info!(
            "{} dumped. Finishing container...",
            (total_size.bytes_as_hrb())
        ),
        ProgressBarValue::NumberOfFiles(total_files) => info!(
            "{} files dumped. Finishing container...",
            total_files - zs.files_left_total()
        ),
    }
    if let Some(pb) = pb {
        pb.finish();
    }

    info!("Zff file(s) successfully created");
    exit(EXIT_STATUS_SUCCESS);
}

/// Builds the creation parameters for one container.
///
/// The signature key is passed in rather than derived here: the tar conversion
/// needs a second parameter set for the container it extends, and deriving a
/// key again would sign the two halves of one container with different keys.
fn setup_optional_parameter<R: ReadAt>(
    args: &Cli,
    sign_keypair: Option<SigningKey>,
) -> ZffCreationParameters<R> {
    let mut rng = rand::rng();

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
            error!(
                "{}{}",
                ERROR_UNPARSABLE_CHUNKMAP_SIZE_VALUE, args.chunkmap_size
            );
            exit(EXIT_STATUS_ERROR);
        }
    };

    let unique_identifier = rng.random();

    ZffCreationParameters {
        signature_key: sign_keypair,
        target_segment_size,
        chunkmap_size,
        deduplication_metadata: None,
        unique_identifier,
        description_notes: args.description_notes.clone(),
    }
}

fn setup_deduplication_map(
    args: &Cli,
    optional_parameter: &mut ZffCreationParameters<File>,
    segment_file_paths: Option<Vec<PathBuf>>,
) {
    let mut deduplication_map = if args.in_memory_chunk_deduplication {
        DeduplicationChunkMap::new_in_memory_map()
    } else if let Some(path) = &args.on_disk_chunk_deduplication {
        match DeduplicationChunkMap::new_from_path(path) {
            Ok(map) => map,
            Err(e) => {
                error!("cannot create deduplication chunkmap: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    } else {
        return;
    };
    let deduplication_metadata = if let Some(segment_file_paths) = segment_file_paths {
        let segment_files = setup_segments(segment_file_paths);
        let zs = setup_zffreader(segment_files);
        match zs.get_xxhashmaps_unencrypted() {
            Ok(map) => {
                for (chunk_no, xxhash) in map {
                    if let Err(e) = deduplication_map.append_entry(xxhash, chunk_no) {
                        error!(
                            "An error occured while trying to append an entry to the deduplication map: {e}"
                        );
                        exit(EXIT_STATUS_ERROR);
                    }
                }
            }
            Err(e) => {
                error!(
                    "An error occured while trying to append an entry to the deduplication map: {e}"
                );
                exit(EXIT_STATUS_ERROR);
            }
        };

        Some(DeduplicationMetadata {
            deduplication_map,
            original_zffreader: Some(zs),
        })
    } else {
        Some(DeduplicationMetadata {
            deduplication_map,
            original_zffreader: None,
        })
    };
    optional_parameter.deduplication_metadata = deduplication_metadata;
}

fn setup_zffreader<R: ReadAt>(segment_files: Vec<R>) -> ZffReader<R> {
    let mut zs = match ZffReader::with_reader(segment_files) {
        Ok(zs) => zs,
        Err(e) => {
            error!("Error initializing ZffReader: {}", e);
            exit(EXIT_STATUS_ERROR);
        }
    };
    if let Err(e) = zs.initialize_objects_all() {
        error!("Error initializing objects: {}", e);
        exit(EXIT_STATUS_ERROR);
    };
    zs
}

fn setup_segments(segment_file_paths: Vec<PathBuf>) -> Vec<File> {
    let mut files = Vec::new();
    for segment in segment_file_paths {
        let file = match File::open(segment) {
            Ok(file) => file,
            Err(e) => {
                error!("Error opening file: {}", e);
                exit(EXIT_STATUS_ERROR);
            }
        };
        files.push(file);
    }
    files
}

/// File names of the given paths, for the description header.
///
/// A path with no final component (a bare "/" or one ending in "..") keeps its
/// full display form rather than panicking on an absent file name.
fn file_names(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| match path.file_name() {
            Some(name) => name.to_string_lossy().to_string(),
            None => path.display().to_string(),
        })
        .collect()
}

fn object_is_passive(args: &Cli) -> bool {
    matches!(
        args.command,
        Commands::Convert {
            convert_command: ConvertSubcommands::Tar {
                inputfile: _,
                outputfile: _
            }
        }
    )
}
