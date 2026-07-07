// - STD
use std::{
    process::exit,
    path::{PathBuf, Path},
    collections::HashMap,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, SeekFrom, Seek, Cursor};
use std::error::Error;
use std::ops::Range;

#[cfg(target_family = "windows")]
use std::{io, ptr};

// - modules
mod res;

// - internal
use crate::res::{
    chunk_size, concat_prefix_path, constants::*, get_physical_input_file, get_size_of_inputfile, header_creation::{self, ask_password, create_object_header}, hrs_parser, open_files, parse_key_val
};
#[cfg(target_os = "linux")]
use crate::res::{
    memory_reader::{MemoryReaderType, memory_size},
    get_memory_reader,
    setup_output_writer,
    setup_output_writer_from_path,
};

#[cfg(target_family = "windows")]
use crate::res::list_devices::print_devices_table;

use res::traits::HumanReadable;
use zff::{LogicalObjectSource, LogicalObjectSourceFilesystem};
use zff::header::DeduplicationMetadata;
use zff::io::zffreader::ZffReader;
use zff::io::zffwriter::SegmentationState;
use zff::{
    ReadAt,
    VirtualObjectSourceLogicalTar,
    EncryptionAlgorithm,
    CompressionAlgorithm,
    KDFScheme,
    PBEScheme,
    Signature,
    HashType,
    file_extension_next_value,
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
        DeduplicationChunkMap, 
        ObjectHeader, 
        ObjectFlags,
    },
    io::{ZffCreationParameters,zffwriter::{ZffWriter, ZffFilesOutput},
    },
    constants::{
        DEFAULT_COMPRESSION_RATIO_THRESHOLD,
        INITIAL_OBJECT_NUMBER,
        FIRST_FILE_EXTENSION,
    },
    encryption::*,
};

// - external
use clap::{
    Parser,
    Subcommand,
    ValueEnum,
};
use ewf::{self, EwfReader};
use indicatif::{ProgressBar, MultiProgress, ProgressStyle, ProgressDrawTarget};
use indicatif_log_bridge::LogWrapper;
use rand::RngExt;
use ed25519_dalek::SigningKey;
use log::{LevelFilter, error, debug, info, warn};
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};
use phollpers::compression::decompress;

#[cfg(target_os = "linux")]
use procfs::process::{Process, MMPermissions};
#[cfg(target_os = "linux")]
use aya::{
    programs::UProbe, 
    Ebpf,
    maps::{MapData, Queue},
};
#[cfg(target_family = "windows")]
use comfy_table::{
    Table, Attribute, Cell, ContentArrangement,
    modifiers::UTF8_ROUND_CORNERS,
    presets::UTF8_FULL,
};

#[cfg(target_family = "windows")]
use windows_drives::drive::{BufferedPhysicalDrive, BufferedHarddiskVolume};
#[cfg(target_family = "windows")]
use winapi::{
    shared::minwindef::{MAX_PATH, DWORD},
    um::{
        fileapi::{
            GetVolumeInformationByHandleW, 
            FindFirstVolumeW,
            FindNextVolumeW,
            QueryDosDeviceW,
            GetVolumePathNamesForVolumeNameW,
            OPEN_EXISTING,
            CreateFileW,
        },
        handleapi::{INVALID_HANDLE_VALUE, CloseHandle},
        ioapiset::DeviceIoControl,
        winioctl::{IOCTL_STORAGE_GET_DEVICE_NUMBER, STORAGE_DEVICE_NUMBER, IOCTL_DISK_GET_DRIVE_GEOMETRY, DISK_GEOMETRY},
        winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE},
    },
};
#[cfg(target_os = "linux")]
use emd_common::*;

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

    /// encrypts the the zff object.
    #[clap(short='p', long="encrypt", global=true, required=false)]
    encrypt: bool,

    /// This option activates the deduplication feature using an on-disk buffer (currently, a temporary redb-database will be used).
    #[clap(short='r', long, global=true, required=false, conflicts_with="in_memory_chunk_deduplication", group="deduplication")]
    on_disk_chunk_deduplication: Option<PathBuf>,

    /// This option activates the deduplication feature using an in-memory buffer.
    #[clap(short='m', long, global=true, required=false, conflicts_with="on_disk_chunk_deduplication", group="deduplication")]
    in_memory_chunk_deduplication: bool,

    /// Sets the key derivation function for the password. Default is [scrypt-aes256].
    #[clap(short='K', long="password-kdf", global=true, required=false, value_enum, default_value="argon2id-aes256", requires="encrypt")]
    password_kdf: PasswordKdfValues,

    //TODO: Depends on "encrypt"...this has to be configured through clap.
    /// Sets the encryption algorithm. Default is [chacha20poly1305].
    #[clap(short='E', long="encryption-algorithm", global=true, required=false, value_enum, default_value="aes256gcm", requires="encrypt")]
    encryption_algorithm: EncryptionAlgorithmValues,

    /// This option adds an additional hash algorithm to calculate. You can use this option multiple times. If no algorithm is selected, zffacquire automatically calculates [blake3] hash values.
    #[clap(short='d', long="hash-algorithm", global=true, required=false, value_enum, default_value="blake3")]
    hash_algorithm: Vec<HashAlgorithmValues>,

    /// Sign hash values of data with an autogenerated or given secret EdDSA key.
    #[clap(short='S', long="sign-data", global=true)]
    sign_data: bool,

    //TODO: requires sign_data?
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

    /// Sets the log level. Default is info. Log messages will be written to stderr.
    #[clap(short='L', long="log-level", value_enum, default_value="info", global=true, required=false)]
    log_level: LogLevel,

    /// Tries to uncompress the input file, if necessary. If e.g. the input is a compressed dd file (e.g. my_file.dd.gz)
    /// zffacquire will try do decompress the input data on-the-fly and read / write the uncompressed data in the 
    /// zff container. This option will check the magic bytes of the input file and supports 
    /// gz, bz2, lz4, zst and xz files.
    #[clap(short='U', long="uncompress-input", global=true, required=false)]
    uncompress_input: bool,

    /// Shows a progress bar.
    /// The progress bar will be written to stderr.
    #[clap(short='P', long="progress-bar", global=true, required=false, default_value="false")]
    progress_bar: bool,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Acquire a physical image
    #[clap(arg_required_else_help=true)]
    Physical {
        /// The input file. This should be your device to dump.
        /// You can use all devices which are available by using the "zffacquire list-devices" command.
        /// E.g. "/dev/sda" or "/dev/nvme0n1" in Linux systems.
        /// On windows systems, you have to use the device names which are listed by the "zffacquire list-devices" command,
        /// e.g. "disk0" for "\\.\PhysicalDrive0" or "volume1" for "\\.\HarddiskVolume1".
        #[clap(short='i', long="inputfile", required=true)]
        inputfile: PathBuf,

        /// The the name/path of the output-file (without file-extension). E.g. "/home/ph0llux/sda_dump".
        /// File extension will be added automatically.
        /// If not set, --segment-size will be ignored and the output will be streamed to stdout.
        #[clap(short='o', long="outputfile", global=true, required=false)]
        outputfile: Option<String>,
    },
    /// Acquire logical folder
    #[clap(arg_required_else_help=true)]
    Logical {
        /// The input folders. You can use this option multiple times.
        #[clap(short='i', long="inputfiles", required=true)]
        inputfiles: Vec<PathBuf>,

        /// The the name/path of the output-file (without file-extension). E.g. "/home/ph0llux/sda_dump".
        /// File extension will be added automatically.
        /// If not set, --segment-size will be ignored and the output will be streamed to stdout.
        #[clap(short='o', long="outputfile", global=true, required=false)]
        outputfile: Option<String>,
    },

    #[cfg(target_os = "linux")]
    /// Acquire the physical memory (root some specific capabilities are necessary).
    Memory {
        /// The the name/path of the output-file (without file-extension). E.g. "/home/ph0llux/sda_dump". 
        /// File extension will be added automatically. 
        /// If not set, --segment-size will be ignored and the output will be streamed to stdout.
        #[clap(short='o', long="outputfile", global=true, required=false)]
        outputfile: Option<String>,
    },

    /// Extend an existing zff file
    /// TODO: Extend Convert from other zff files.
    #[clap(arg_required_else_help=true)]
    Extend {
        /// Your zXX files, which should be extended.
        #[clap(short='a', long="append", global=true, value_delimiter = ' ', num_args = 1..)]
        append_files: Vec<PathBuf>,

        #[clap(subcommand)]
        extend_command: ExtendSubcommands,
    },

    /// Converts the given file to a zff container.
    /// The original file will *not* be deleted, but the appropriate content will be stored in a zff container.
    /// Currently supported file formats which can be converted: 
    /// .tar, .tar.gz, tar.bz2, .tar.xz, .tar.zst, .tar.lz4,
    #[clap(arg_required_else_help=true)]
    Convert {
        #[clap(subcommand)]
        convert_command: ConvertSubcommands,
    },

    #[cfg(target_family = "windows")]
    /// List all available physical devices,
    /// which can be used as input for the physical subcommand.
    #[clap()]
    ListDevices { },
}

#[derive(Subcommand)]
enum ConvertSubcommands {
    /// Currently supported file formats which can be converted: 
    /// .tar, .tar.gz, tar.bz2, .tar.xz, .tar.zst, .tar.lz4.
    #[clap(arg_required_else_help=true)]
    Tar {
        /// The input file. This field is REQUIRED.
        #[clap(short='i', long="inputfile", required=true)]
        inputfile: PathBuf,

        /// The the name/path of the output-file (without file-extension). E.g. "/home/ph0llux/sda_dump".
        /// File extension will be added automatically. This field is REQUIRED.
        #[clap(short='o', long="outputfile", global=true, required=false)]
        outputfile: String,
    },
    #[clap(arg_required_else_help=true)]
    Ewf {
        /// The segments of the appropriate EWF/E01 container. You have to provide all necessary segments.
        #[clap(short='i', long="input-segment-files", required=true)]
        input_segments: Vec<PathBuf>,

        /// The the name/path of the output-file (without file-extension). E.g. "/home/ph0llux/e01_converted_image".
        /// File extension will be added automatically. This field is REQUIRED.
        /// If not set, --segment-size will be ignored and the output will be streamed to stdout.
        #[clap(short='o', long="outputfile", global=true, required=false)]
        outputfile: Option<String>,
    },
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
    #[cfg(target_os = "linux")]
    /// Acquire the physical memory (root some specific capabilities are necessary).
    #[clap(arg_required_else_help=true)]
    Memory { }
}

#[derive(ValueEnum, Clone, PartialEq)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
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


#[derive(Debug, Clone, PartialEq, Eq)]
enum ProgressBarValue {
    TotalSize(u64),
    NumberOfFiles(u64),
}

fn main() {
    let args = Cli::parse();

    // setup the progress bar (only neccessary for the progress bar option is set)
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

    LogWrapper::new(multi.clone(), logger)
        .try_init()
        .unwrap();

    debug!("Started zffacquire");
    let pid = std::process::id();
    info!("Using PID: {pid}");

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
    debug!("Following hash algorithms will be used: {:?}", hash_types);

    let chunk_size = chunk_size(&args);

    let password = ask_password(&args);

    let encryption_header = match password {
        Some(ref password) => header_creation::encryption_header(&args, password),
        None => None
    };

    let mut optional_parameter = setup_optional_parameter(&args);

    let mut obj_header = header_creation::create_object_header(&args, encryption_header);

    let mut logical_objects: HashMap<ObjectHeader, Box<dyn LogicalObjectSource>> = HashMap::new();
    let mut physical_objects = HashMap::new();
    let mut virtual_objects = HashMap::new();

    let mut progressbar_value;

    let zff_files_output = match &args.command {
        #[cfg(target_family = "windows")]
        Commands::ListDevices {  } => {
            unreachable!()
        },
        Commands::Physical { inputfile, outputfile } => {
            setup_deduplication_map(&args, &mut optional_parameter, None);
            let inputfile_size = match get_size_of_inputfile(inputfile.clone()) {
                Ok(size) => size,
                Err(e) => {
                    let inputfile = inputfile.to_string_lossy();
                    error!("Following error occurred while trying to get the size of {inputfile}:\n{e}");
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

            physical_objects.insert(obj_header, file);

            if let Some(outputfile) = outputfile {
                let mut outputfile = PathBuf::from(outputfile);
                outputfile.set_extension(FIRST_FILE_EXTENSION);
                ZffFilesOutput::NewContainer(outputfile)
            } else {
                optional_parameter.target_segment_size = None;
                ZffFilesOutput::Stream
            }

        },
        Commands::Logical { inputfiles, outputfile } => {
            setup_deduplication_map(&args, &mut optional_parameter, None);
            let inputfiles: Vec<PathBuf> = inputfiles.iter().map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX ,x)).collect();
            obj_header.object_type = ObjectType::Logical;
            
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
        },
        #[cfg(target_os = "linux")]
        Commands::Memory { outputfile } => {
            // Bump the memlock rlimit. This is needed for older kernels that don't use the
            // new memcg based accounting, see https://lwn.net/Articles/837122/
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
        },
        Commands::Extend { extend_command, append_files } => {
            setup_deduplication_map(&args, &mut optional_parameter, Some(append_files.to_vec()));
            match extend_command {
                //setup logical objects.
                ExtendSubcommands::Logical { inputfiles } => {
                    let inputfiles: Vec<PathBuf> = inputfiles.iter().map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX ,x)).collect();
                    obj_header.object_type = ObjectType::Logical;
                    progressbar_value = ProgressBarValue::NumberOfFiles(inputfiles.len() as u64);
                    let logical_object_source = match LogicalObjectSourceFilesystem::try_from(inputfiles) {
                        Ok(source) => source,
                        Err(e) => {
                            error!("Failed to initialize logical object for filesystem data: {e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    logical_objects.insert(obj_header, Box::new(logical_object_source));
                },
                //setup physical objects.
                ExtendSubcommands::Physical { inputfile } => {
                    let inputfile_size = match get_size_of_inputfile(inputfile.clone()) {
                        Ok(size) => size,
                        Err(e) => {
                            let inputfile = inputfile.to_string_lossy();
                            error!("Following error occurred while trying to get the size of {inputfile}:\n{e}");
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
                    physical_objects.insert(obj_header, file);
                },
                #[cfg(target_os = "linux")]
                ExtendSubcommands::Memory {  } => {
                    // Bump the memlock rlimit. This is needed for older kernels that don't use the
                    // new memcg based accounting, see https://lwn.net/Articles/837122/
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
                },
            };

            ZffFilesOutput::ExtendContainer(append_files.to_vec())
        },
        Commands::Convert { convert_command } => {
            let mut optional_parameter = setup_optional_parameter(&args);
            setup_deduplication_map(&args, &mut optional_parameter, None);
            match convert_command {
                ConvertSubcommands::Ewf { input_segments, outputfile } => {
                    obj_header.description_header.custom_identifier_value("zffacquire::ewf_image", 
                    format!("{:?}", input_segments.iter().map(|path| path.file_name().unwrap().to_string_lossy())));
                    //input_segments.sort(); //TODO: Sort. Order is necessary.
                    let ewf_reader = match EwfReader::open_segments(input_segments) {
                        Ok(reader) => reader,
                        Err(e) => {
                            error!("An error occured while trying to open ewf segment(s): {e}");
                            exit(EXIT_STATUS_ERROR)
                        }
                    };
                    progressbar_value = ProgressBarValue::TotalSize(1); //TODO

                    physical_objects.insert(obj_header, Box::new(ewf_reader));

                    if let Some(outputfile) = outputfile {
                        let mut outputfile = PathBuf::from(outputfile);
                        outputfile.set_extension(FIRST_FILE_EXTENSION);
                        ZffFilesOutput::NewContainer(outputfile)
                    } else {
                        optional_parameter.target_segment_size = None;
                        ZffFilesOutput::Stream
                    }
                },
                ConvertSubcommands::Tar { inputfile, outputfile } => {
                    obj_header.description_header.custom_identifier_value("zffacquire::tar_archive::virtual_mapped_object", 
                    inputfile.file_name().unwrap().to_string_lossy());
                    // the original file will be stored as a physical object and 
                    // a virtual object will map the appropriate
                    let fd = match File::open(inputfile) {
                        Ok(fd) => fd,
                        Err(e) => {
                            error!("Unable to open inputfile {}: {e}", inputfile.to_string_lossy());
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
                    //TODO: Check if this is a valid tar archive.
                    progressbar_value = ProgressBarValue::NumberOfFiles(1);//TODO!

                    let mut outputfile = PathBuf::from(outputfile);
                    outputfile.set_extension(FIRST_FILE_EXTENSION);

                    info!("Reading tar source file. This could take a few minutes ...");
                    let mut converter_objects = HashMap::new();
                    converter_objects.insert(obj_header, inputfile);

                    let zff_files_output = ZffFilesOutput::NewContainer(outputfile);

                    let mut zs = match ZffWriter::new(
                        converter_objects,
                        HashMap::new(),
                        HashMap::new(),
                        hash_types.clone(),
                        optional_parameter,
                        zff_files_output,
                        ) {
                        Ok(zw) => zw,
                        Err(e) => {
                            error!("An error occured while trying to create the ZffWriter object:\n{e}");
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

                    let reader_vec = open_files(&segment_filepaths);

                    let mut zffreader = match ZffReader::with_reader(reader_vec) {
                        Ok(reader) => reader,
                        Err(e) => {
                            error!("An error occurred while trying to create the ZffReader: {e}");
                            exit(EXIT_STATUS_ERROR);
                        }
                    };
                    match zffreader.initialize_object(INITIAL_OBJECT_NUMBER) {
                        Ok(_) => debug!("Successfully initialized passive object {INITIAL_OBJECT_NUMBER}"),
                        Err(e) => {
                            error!("Could not inititalize object {INITIAL_OBJECT_NUMBER} due following error: {e}");
                            exit(EXIT_STATUS_ERROR);
                        },
                    }
                    if let Some(ref password) = password {
                        match zffreader.decrypt_object(INITIAL_OBJECT_NUMBER, password) {
                            Ok(o_type) => debug!("Passive object {INITIAL_OBJECT_NUMBER} ({o_type} object) decrypted successfully"),
                            Err(e) => {
                                error!("Could not decrypt passive object {INITIAL_OBJECT_NUMBER}: {e}");
                                exit(EXIT_STATUS_ERROR)
                            },
                        }
                    }

                    let virtual_encryption_header = match password {
                        Some(ref password) => header_creation::encryption_header(&args, password),
                        None => None
                    };


                    let vos_tar = match VirtualObjectSourceLogicalTar::new(zffreader, INITIAL_OBJECT_NUMBER, None, hash_types.clone()) {
                        Ok(vos_tar) => header_creation::create_vos(vos_tar),
                        Err(e) => {
                            error!("An error occured while trying to create the virtual object writer: {e}");
                            exit(EXIT_STATUS_ERROR)
                        }
                    };
                    let mut obj_header = create_object_header(&args, virtual_encryption_header);
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
        zff_files_output.clone()) {
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
            },
            ProgressBarValue::NumberOfFiles(_) => {
                let number_of_files_readable = zs.files_left_total();
                progressbar_value = ProgressBarValue::NumberOfFiles(number_of_files_readable);
                info!("Number of files to dump: {}", number_of_files_readable);
                let pb = multi.add(ProgressBar::new(number_of_files_readable));
                pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.green/blue}] [{pos}/{len} Files] [{percent}%] ({eta})")
                .unwrap()
                .progress_chars("=>-"));
                pb
            },
        };
        Some(pb)
    } else {
        None
    };
    // reads the next data with zs.read() (ZffWriter implements the Read trait) and writes the data to a buffer.
    // The buffer will be written to the output file.
    let mut buffer = vec![0u8; chunk_size as usize];
    let mut output_writer = setup_output_writer(&zff_files_output);
    
    // only used if output file is given ;)
    let mut outputfile_path = zs.output_path().unwrap_or_default();
    let mut current_extension = zs
    .output_path()
    .unwrap_or_default()
    .extension()
    .unwrap_or_default()
    .to_str()
    .unwrap_or_default()
    .to_string();

    loop {
        // Set the position of the progress bar, depending on the appropriate type
        if let Some(ref pb) = pb {
            match progressbar_value {
                ProgressBarValue::TotalSize(_) => pb.set_position(zs.current_chunk_number()*chunk_size),
                ProgressBarValue::NumberOfFiles(total_files) => pb.set_position(total_files-zs.files_left_total()),
            }
        }

        match zs.read(&mut buffer) {
            Ok(0) => {
                match zs.next_segment() {
                    SegmentationState::SegmentFinished => {
                        current_extension = match file_extension_next_value(current_extension) {
                            Ok(val) => val,
                            Err(e) => {
                                error!("An error occured while trying to set next segment file extension:\n{e}");
                                exit(EXIT_STATUS_ERROR);
                            },
                        }; 
                        outputfile_path.set_extension(&current_extension);
                        output_writer = setup_output_writer_from_path(&outputfile_path);
                    },
                    SegmentationState::LastSegmentFinished => break,
                    SegmentationState::SegmentNotFinished => ()
                }
            },
            Ok(n) => {
                match output_writer.write_all(&buffer[..n]) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("An error occured while trying to write to the output file:\n{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                }
            },
            Err(e) => {
                error!("An error occured while trying to read from the input file:\n{e}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    }
    match progressbar_value {
        ProgressBarValue::TotalSize(total_size) => info!("{} dumped. Finishing container...", (total_size.bytes_as_hrb())),
        ProgressBarValue::NumberOfFiles(total_files) => info!("{} files dumped. Finishing container...", total_files-zs.files_left_total()),
    }
    if let Some(pb) = pb {
        pb.finish();
    }

    info!("Zff file(s) successfully created");
    exit(EXIT_STATUS_SUCCESS);
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

fn setup_optional_parameter<R: ReadAt>(args: &Cli) -> ZffCreationParameters<R> {
    let mut rng = rand::rng();

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

    let unique_identifier = rng.random();

    ZffCreationParameters {
        signature_key: sign_keypair,
        target_segment_size,
        chunkmap_size,
        deduplication_metadata: None,
        unique_identifier,
        description_notes: description_notes.clone(),
    }
}

fn setup_deduplication_map(
    args: &Cli,
    optional_parameter: &mut ZffCreationParameters<File>,
    segment_file_paths: Option<Vec<PathBuf>>) {
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
                    error!("An error occured while trying to append an entry to the deduplication map: {e}");
                    exit(1);
                    }
                }
            },
            Err(e) => {
                error!("An error occured while trying to append an entry to the deduplication map: {e}");
                exit(1);
            },
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
    if let Err(e) = zs.initialize_objects_all() { //TODO: initialize only the unencrypted objects
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

fn object_is_passive(args: &Cli) -> bool {
    matches!(args.command, Commands::Convert { convert_command: ConvertSubcommands::Tar { inputfile: _, outputfile: _ } })
}