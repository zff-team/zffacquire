use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use rand::RngExt;

use zffacquire_common::{
    AcquireConfig, INITIAL_OBJECT_NUMBER, FIRST_FILE_EXTENSION,
    ObjectHeader, ObjectType, EncryptionHeader,
    LogicalObjectSource, LogicalObjectSourceFilesystem,
    ZffCreationParameters,
    ZffWriter, ZffFilesOutput, SegmentationState,
    file_extension_next_value,
    compression_header, encryption_header, object_description_header,
    populate_physical_device_info, populate_logical_source_info,
    setup_object_flags,
    create_signing_key, parse_chunk_size,
    get_size_of_inputfile,
    hrs_parser, HumanReadable,
};

use crate::app::{AcquireCommand, DeduplicationMode};

#[derive(Debug, Clone)]
pub enum AcquireMessage {
    Progress(u64, u64),
    Log(String),
    Status(String),
    Finished(Result<(), String>),
}

pub struct AcquireParams {
    pub command: AcquireCommand,
    pub config: AcquireConfig,
    pub password: Option<String>,
    pub input_files: Vec<PathBuf>,
    pub output_file: PathBuf,
    pub chunk_size_str: String,
    pub chunkmap_size_str: String,
    pub segment_size_str: Option<String>,
    #[allow(dead_code)]
    pub deduplication: DeduplicationMode,
}

pub fn start_acquisition(
    params: AcquireParams,
    sender: tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel_token: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        cancel_token.store(false, Ordering::Relaxed);
        match run_acquisition(params, &sender, &cancel_token) {
            Ok(()) => {
                let _ = sender.send(AcquireMessage::Finished(Ok(())));
            }
            Err(e) => {
                let _ = sender.send(AcquireMessage::Log(format!("FATAL: {e}")));
                let _ = sender.send(AcquireMessage::Finished(Err(e)));
            }
        }
    });
}

fn run_acquisition(
    params: AcquireParams,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let _ = sender.send(AcquireMessage::Status("Initializing...".to_string()));
    let _ = sender.send(AcquireMessage::Log("Starting acquisition".to_string()));

    let hash_types = params.config.hash_algorithms.clone();
    let chunk_size_val = parse_chunk_size(&params.chunk_size_str)?;

    let encryption_hdr = if params.config.encrypt {
        let pw = params.password.as_deref()
            .ok_or("Encryption enabled but no password provided")?;
        Some(encryption_header(
            params.config.kdf_scheme.clone(),
            params.config.pbe_scheme.clone(),
            params.config.encryption_algorithm.clone(),
            pw,
        )?)
    } else {
        None
    };

    let sign_keypair = create_signing_key(&params.config)?;

    let target_segment_size = if let Some(ref ss) = params.segment_size_str {
        Some(hrs_parser(ss).ok_or_else(|| format!("Invalid segment size: {ss}"))?)
    } else {
        None
    };

    let chunkmap_size = Some(
        hrs_parser(&params.chunkmap_size_str)
            .ok_or_else(|| format!("Invalid chunkmap size: {}", params.chunkmap_size_str))?,
    );

    let mut rng = rand::rng();
    let unique_identifier: u64 = rng.random();

    let optional_parameter = ZffCreationParameters {
        signature_key: sign_keypair,
        target_segment_size,
        chunkmap_size,
        deduplication_metadata: None,
        unique_identifier,
        description_notes: params.config.description_notes.clone(),
    };

    let _ = sender.send(AcquireMessage::Status("Acquiring data...".to_string()));

    match params.command {
        AcquireCommand::Physical => {
            acquire_physical(
                &params.config,
                &params.input_files,
                &params.output_file,
                encryption_hdr,
                optional_parameter,
                hash_types,
                chunk_size_val,
                sender,
                cancel,
            )
        }
        AcquireCommand::Logical => {
            acquire_logical(
                &params.config,
                &params.input_files,
                &params.output_file,
                encryption_hdr,
                optional_parameter,
                hash_types,
                chunk_size_val,
                sender,
                cancel,
            )
        }
        _ => {
            Err(format!("Command {:?} is not yet supported in the GUI", params.command))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn acquire_physical(
    config: &AcquireConfig,
    input_files: &[PathBuf],
    output_file: &Path,
    encryption_hdr: Option<EncryptionHeader>,
    optional_parameter: ZffCreationParameters<File>,
    hash_types: Vec<zffacquire_common::HashType>,
    chunk_size: u64,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let input_path = input_files.first()
        .ok_or("No input file specified for physical acquisition")?;

    let _ = sender.send(AcquireMessage::Log(
        format!("Input: {}", input_path.display())
    ));

    let total_size = get_size_of_inputfile(input_path.clone())
        .map_err(|e| format!("Failed to get input size: {e}"))?;
    let _ = sender.send(AcquireMessage::Log(
        format!("Total size: {}", total_size.bytes_as_hrb())
    ));
    let _ = sender.send(AcquireMessage::Status(
        format!("Acquiring {} ...", total_size.bytes_as_hrb())
    ));

    let flags = setup_object_flags(config, false);
    let mut obj_header = ObjectHeader::new(
        INITIAL_OBJECT_NUMBER,
        encryption_hdr,
        chunk_size,
        compression_header(config)?,
        object_description_header(config),
        ObjectType::Physical,
        flags,
    );
    populate_physical_device_info(&mut obj_header.description_header, input_path);

    let file = File::open(input_path)
        .map_err(|e| format!("Failed to open input: {e}"))?;

    let mut physical_objects: HashMap<ObjectHeader, File> = HashMap::new();
    physical_objects.insert(obj_header, file);

    let output_path = build_output_path(output_file);
    let _ = sender.send(AcquireMessage::Log(
        format!("Output: {}", output_path.display())
    ));

    let mut zs = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        hash_types,
        optional_parameter,
        ZffFilesOutput::NewContainer(output_path.clone()),
    ).map_err(|e| format!("Failed to create ZffWriter: {e}"))?;

    let mut output_writer = setup_writer(&output_path)?;
    let mut buffer = vec![0u8; chunk_size as usize];
    let mut current_extension = output_path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("z01")
        .to_string();
    let mut output_path_buf = output_path.clone();

    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = sender.send(AcquireMessage::Status("Cancelled".to_string()));
            let _ = sender.send(AcquireMessage::Log("Acquisition cancelled by user".to_string()));
            return Ok(());
        }

        match zs.read(&mut buffer) {
            Ok(0) => {
                match zs.next_segment() {
                    SegmentationState::SegmentFinished => {
                        current_extension = file_extension_next_value(&current_extension)
                            .map_err(|e| format!("Extension error: {e}"))?;
                        output_path_buf.set_extension(&current_extension);
                        output_writer = setup_writer(&output_path_buf)?;
                        let _ = sender.send(AcquireMessage::Log(
                            format!("New segment: {}", output_path_buf.display())
                        ));
                    }
                    SegmentationState::LastSegmentFinished => break,
                    SegmentationState::SegmentNotFinished => {}
                }
            }
            Ok(n) => {
                if let Err(e) = output_writer.write_all(&buffer[..n]) {
                    let _ = sender.send(AcquireMessage::Log(format!("Write error: {e}")));
                    return Err(format!("Write error: {e}"));
                }
                let _ = sender.send(AcquireMessage::Progress(
                    zs.current_chunk_number() * chunk_size,
                    total_size,
                ));
            }
            Err(e) => {
                let _ = sender.send(AcquireMessage::Log(format!("Read error: {e}")));
                return Err(format!("Read error: {e}"));
            }
        }
    }

    let _ = sender.send(AcquireMessage::Progress(total_size, total_size));
    let _ = sender.send(AcquireMessage::Log(
        format!("{} dumped. Finishing container...", total_size.bytes_as_hrb())
    ));
    let _ = sender.send(AcquireMessage::Status("Finishing...".to_string()));
    let _ = sender.send(AcquireMessage::Log("Zff file(s) successfully created".to_string()));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn acquire_logical(
    config: &AcquireConfig,
    input_files: &[PathBuf],
    output_file: &Path,
    encryption_hdr: Option<EncryptionHeader>,
    optional_parameter: ZffCreationParameters<File>,
    hash_types: Vec<zffacquire_common::HashType>,
    chunk_size: u64,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<(), String> {
    if input_files.is_empty() {
        return Err("No input files specified for logical acquisition".to_string());
    }

    let _ = sender.send(AcquireMessage::Log(
        format!("Input: {} file(s)/folder(s)", input_files.len())
    ));

    let flags = setup_object_flags(config, false);
    let mut obj_header = ObjectHeader::new(
        INITIAL_OBJECT_NUMBER,
        encryption_hdr,
        chunk_size,
        compression_header(config)?,
        object_description_header(config),
        ObjectType::Logical,
        flags,
    );
    populate_logical_source_info(&mut obj_header.description_header, input_files);

    let logical_source = LogicalObjectSourceFilesystem::new(input_files.to_vec())
        .map_err(|e| format!("Failed to create logical source: {e}"))?;

    let mut logical_objects: HashMap<ObjectHeader, Box<dyn LogicalObjectSource>> = HashMap::new();
    logical_objects.insert(obj_header, Box::new(logical_source));

    let output_path = build_output_path(output_file);
    let _ = sender.send(AcquireMessage::Log(
        format!("Output: {}", output_path.display())
    ));

    let total_files = input_files.len() as u64;
    let _ = sender.send(AcquireMessage::Status(
        format!("Acquiring {total_files} file(s)...")
    ));

    let physical_objects: HashMap<ObjectHeader, std::fs::File> = HashMap::new();
    let mut zs = ZffWriter::new(
        physical_objects,
        logical_objects,
        HashMap::new(),
        hash_types,
        optional_parameter,
        ZffFilesOutput::NewContainer(output_path.clone()),
    ).map_err(|e| format!("Failed to create ZffWriter: {e}"))?;

    let mut output_writer = setup_writer(&output_path)?;
    let mut buffer = vec![0u8; chunk_size as usize];
    let mut current_extension = output_path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("z01")
        .to_string();
    let mut output_path_buf = output_path.clone();

    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = sender.send(AcquireMessage::Status("Cancelled".to_string()));
            let _ = sender.send(AcquireMessage::Log("Acquisition cancelled by user".to_string()));
            return Ok(());
        }

        match zs.read(&mut buffer) {
            Ok(0) => {
                match zs.next_segment() {
                    SegmentationState::SegmentFinished => {
                        current_extension = file_extension_next_value(&current_extension)
                            .map_err(|e| format!("Extension error: {e}"))?;
                        output_path_buf.set_extension(&current_extension);
                        output_writer = setup_writer(&output_path_buf)?;
                        let _ = sender.send(AcquireMessage::Log(
                            format!("New segment: {}", output_path_buf.display())
                        ));
                    }
                    SegmentationState::LastSegmentFinished => break,
                    SegmentationState::SegmentNotFinished => {}
                }
            }
            Ok(n) => {
                if let Err(e) = output_writer.write_all(&buffer[..n]) {
                    let _ = sender.send(AcquireMessage::Log(format!("Write error: {e}")));
                    return Err(format!("Write error: {e}"));
                }
                let files_done = total_files.saturating_sub(zs.files_left_total());
                let _ = sender.send(AcquireMessage::Progress(files_done, total_files));
            }
            Err(e) => {
                let _ = sender.send(AcquireMessage::Log(format!("Read error: {e}")));
                return Err(format!("Read error: {e}"));
            }
        }
    }

    let _ = sender.send(AcquireMessage::Progress(total_files, total_files));
    let _ = sender.send(AcquireMessage::Log(
        format!("{total_files} file(s) dumped. Finishing container...")
    ));
    let _ = sender.send(AcquireMessage::Status("Finishing...".to_string()));
    let _ = sender.send(AcquireMessage::Log("Zff file(s) successfully created".to_string()));
    Ok(())
}

fn build_output_path(output_file: &Path) -> PathBuf {
    let mut path = output_file.to_path_buf();
    path.set_extension(FIRST_FILE_EXTENSION);
    path
}

fn setup_writer(path: &std::path::Path) -> Result<Box<dyn Write>, String> {
    File::create(path)
        .map(|f| Box::new(f) as Box<dyn Write>)
        .map_err(|e| format!("Failed to create output file {}: {e}", path.display()))
}
