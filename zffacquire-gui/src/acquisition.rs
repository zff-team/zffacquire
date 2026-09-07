use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use rand::RngExt;

use zff::{
    VirtualObjectSourceLogicalTar,
    header::{DeduplicationChunkMap, DeduplicationMetadata},
    io::zffreader::ZffReader,
};
use zffacquire_common::{
    AcquireConfig, EncryptionHeader, FIRST_FILE_EXTENSION, HumanReadable, INITIAL_OBJECT_NUMBER,
    LogicalObjectSource, LogicalObjectSourceFilesystem, ObjectHeader, ObjectType, ReadAt,
    SegmentationState, SigningKey, ZffCreationParameters, ZffFilesOutput, ZffWriter,
    compression_header, create_object_header, create_signing_key, create_vos, encryption_header,
    file_extension_next_value, get_physical_input_file, get_size_of_inputfile, hrs_parser,
    object_description_header, open_files, parse_chunk_size, populate_logical_source_info,
    populate_physical_device_info, setup_object_flags,
};

use crate::app::{AcquireCommand, ConvertFormat, DeduplicationMode};

#[derive(Debug, Clone)]
pub enum AcquireMessage {
    Progress(u64, u64),
    Log(String),
    Status(String),
    Finished(Result<AcquireOutcome, String>),
}

/// How an acquisition ended.
///
/// A cancelled run is not a successful one: the container was never finalised,
/// so it has no main footer and no reader can open it. Reporting it as success
/// would be the worst possible outcome for an evidence container, so it is kept
/// distinct from `Completed` all the way to the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireOutcome {
    Completed,
    Cancelled,
}

pub struct AcquireParams {
    pub command: AcquireCommand,
    pub append_command: AcquireCommand,
    pub segments: Vec<PathBuf>,
    pub convert_format: ConvertFormat,
    pub config: AcquireConfig,
    pub password: Option<String>,
    pub input_files: Vec<PathBuf>,
    pub output_file: PathBuf,
    pub chunk_size_str: String,
    pub chunkmap_size_str: String,
    pub segment_size_str: Option<String>,
    pub deduplication: DeduplicationMode,
}

pub fn start_acquisition(
    params: AcquireParams,
    sender: tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel_token: Arc<AtomicBool>,
) {
    thread::spawn(
        move || match run_acquisition(params, &sender, &cancel_token) {
            Ok(outcome) => {
                let _ = sender.send(AcquireMessage::Finished(Ok(outcome)));
            }
            Err(e) => {
                let _ = sender.send(AcquireMessage::Log(format!("FATAL: {e}")));
                let _ = sender.send(AcquireMessage::Finished(Err(e)));
            }
        },
    );
}

/// Everything needed to build a [`ZffCreationParameters`], as often as needed.
///
/// The TAR conversion writes two containers, and both must be given the same
/// signature key: deriving them separately would sign the two halves of one
/// container with two different keys.
struct CreationParameters {
    signature_key: Option<SigningKey>,
    target_segment_size: Option<u64>,
    chunkmap_size: Option<u64>,
    unique_identifier: u64,
    description_notes: Option<String>,
    deduplication: DeduplicationMode,
    segments: Vec<PathBuf>,
    reuse_existing_chunks: bool,
}

impl CreationParameters {
    fn output(&self, path: &Path) -> ZffFilesOutput {
        if self.segments.is_empty() {
            ZffFilesOutput::NewContainer(build_output_path(path))
        } else {
            ZffFilesOutput::ExtendContainer(self.segments.clone())
        }
    }

    fn build(&self) -> Result<ZffCreationParameters<File>, String> {
        Ok(ZffCreationParameters {
            signature_key: self.signature_key.clone(),
            target_segment_size: self.target_segment_size,
            chunkmap_size: self.chunkmap_size,
            deduplication_metadata: self.build_deduplication_metadata()?,
            unique_identifier: self.unique_identifier,
            description_notes: self.description_notes.clone(),
        })
    }

    fn build_deduplication_metadata(&self) -> Result<Option<DeduplicationMetadata<File>>, String> {
        let mut deduplication_map = match &self.deduplication {
            DeduplicationMode::None => return Ok(None),
            DeduplicationMode::InMemory => DeduplicationChunkMap::new_in_memory_map(),
            DeduplicationMode::OnDisk(path) => {
                DeduplicationChunkMap::new_from_path(path).map_err(|e| {
                    format!(
                        "Cannot create the deduplication chunkmap at {}: {e}",
                        path.display()
                    )
                })?
            }
        };
        // The reader decrypts duplicate chunks with the new object's key. Reusing
        // plaintext or differently encrypted chunks would make it unreadable.
        let original_zffreader = if self.segments.is_empty() || !self.reuse_existing_chunks {
            None
        } else {
            let mut reader = ZffReader::with_reader(open_files(self.segments.clone())?)
                .map_err(|e| e.to_string())?;
            reader.initialize_objects_all().map_err(|e| e.to_string())?;
            for (chunk, hash) in reader
                .get_xxhashmaps_unencrypted()
                .map_err(|e| e.to_string())?
            {
                deduplication_map
                    .append_entry(hash, chunk)
                    .map_err(|e| e.to_string())?;
            }
            Some(reader)
        };
        Ok(Some(DeduplicationMetadata {
            deduplication_map,
            original_zffreader,
        }))
    }
}

fn run_acquisition(
    params: AcquireParams,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<AcquireOutcome, String> {
    let _ = sender.send(AcquireMessage::Status("Initializing...".to_string()));
    let _ = sender.send(AcquireMessage::Log("Starting acquisition".to_string()));

    let hash_types = params.config.hash_algorithms.clone();
    let chunk_size_val = parse_chunk_size(&params.chunk_size_str)?;

    let encryption_hdr = if params.config.encrypt {
        let pw = params
            .password
            .as_deref()
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
    let creation_parameters = CreationParameters {
        signature_key: create_signing_key(&params.config)?,
        target_segment_size,
        chunkmap_size,
        unique_identifier: rng.random(),
        description_notes: params.config.description_notes.clone(),
        deduplication: params.deduplication.clone(),
        reuse_existing_chunks: !params.config.encrypt,
        segments: if params.command == AcquireCommand::Extend {
            if params.segments.is_empty() {
                return Err("Select all existing container segments".into());
            }
            params.segments.clone()
        } else {
            Vec::new()
        },
    };

    let _ = sender.send(AcquireMessage::Status("Acquiring data...".to_string()));

    let command = if params.command == AcquireCommand::Extend {
        &params.append_command
    } else {
        &params.command
    };
    match command {
        AcquireCommand::Physical => acquire_physical(
            &params.config,
            &params.input_files,
            &params.output_file,
            encryption_hdr,
            &creation_parameters,
            hash_types,
            chunk_size_val,
            sender,
            cancel,
        ),
        AcquireCommand::Logical => acquire_logical(
            &params.config,
            &params.input_files,
            &params.output_file,
            encryption_hdr,
            &creation_parameters,
            hash_types,
            chunk_size_val,
            sender,
            cancel,
        ),
        AcquireCommand::Memory => acquire_memory(
            &params.config,
            &params.output_file,
            encryption_hdr,
            &creation_parameters,
            hash_types,
            chunk_size_val,
            sender,
            cancel,
        ),
        AcquireCommand::Extend => {
            Err("Select physical, logical or memory evidence to append".into())
        }
        AcquireCommand::Convert => match params.convert_format {
            ConvertFormat::Tar => acquire_convert_tar(
                &params.config,
                params.password.as_deref(),
                &params.input_files,
                &params.output_file,
                encryption_hdr,
                &creation_parameters,
                hash_types,
                chunk_size_val,
                sender,
                cancel,
            ),
            ConvertFormat::Ewf => acquire_convert_ewf(
                &params.config,
                &params.input_files,
                &params.output_file,
                encryption_hdr,
                &creation_parameters,
                hash_types,
                chunk_size_val,
                sender,
                cancel,
            ),
        },
    }
}

/// What the progress bar counts for a given acquisition.
enum ProgressBasis {
    Bytes(u64),
    Files(u64),
}

/// Opens the writer for the output the [`ZffWriter`] is currently writing to.
///
/// `writer_output_path` is the segment zff reports as its own current output.
/// For an extended container that is the segment carrying the main footer, and
/// it must be appended to, never recreated: `File::create` on it would truncate
/// the container that is being extended.
fn setup_writer(
    output: &ZffFilesOutput,
    writer_output_path: Option<&Path>,
) -> Result<Box<dyn Write>, String> {
    match output {
        ZffFilesOutput::NewContainer(path) => {
            create_output_file(writer_output_path.unwrap_or(path))
        }
        ZffFilesOutput::ExtendContainer(paths) => {
            let path = writer_output_path
                .or_else(|| paths.first().map(|p| p.as_path()))
                .ok_or("No output file to extend")?;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .read(true)
                .open(path)
                .map_err(|e| format!("Failed to open {} for appending: {e}", path.display()))?;
            file.seek(SeekFrom::End(0))
                .map_err(|e| format!("Failed to seek to the end of {}: {e}", path.display()))?;
            Ok(Box::new(file))
        }
        ZffFilesOutput::Stream => Err("The GUI does not write to a stream".to_string()),
    }
}

fn create_output_file(path: &Path) -> Result<Box<dyn Write>, String> {
    File::create(path)
        .map(|f| Box::new(f) as Box<dyn Write>)
        .map_err(|e| format!("Failed to create output file {}: {e}", path.display()))
}

/// Drives a [`ZffWriter`] to completion, following it across segment boundaries.
///
/// This is the one place the output loop lives, so the segment handling, the
/// cancellation semantics and the append-versus-create decision are the same
/// for every acquisition the GUI can run.
#[allow(clippy::too_many_arguments)]
fn drive_writer<R: Read, C: ReadAt>(
    zs: &mut ZffWriter<R, C>,
    output: &ZffFilesOutput,
    chunk_size: u64,
    basis: &ProgressBasis,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<AcquireOutcome, String> {
    let mut output_path_buf = zs.output_path().ok_or("The container has no output path")?;
    let mut output_writer = setup_writer(output, Some(&output_path_buf))?;
    let mut current_extension = output_path_buf
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or(FIRST_FILE_EXTENSION)
        .to_string();
    let initial_chunk = zs.current_chunk_number();
    let mut buffer = vec![0u8; chunk_size as usize];

    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = sender.send(AcquireMessage::Log(
                "Cancelled by user. The container was not finalised and cannot be read."
                    .to_string(),
            ));
            return Ok(AcquireOutcome::Cancelled);
        }

        match zs.read(&mut buffer) {
            Ok(0) => {
                match zs.next_segment() {
                    SegmentationState::SegmentFinished => {
                        current_extension = file_extension_next_value(&current_extension)
                            .map_err(|e| format!("Extension error: {e}"))?;
                        output_path_buf.set_extension(&current_extension);
                        // A new segment is always a new file, never an append.
                        output_writer = create_output_file(&output_path_buf)?;
                        let _ = sender.send(AcquireMessage::Log(format!(
                            "New segment: {}",
                            output_path_buf.display()
                        )));
                    }
                    SegmentationState::LastSegmentFinished => break,
                    SegmentationState::SegmentNotFinished => {}
                }
            }
            Ok(n) => {
                output_writer
                    .write_all(&buffer[..n])
                    .map_err(|e| format!("Write error: {e}"))?;
                match basis {
                    ProgressBasis::Bytes(total) => {
                        let _ = sender.send(AcquireMessage::Progress(
                            zs.current_chunk_number()
                                .saturating_sub(initial_chunk)
                                .saturating_mul(chunk_size)
                                .min(*total),
                            *total,
                        ));
                    }
                    ProgressBasis::Files(total) => {
                        let _ = sender.send(AcquireMessage::Progress(
                            total.saturating_sub(zs.files_left_total()),
                            *total,
                        ));
                    }
                }
            }
            Err(e) => return Err(format!("Read error: {e}")),
        }
    }

    output_writer
        .flush()
        .map_err(|e| format!("Failed to flush the output: {e}"))?;
    match basis {
        ProgressBasis::Bytes(total) => {
            let _ = sender.send(AcquireMessage::Progress(*total, *total));
        }
        ProgressBasis::Files(total) => {
            let _ = sender.send(AcquireMessage::Progress(*total, *total));
        }
    }
    Ok(AcquireOutcome::Completed)
}

#[allow(clippy::too_many_arguments)]
fn acquire_physical(
    config: &AcquireConfig,
    input_files: &[PathBuf],
    output_file: &Path,
    encryption_hdr: Option<EncryptionHeader>,
    creation_parameters: &CreationParameters,
    hash_types: Vec<zffacquire_common::HashType>,
    chunk_size: u64,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<AcquireOutcome, String> {
    let input_path = input_files
        .first()
        .ok_or("No input file specified for physical acquisition")?;

    let _ = sender.send(AcquireMessage::Log(format!(
        "Input: {}",
        input_path.display()
    )));

    let total_size = get_size_of_inputfile(input_path.clone())
        .map_err(|e| format!("Failed to get input size: {e}"))?;
    let _ = sender.send(AcquireMessage::Log(format!(
        "Total size: {}",
        total_size.bytes_as_hrb()
    )));
    let _ = sender.send(AcquireMessage::Status(format!(
        "Acquiring {} ...",
        total_size.bytes_as_hrb()
    )));

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

    // Goes through the same platform-specific device handling as the command
    // line tool, so a Windows physical drive and a compressed image behave the
    // same in both.
    let file = get_physical_input_file(input_path.clone(), config.uncompress_input)
        .map_err(|e| format!("Failed to open input: {e}"))?;

    let mut physical_objects: HashMap<ObjectHeader, Box<dyn Read>> = HashMap::new();
    physical_objects.insert(obj_header, file);

    let output_path = build_output_path(output_file);
    let _ = sender.send(AcquireMessage::Log(format!(
        "Output: {}",
        output_path.display()
    )));

    let output = creation_parameters.output(&output_path);
    let mut zs = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        hash_types,
        creation_parameters.build()?,
        output.clone(),
    )
    .map_err(|e| format!("Failed to create ZffWriter: {e}"))?;

    let outcome = drive_writer(
        &mut zs,
        &output,
        chunk_size,
        &ProgressBasis::Bytes(total_size),
        sender,
        cancel,
    )?;
    if outcome == AcquireOutcome::Completed {
        let _ = sender.send(AcquireMessage::Log(format!(
            "{} dumped. Finishing container...",
            total_size.bytes_as_hrb()
        )));
        let _ = sender.send(AcquireMessage::Status("Finishing...".to_string()));
        let _ = sender.send(AcquireMessage::Log(
            "Zff file(s) successfully created".to_string(),
        ));
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn acquire_logical(
    config: &AcquireConfig,
    input_files: &[PathBuf],
    output_file: &Path,
    encryption_hdr: Option<EncryptionHeader>,
    creation_parameters: &CreationParameters,
    hash_types: Vec<zffacquire_common::HashType>,
    chunk_size: u64,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<AcquireOutcome, String> {
    if input_files.is_empty() {
        return Err("No input files specified for logical acquisition".to_string());
    }

    let _ = sender.send(AcquireMessage::Log(format!(
        "Input: {} file(s)/folder(s)",
        input_files.len()
    )));

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
    let _ = sender.send(AcquireMessage::Log(format!(
        "Output: {}",
        output_path.display()
    )));

    let physical_objects: HashMap<ObjectHeader, File> = HashMap::new();
    let output = creation_parameters.output(&output_path);
    let mut zs = ZffWriter::new(
        physical_objects,
        logical_objects,
        HashMap::new(),
        hash_types,
        creation_parameters.build()?,
        output.clone(),
    )
    .map_err(|e| format!("Failed to create ZffWriter: {e}"))?;

    // Only known once the writer has walked the input tree.
    let total_files = zs.files_left_total();
    let _ = sender.send(AcquireMessage::Status(format!(
        "Acquiring {total_files} file(s)..."
    )));

    let outcome = drive_writer(
        &mut zs,
        &output,
        chunk_size,
        &ProgressBasis::Files(total_files),
        sender,
        cancel,
    )?;
    if outcome == AcquireOutcome::Completed {
        let _ = sender.send(AcquireMessage::Log(format!(
            "{total_files} file(s) dumped. Finishing container..."
        )));
        let _ = sender.send(AcquireMessage::Status("Finishing...".to_string()));
        let _ = sender.send(AcquireMessage::Log(
            "Zff file(s) successfully created".to_string(),
        ));
    }
    Ok(outcome)
}

fn build_output_path(output_file: &Path) -> PathBuf {
    let mut path = output_file.to_path_buf();
    path.set_extension(FIRST_FILE_EXTENSION);
    path
}

/// File names of the given paths, for the description header.
///
/// A path with no final component keeps its full display form rather than
/// panicking on an absent file name.
fn file_names(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| match path.file_name() {
            Some(name) => name.to_string_lossy().to_string(),
            None => path.display().to_string(),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn acquire_convert_ewf(
    config: &AcquireConfig,
    input_files: &[PathBuf],
    output_file: &Path,
    encryption_hdr: Option<EncryptionHeader>,
    creation_parameters: &CreationParameters,
    hash_types: Vec<zffacquire_common::HashType>,
    chunk_size: u64,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<AcquireOutcome, String> {
    let _ = sender.send(AcquireMessage::Status(
        "Converting EWF to ZFF...".to_string(),
    ));
    let _ = sender.send(AcquireMessage::Log(format!(
        "Input: {} EWF segment(s)",
        input_files.len()
    )));

    let mut ewf_reader = ewf::EwfReader::open_segments(input_files)
        .map_err(|e| format!("Failed to open EWF segment(s): {e}"))?;

    let total_size = ewf_reader
        .seek(SeekFrom::End(0))
        .and_then(|size| ewf_reader.rewind().map(|_| size))
        .map_err(|e| format!("Failed to determine the size of the EWF image: {e}"))?;
    let _ = sender.send(AcquireMessage::Log(format!(
        "EWF image size: {}",
        total_size.bytes_as_hrb()
    )));

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
    obj_header
        .description_header
        .custom_identifier_value("zffacquire::ewf_image", file_names(input_files).join(", "));

    let mut physical_objects: HashMap<ObjectHeader, ewf::EwfReader> = HashMap::new();
    physical_objects.insert(obj_header, ewf_reader);

    let output_path = build_output_path(output_file);
    let _ = sender.send(AcquireMessage::Log(format!(
        "Output: {}",
        output_path.display()
    )));

    let output = creation_parameters.output(&output_path);
    let mut zs = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        hash_types,
        creation_parameters.build()?,
        output.clone(),
    )
    .map_err(|e| format!("Failed to create ZffWriter: {e}"))?;

    let outcome = drive_writer(
        &mut zs,
        &output,
        chunk_size,
        &ProgressBasis::Bytes(total_size),
        sender,
        cancel,
    )?;
    if outcome == AcquireOutcome::Completed {
        let _ = sender.send(AcquireMessage::Status("Finishing...".to_string()));
        let _ = sender.send(AcquireMessage::Log(
            "ZFF container successfully created from EWF".to_string(),
        ));
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn acquire_convert_tar(
    config: &AcquireConfig,
    password: Option<&str>,
    input_files: &[PathBuf],
    output_file: &Path,
    encryption_hdr: Option<EncryptionHeader>,
    creation_parameters: &CreationParameters,
    hash_types: Vec<zffacquire_common::HashType>,
    chunk_size: u64,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<AcquireOutcome, String> {
    let input_path = input_files
        .first()
        .ok_or("No input file specified for TAR conversion")?;

    let _ = sender.send(AcquireMessage::Status(
        "Converting TAR to ZFF...".to_string(),
    ));
    let _ = sender.send(AcquireMessage::Log(format!(
        "Input: {}",
        input_path.display()
    )));

    // Step 1: write the tar as a passive physical object into a container.
    let flags = setup_object_flags(config, true);
    let mut obj_header = ObjectHeader::new(
        INITIAL_OBJECT_NUMBER,
        encryption_hdr,
        chunk_size,
        compression_header(config)?,
        object_description_header(config),
        ObjectType::Physical,
        flags,
    );
    obj_header.flags.passive_object = true;
    obj_header.description_header.custom_identifier_value(
        "zffacquire::tar_archive::virtual_mapped_object",
        file_names(std::slice::from_ref(input_path)).join(", "),
    );

    let fd = File::open(input_path)
        .map_err(|e| format!("Failed to open TAR file {}: {e}", input_path.display()))?;

    let decompressed = phollpers::compression::decompress(fd)
        .map_err(|e| format!("Failed to decompress TAR input: {e}"))?;

    let mut converter_objects = HashMap::new();
    converter_objects.insert(obj_header, decompressed);

    let container_path = build_output_path(output_file);
    let _ = sender.send(AcquireMessage::Log(format!(
        "Step 1: Writing passive container: {}",
        container_path.display()
    )));

    let output = ZffFilesOutput::NewContainer(container_path.clone());
    let mut zs = ZffWriter::new(
        converter_objects,
        HashMap::new(),
        HashMap::new(),
        hash_types.clone(),
        creation_parameters.build()?,
        output.clone(),
    )
    .map_err(|e| format!("Failed to create ZffWriter: {e}"))?;

    let outcome = drive_writer(
        &mut zs,
        &output,
        chunk_size,
        &ProgressBasis::Files(1),
        sender,
        cancel,
    )?;
    if outcome == AcquireOutcome::Cancelled {
        return Ok(outcome);
    }
    // The reader below opens the container by path, so the writer must be gone.
    drop(zs);

    // Step 2: read the container back and map the tar into a virtual object.
    let _ = sender.send(AcquireMessage::Status(
        "Creating virtual TAR object...".to_string(),
    ));
    let _ = sender.send(AcquireMessage::Log(
        "Step 2: Reading back container for virtual object".to_string(),
    ));

    let reader_vec = open_files(vec![container_path.clone()])?;

    let mut zffreader = ZffReader::with_reader(reader_vec)
        .map_err(|e| format!("Failed to create ZffReader: {e}"))?;

    zffreader
        .initialize_object(INITIAL_OBJECT_NUMBER)
        .map_err(|e| format!("Failed to initialize object: {e}"))?;

    // The passive object written in step 1 carries the tar. If it was
    // encrypted, it has to be unlocked before its contents can be mapped.
    if let Some(password) = password {
        zffreader
            .decrypt_object(INITIAL_OBJECT_NUMBER, password)
            .map_err(|e| format!("Failed to decrypt the passive object: {e}"))?;
    }

    let vos_tar = VirtualObjectSourceLogicalTar::new(
        zffreader,
        INITIAL_OBJECT_NUMBER,
        None,
        hash_types.clone(),
    )
    .map_err(|e| format!("Failed to create VirtualObjectSourceLogicalTar: {e}"))?;

    // The virtual object needs an encryption header of its own; the one built
    // for step 1 was consumed there. Without this the file listing would be
    // written in the clear on top of an encrypted container.
    let virtual_encryption_header = match password {
        Some(password) => Some(encryption_header(
            config.kdf_scheme.clone(),
            config.pbe_scheme.clone(),
            config.encryption_algorithm.clone(),
            password,
        )?),
        None => None,
    };

    let mut virtual_obj_header = create_object_header(config, virtual_encryption_header, false)
        .map_err(|e| format!("Failed to create object header: {e}"))?;
    virtual_obj_header.flags.passive_object = false;
    virtual_obj_header.object_type = ObjectType::Virtual;

    let mut virtual_objects: HashMap<ObjectHeader, Box<dyn zff::VirtualObjectSource>> =
        HashMap::new();
    virtual_objects.insert(virtual_obj_header, create_vos(vos_tar));

    let _ = sender.send(AcquireMessage::Log(format!(
        "Step 3: Extending container: {}",
        container_path.display()
    )));

    let physical_objects: HashMap<ObjectHeader, File> = HashMap::new();
    // Extending, not rewriting: the writer appends to the container step 1
    // produced, so the same creation parameters -- above all the same signature
    // key -- are reused rather than derived a second time.
    let output = ZffFilesOutput::ExtendContainer(vec![container_path]);
    let mut zs = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        virtual_objects,
        hash_types,
        creation_parameters.build()?,
        output.clone(),
    )
    .map_err(|e| format!("Failed to create final ZffWriter: {e}"))?;

    let outcome = drive_writer(
        &mut zs,
        &output,
        chunk_size,
        &ProgressBasis::Files(1),
        sender,
        cancel,
    )?;
    if outcome == AcquireOutcome::Completed {
        let _ = sender.send(AcquireMessage::Status("Finishing...".to_string()));
        let _ = sender.send(AcquireMessage::Log(
            "ZFF container successfully created from TAR".to_string(),
        ));
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn acquire_memory(
    config: &AcquireConfig,
    output_file: &Path,
    encryption_hdr: Option<EncryptionHeader>,
    creation_parameters: &CreationParameters,
    hash_types: Vec<zffacquire_common::HashType>,
    chunk_size: u64,
    sender: &tokio::sync::mpsc::UnboundedSender<AcquireMessage>,
    cancel: &AtomicBool,
) -> Result<AcquireOutcome, String> {
    #[cfg(target_os = "linux")]
    {
        use zffacquire_common::memory_reader::{Emd, memory_size};
        let total = memory_size().map_err(|e| format!("Cannot determine RAM size: {e}"))?;
        if total == 0 {
            return Err(
                "No readable RAM ranges found; check kernel memory access privileges".into(),
            );
        }
        let reader = Emd::new().map_err(|e| format!("Cannot acquire RAM via eBPF: {e}"))?;
        let mut header = create_object_header(config, encryption_hdr, false)?;
        header.object_type = ObjectType::Physical;
        header
            .description_header
            .custom_identifier_value("zffacquire::memory", "eBPF / LiME");
        let output = creation_parameters.output(output_file);
        let mut writer = ZffWriter::new(
            HashMap::from([(header, reader)]),
            HashMap::new(),
            HashMap::new(),
            hash_types,
            creation_parameters.build()?,
            output.clone(),
        )
        .map_err(|e| e.to_string())?;
        drive_writer(
            &mut writer,
            &output,
            chunk_size,
            &ProgressBasis::Bytes(total),
            sender,
            cancel,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            config,
            output_file,
            encryption_hdr,
            creation_parameters,
            hash_types,
            chunk_size,
            sender,
            cancel,
        );
        Err("Live memory acquisition is supported on Linux only".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gui_extends_multiple_segments_with_physical_and_logical_evidence() {
        let dir = std::env::temp_dir().join(format!(
            "zff-gui-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let input = dir.join("input.raw");
        let mut state = 42_u64;
        let data: Vec<u8> = (0..2 * 1024 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        std::fs::write(&input, &data).unwrap();
        let base = dir.join("output.z01");
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let cancel = AtomicBool::new(false);
        let segments = || {
            let mut paths: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.file_stem().is_some_and(|s| s == "output"))
                .collect();
            paths.sort();
            paths
        };
        for (index, source) in [
            AcquireCommand::Physical,
            AcquireCommand::Physical,
            AcquireCommand::Logical,
            AcquireCommand::Physical,
        ]
        .into_iter()
        .enumerate()
        {
            let params = AcquireParams {
                command: if index == 0 {
                    source.clone()
                } else {
                    AcquireCommand::Extend
                },
                append_command: source,
                segments: if index == 0 { Vec::new() } else { segments() },
                convert_format: ConvertFormat::Tar,
                config: AcquireConfig {
                    encrypt: index == 3,
                    ..AcquireConfig::default()
                },
                password: (index == 3).then(|| "test password".into()),
                input_files: vec![input.clone()],
                output_file: base.clone(),
                chunk_size_str: "32KiB".into(),
                chunkmap_size_str: "32KiB".into(),
                segment_size_str: Some("1MiB".into()),
                deduplication: if index == 3 {
                    DeduplicationMode::OnDisk(dir.join("dedup.map"))
                } else if index == 1 {
                    DeduplicationMode::InMemory
                } else {
                    DeduplicationMode::None
                },
            };
            assert_eq!(
                run_acquisition(params, &sender, &cancel).unwrap(),
                AcquireOutcome::Completed
            );
            assert!(segments().len() > 1);
            let mut reader = ZffReader::with_reader(open_files(segments()).unwrap()).unwrap();
            reader.initialize_objects_all().unwrap();
            assert_eq!(reader.list_objects().unwrap().len(), index + 1);
            reader.set_active_object(1).unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, data);
            if index > 0 {
                let object_number = index as u64 + 1;
                if index == 3 {
                    reader
                        .decrypt_object(object_number, "test password")
                        .unwrap();
                }
                reader.set_active_object(object_number).unwrap();
                if index == 2 {
                    reader.set_active_file(1).unwrap();
                }
                actual.clear();
                reader.read_to_end(&mut actual).unwrap();
                assert_eq!(actual, data);
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
