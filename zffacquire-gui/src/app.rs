use iced::{Element, Task, Theme};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zffacquire_common::{
    AcquireConfig, CompressionAlgorithm, EncryptionAlgorithm, HashType, KDFScheme, PBEScheme,
};

use crate::acquisition::{AcquireMessage, AcquireOutcome, AcquireParams, start_acquisition};
use crate::screens::{command_select, input_select, parameters, progress, review};

static ACQUIRE_RX: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<AcquireMessage>>> =
    Mutex::new(None);

fn build_acquire_stream(
    _generation: &u64,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = Message> + Send>> {
    let rx = ACQUIRE_RX.lock().unwrap().take().expect("receiver not set");
    Box::pin(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|msg| match msg {
            AcquireMessage::Progress(c, t) => (Message::AcquireProgress(c, t), rx),
            AcquireMessage::Log(l) => (Message::AcquireLog(l), rx),
            AcquireMessage::Status(s) => (Message::AcquireStatus(s), rx),
            AcquireMessage::Finished(r) => (Message::AcquireFinished(r), rx),
        })
    }))
}

#[derive(Debug, Clone)]
pub enum Screen {
    CommandSelect,
    Parameters,
    InputSelect,
    Review,
    Progress,
}

/// The acquisitions the GUI can carry out.
///
/// Memory acquisition and extending an existing container are command line
/// features: they need input the wizard has no screen for, so they are not
/// offered here rather than being offered and then refused.
#[derive(Debug, Clone, PartialEq)]
pub enum AcquireCommand {
    Physical,
    Logical,
    Convert,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConvertFormat {
    Tar,
    Ewf,
}

impl ConvertFormat {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Tar => "TAR Archive",
            Self::Ewf => "EWF (E01)",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeduplicationMode {
    None,
    InMemory,
    OnDisk(PathBuf),
}

#[derive(Debug, Clone, PartialEq)]
pub enum KdfPbeOption {
    Argon2idAes256,
    Argon2idAes128,
    ScryptAes256,
    ScryptAes128,
    Pbkdf2Aes256,
    Pbkdf2Aes128,
}

impl KdfPbeOption {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Argon2idAes256 => "Argon2id + AES-256-CBC",
            Self::Argon2idAes128 => "Argon2id + AES-128-CBC",
            Self::ScryptAes256 => "Scrypt + AES-256-CBC",
            Self::ScryptAes128 => "Scrypt + AES-128-CBC",
            Self::Pbkdf2Aes256 => "PBKDF2-SHA256 + AES-256-CBC",
            Self::Pbkdf2Aes128 => "PBKDF2-SHA256 + AES-128-CBC",
        }
    }

    pub fn all() -> &'static [KdfPbeOption] {
        &[
            Self::Argon2idAes256,
            Self::Argon2idAes128,
            Self::ScryptAes256,
            Self::ScryptAes128,
            Self::Pbkdf2Aes256,
            Self::Pbkdf2Aes128,
        ]
    }

    pub fn to_kdf_pbe(&self) -> (KDFScheme, PBEScheme) {
        match self {
            Self::Argon2idAes256 => (KDFScheme::Argon2id, PBEScheme::AES256CBC),
            Self::Argon2idAes128 => (KDFScheme::Argon2id, PBEScheme::AES128CBC),
            Self::ScryptAes256 => (KDFScheme::Scrypt, PBEScheme::AES256CBC),
            Self::ScryptAes128 => (KDFScheme::Scrypt, PBEScheme::AES128CBC),
            Self::Pbkdf2Aes256 => (KDFScheme::PBKDF2SHA256, PBEScheme::AES256CBC),
            Self::Pbkdf2Aes128 => (KDFScheme::PBKDF2SHA256, PBEScheme::AES128CBC),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    NextScreen,
    PrevScreen,
    SelectCommand(AcquireCommand),
    ConvertFormatChanged(ConvertFormat),
    CompressionAlgoChanged(CompressionAlgorithm),
    CompressionLevelChanged(u8),
    CompressionThresholdChanged(String),
    ToggleEncryption(bool),
    PasswordChanged(String),
    PasswordConfirmChanged(String),
    KdfPbeChanged(KdfPbeOption),
    EncryptionAlgoChanged(EncryptionAlgorithm),
    ToggleHash(HashType),
    ToggleSignData(bool),
    SignKeyChanged(String),
    SegmentSizeChanged(String),
    ChunkSizeChanged(String),
    ChunkmapSizeChanged(String),
    DeduplicationChanged(DeduplicationMode),
    UncompressInputChanged(bool),
    CaseNumberChanged(String),
    EvidenceNumberChanged(String),
    ExaminerNameChanged(String),
    NotesChanged(String),
    AddCustomDescription,
    RemoveCustomDescription(usize),
    CustomDescriptionKeyChanged(usize, String),
    CustomDescriptionValueChanged(usize, String),
    PickInputFile,
    PickInputFolder,
    PickOutputFile,
    PickDeduplicationFile,
    InputFilesSelected(Vec<PathBuf>),
    OutputFileSelected(PathBuf),
    ClearInputFiles,
    StartAcquisition,
    CancelAcquisition,
    AcquireProgress(u64, u64),
    AcquireLog(String),
    AcquireStatus(String),
    AcquireFinished(Result<AcquireOutcome, String>),
}

pub struct ZffAcquireApp {
    pub current_screen: Screen,
    pub selected_command: Option<AcquireCommand>,
    pub convert_format: ConvertFormat,

    pub compression_algo: CompressionAlgorithm,
    pub compression_level: u8,
    pub compression_threshold: f32,
    pub encrypt: bool,
    pub password: String,
    pub password_confirm: String,
    pub kdf_pbe: KdfPbeOption,
    pub encryption_algo: EncryptionAlgorithm,
    pub hash_algorithms: Vec<HashType>,
    pub sign_data: bool,
    pub sign_key: Option<String>,
    pub segment_size: Option<String>,
    pub chunk_size: String,
    pub chunkmap_size: String,
    pub deduplication: DeduplicationMode,
    pub uncompress_input: bool,
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub examiner_name: Option<String>,
    pub notes: Option<String>,
    pub custom_descriptions: Vec<(String, String)>,

    pub input_files: Vec<PathBuf>,
    pub output_file: Option<PathBuf>,

    pub progress_current: u64,
    pub progress_total: u64,
    pub progress_status: String,
    pub log_lines: Vec<String>,
    pub is_running: bool,

    #[allow(dead_code)]
    pub is_windows: bool,

    pub cancel_token: Option<Arc<AtomicBool>>,
    pub acquire_generation: u64,
}

impl ZffAcquireApp {
    pub fn new() -> (Self, Task<Message>) {
        let is_windows = cfg!(target_family = "windows");

        let app = Self {
            current_screen: Screen::CommandSelect,
            selected_command: None,
            convert_format: ConvertFormat::Tar,
            compression_algo: CompressionAlgorithm::Zstd,
            compression_level: 3,
            compression_threshold: 1.05,
            encrypt: false,
            password: String::new(),
            password_confirm: String::new(),
            kdf_pbe: KdfPbeOption::Argon2idAes256,
            encryption_algo: EncryptionAlgorithm::AES256GCM,
            hash_algorithms: vec![HashType::Blake3],
            sign_data: false,
            sign_key: None,
            segment_size: None,
            chunk_size: "32KB".to_string(),
            chunkmap_size: "32KB".to_string(),
            deduplication: DeduplicationMode::None,
            uncompress_input: false,
            case_number: None,
            evidence_number: None,
            examiner_name: None,
            notes: None,
            custom_descriptions: Vec::new(),
            input_files: Vec::new(),
            output_file: None,
            progress_current: 0,
            progress_total: 0,
            progress_status: String::new(),
            log_lines: Vec::new(),
            is_running: false,
            is_windows,
            cancel_token: None,
            acquire_generation: 0,
        };

        (app, Task::none())
    }

    pub fn title(&self) -> String {
        "zffacquire GUI".to_string()
    }

    pub fn build_config(&self) -> AcquireConfig {
        let (kdf_scheme, pbe_scheme) = self.kdf_pbe.to_kdf_pbe();
        AcquireConfig {
            tool: zffacquire_common::tool_identification!(),
            compression_algorithm: self.compression_algo.clone(),
            compression_level: self.compression_level,
            compression_threshold: self.compression_threshold,
            encrypt: self.encrypt,
            kdf_scheme,
            pbe_scheme,
            encryption_algorithm: self.encryption_algo.clone(),
            hash_algorithms: self.hash_algorithms.clone(),
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
            // The object note above and the container description note are two
            // distinct fields; the GUI offers only the former, so the latter
            // stays empty rather than carrying a copy.
            description_notes: None,
            uncompress_input: self.uncompress_input,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::NextScreen => {
                self.current_screen = match self.current_screen {
                    Screen::CommandSelect => Screen::Parameters,
                    Screen::Parameters => Screen::InputSelect,
                    Screen::InputSelect => Screen::Review,
                    Screen::Review => Screen::Progress,
                    Screen::Progress => Screen::Progress,
                };
            }
            Message::PrevScreen => {
                self.current_screen = match self.current_screen {
                    Screen::CommandSelect => Screen::CommandSelect,
                    Screen::Parameters => Screen::CommandSelect,
                    Screen::InputSelect => Screen::Parameters,
                    Screen::Review => Screen::InputSelect,
                    Screen::Progress => Screen::Review,
                };
            }
            Message::SelectCommand(cmd) => {
                self.selected_command = Some(cmd);
                self.current_screen = Screen::Parameters;
            }
            Message::ConvertFormatChanged(fmt) => {
                self.convert_format = fmt;
            }
            Message::CompressionAlgoChanged(algo) => {
                self.compression_algo = algo;
            }
            Message::CompressionLevelChanged(level) => {
                self.compression_level = level;
            }
            Message::CompressionThresholdChanged(threshold) => {
                if let Ok(val) = threshold.parse() {
                    self.compression_threshold = val;
                }
            }
            Message::ToggleEncryption(encrypt) => {
                self.encrypt = encrypt;
            }
            Message::PasswordChanged(password) => {
                self.password = password;
            }
            Message::PasswordConfirmChanged(password) => {
                self.password_confirm = password;
            }
            Message::KdfPbeChanged(opt) => {
                self.kdf_pbe = opt;
            }
            Message::EncryptionAlgoChanged(algo) => {
                self.encryption_algo = algo;
            }
            Message::ToggleHash(hash) => {
                if self.hash_algorithms.contains(&hash) {
                    self.hash_algorithms.retain(|h| h != &hash);
                } else {
                    self.hash_algorithms.push(hash);
                }
            }
            Message::ToggleSignData(sign) => {
                self.sign_data = sign;
            }
            Message::SignKeyChanged(key) => {
                self.sign_key = if key.is_empty() { None } else { Some(key) };
            }
            Message::SegmentSizeChanged(size) => {
                self.segment_size = if size.is_empty() { None } else { Some(size) };
            }
            Message::ChunkSizeChanged(size) => {
                self.chunk_size = size;
            }
            Message::ChunkmapSizeChanged(size) => {
                self.chunkmap_size = size;
            }
            Message::UncompressInputChanged(value) => {
                self.uncompress_input = value;
            }
            Message::DeduplicationChanged(mode) => {
                self.deduplication = mode;
            }
            Message::CaseNumberChanged(number) => {
                self.case_number = if number.is_empty() {
                    None
                } else {
                    Some(number)
                };
            }
            Message::EvidenceNumberChanged(number) => {
                self.evidence_number = if number.is_empty() {
                    None
                } else {
                    Some(number)
                };
            }
            Message::ExaminerNameChanged(name) => {
                self.examiner_name = if name.is_empty() { None } else { Some(name) };
            }
            Message::NotesChanged(notes) => {
                self.notes = if notes.is_empty() { None } else { Some(notes) };
            }
            Message::AddCustomDescription => {
                self.custom_descriptions
                    .push((String::new(), String::new()));
            }
            Message::RemoveCustomDescription(index) => {
                if index < self.custom_descriptions.len() {
                    self.custom_descriptions.remove(index);
                }
            }
            Message::CustomDescriptionKeyChanged(index, key) => {
                if index < self.custom_descriptions.len() {
                    self.custom_descriptions[index].0 = key;
                }
            }
            Message::CustomDescriptionValueChanged(index, value) => {
                if index < self.custom_descriptions.len() {
                    self.custom_descriptions[index].1 = value;
                }
            }
            Message::PickInputFile => {
                return Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Select input file")
                        .pick_file(),
                    |handle| match handle {
                        Some(h) => Message::InputFilesSelected(vec![h.path().to_path_buf()]),
                        None => Message::InputFilesSelected(Vec::new()),
                    },
                );
            }
            Message::PickInputFolder => {
                return Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Select folder")
                        .pick_folder(),
                    |handle| match handle {
                        Some(h) => Message::InputFilesSelected(vec![h.path().to_path_buf()]),
                        None => Message::InputFilesSelected(Vec::new()),
                    },
                );
            }
            Message::PickDeduplicationFile => {
                return Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Select the on-disk deduplication map")
                        .set_file_name("deduplication.map")
                        .save_file(),
                    |handle| match handle {
                        Some(h) => Message::DeduplicationChanged(DeduplicationMode::OnDisk(
                            h.path().to_path_buf(),
                        )),
                        None => Message::DeduplicationChanged(DeduplicationMode::None),
                    },
                );
            }
            Message::PickOutputFile => {
                return Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Select output location")
                        .set_file_name("dump.z01")
                        .save_file(),
                    |handle| match handle {
                        Some(h) => Message::OutputFileSelected(h.path().to_path_buf()),
                        None => Message::OutputFileSelected(PathBuf::new()),
                    },
                );
            }
            Message::InputFilesSelected(files) => {
                self.input_files.extend(files);
            }
            Message::OutputFileSelected(path) => {
                if !path.as_os_str().is_empty() {
                    self.output_file = Some(path);
                }
            }
            Message::ClearInputFiles => {
                self.input_files.clear();
            }
            Message::StartAcquisition => {
                let command = match self.selected_command.clone() {
                    Some(cmd) => cmd,
                    None => return Task::none(),
                };
                let output_file = match self.output_file.clone() {
                    Some(path) => path,
                    None => return Task::none(),
                };

                let password = if self.encrypt && self.password == self.password_confirm {
                    Some(self.password.clone())
                } else if self.encrypt {
                    self.progress_status = "Passwords do not match".to_string();
                    self.current_screen = Screen::Progress;
                    return Task::none();
                } else {
                    None
                };

                let config = self.build_config();
                let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
                let cancel_token = Arc::new(AtomicBool::new(false));
                let cancel_for_thread = cancel_token.clone();

                *ACQUIRE_RX.lock().unwrap() = Some(receiver);

                let params = AcquireParams {
                    command,
                    convert_format: self.convert_format.clone(),
                    config,
                    password,
                    input_files: self.input_files.clone(),
                    output_file,
                    chunk_size_str: self.chunk_size.clone(),
                    chunkmap_size_str: self.chunkmap_size.clone(),
                    segment_size_str: self.segment_size.clone(),
                    deduplication: self.deduplication.clone(),
                };

                start_acquisition(params, sender, cancel_for_thread);

                self.is_running = true;
                self.current_screen = Screen::Progress;
                self.progress_current = 0;
                self.progress_total = 0;
                self.progress_status = "Starting acquisition...".to_string();
                self.log_lines.clear();
                self.cancel_token = Some(cancel_token);
                self.acquire_generation += 1;
            }
            Message::CancelAcquisition => {
                if let Some(ref token) = self.cancel_token {
                    token.store(true, Ordering::Relaxed);
                }
                self.is_running = false;
            }
            Message::AcquireProgress(current, total) => {
                self.progress_current = current;
                self.progress_total = total;
            }
            Message::AcquireStatus(status) => {
                self.progress_status = status;
            }
            Message::AcquireLog(line) => {
                self.log_lines.push(line);
            }
            Message::AcquireFinished(result) => {
                self.is_running = false;
                self.cancel_token = None;
                match result {
                    Ok(AcquireOutcome::Completed) => {
                        self.progress_status = "Acquisition completed successfully".to_string();
                    }
                    Ok(AcquireOutcome::Cancelled) => {
                        self.progress_status =
                            "Cancelled. The container was not finalised and cannot be read."
                                .to_string();
                    }
                    Err(e) => {
                        self.progress_status = format!("Acquisition failed: {e}");
                    }
                }
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        use iced::Length;
        use iced::widget::{column, container};

        let stepper = crate::style::stepper_bar::<Message>(&self.current_screen);

        let screen_content = match self.current_screen {
            Screen::CommandSelect => command_select::view(self),
            Screen::Parameters => parameters::view(self),
            Screen::InputSelect => input_select::view(self),
            Screen::Review => review::view(self),
            Screen::Progress => progress::view(self),
        };

        let layout = column![
            stepper,
            container(screen_content)
                .width(Length::Fill)
                .height(Length::Fill)
                .style(crate::style::app_background),
        ]
        .width(Length::Fill)
        .height(Length::Fill);

        container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(crate::style::app_background)
            .into()
    }

    pub fn subscription(&self) -> iced::Subscription<Message> {
        if !self.is_running {
            return iced::Subscription::none();
        }
        iced::Subscription::run_with(self.acquire_generation, build_acquire_stream)
    }

    #[allow(dead_code)]
    pub fn theme(&self) -> Theme {
        Theme::Dark
    }
}
