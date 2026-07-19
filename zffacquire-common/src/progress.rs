use crossbeam_channel::Sender;

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Progress { current: u64, total: u64 },
    Status(String),
    Finished(Result<(), String>),
}

pub trait ProgressReporter {
    fn update(&mut self, current: u64, total: u64);
    fn set_status(&mut self, status: &str);
}

pub struct NullProgressReporter;

impl ProgressReporter for NullProgressReporter {
    fn update(&mut self, _current: u64, _total: u64) {}
    fn set_status(&mut self, _status: &str) {}
}

pub struct ChannelProgressReporter {
    sender: Sender<ProgressEvent>,
}

impl ChannelProgressReporter {
    pub fn new(sender: Sender<ProgressEvent>) -> Self {
        Self { sender }
    }
}

impl ProgressReporter for ChannelProgressReporter {
    fn update(&mut self, current: u64, total: u64) {
        let _ = self.sender.send(ProgressEvent::Progress { current, total });
    }
    fn set_status(&mut self, status: &str) {
        let _ = self.sender.send(ProgressEvent::Status(status.to_string()));
    }
}

#[allow(clippy::type_complexity)]
pub struct CallbackProgressReporter {
    callback: Box<dyn FnMut(u64, u64) + Send>,
    status_callback: Option<Box<dyn FnMut(&str) + Send>>,
}

impl CallbackProgressReporter {
    pub fn new<F: FnMut(u64, u64) + Send + 'static>(callback: F) -> Self {
        Self { callback: Box::new(callback), status_callback: None }
    }
    pub fn with_status_callback<F: FnMut(&str) + Send + 'static>(mut self, callback: F) -> Self {
        self.status_callback = Some(Box::new(callback));
        self
    }
}

impl ProgressReporter for CallbackProgressReporter {
    fn update(&mut self, current: u64, total: u64) { (self.callback)(current, total); }
    fn set_status(&mut self, status: &str) {
        if let Some(ref mut cb) = self.status_callback { cb(status); }
    }
}

pub fn create_progress_reporter(sender: Option<Sender<ProgressEvent>>) -> Box<dyn ProgressReporter + Send> {
    match sender {
        Some(sender) => Box::new(ChannelProgressReporter::new(sender)),
        None => Box::new(NullProgressReporter),
    }
}
