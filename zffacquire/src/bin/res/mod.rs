// - STD
use std::fs::{File, OpenOptions};
use std::io::{Write, SeekFrom, Seek};
use std::path::Path;

use log::error;

// - modules
pub mod list_devices;
#[cfg(target_os = "linux")]
pub mod memory_reader;

#[cfg(target_os = "linux")]
use memory_reader::Emd;

// - internal
use zffacquire_common::constants::EXIT_STATUS_ERROR;

use zff::io::zffwriter::ZffFilesOutput;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(target_os = "linux")]
pub(crate) fn get_memory_reader(memory_reader_type: memory_reader::MemoryReaderType) -> Result<Box<dyn std::io::Read>> {
    match memory_reader_type {
        memory_reader::MemoryReaderType::Emd => Ok(Box::new(Emd::new()?)),
    }
}

pub fn setup_output_writer(output: &ZffFilesOutput) -> Box<dyn Write> {
    match output {
        ZffFilesOutput::Stream => Box::new(std::io::stdout()),
        ZffFilesOutput::NewContainer(path) => setup_output_writer_from_path(path),
        ZffFilesOutput::ExtendContainer(paths) => {
            match paths.first() {
                Some(path) => {
                    let mut file = match OpenOptions::new().append(true).read(true).open(path) {
                        Ok(file) => file,
                        Err(e) => {
                            error!("An error occured while trying to open the output file:\n{e}");
                            std::process::exit(EXIT_STATUS_ERROR);
                        }
                    };
                    match file.seek(SeekFrom::End(0)) {
                        Ok(_) => (),
                        Err(e) => {
                            error!("An error occured while trying to seek to the end of the output file:\n{e}");
                            std::process::exit(EXIT_STATUS_ERROR);
                        }
                    };
                    Box::new(file)
                },
                None => {
                     error!("An error occured while trying to create the output file: No output files found to open");
                     std::process::exit(EXIT_STATUS_ERROR)
                }
            }
        },
    }
}

pub fn setup_output_writer_from_path<P: AsRef<Path>>(path: P) -> Box<dyn Write> {
    match File::create(&path) {
        Ok(file) => Box::new(file),
        Err(e) => {
            error!("An error occured while trying to create the output file:\n{e}");
            std::process::exit(EXIT_STATUS_ERROR);
        }
    }
}
