use std::borrow::Borrow;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use log::{debug, error};

use crate::constants::*;
use phollpers::compression::decompress;

#[cfg(target_family = "unix")]
pub fn concat_prefix_path<P: AsRef<Path>, S: AsRef<Path>>(prefix: P, path: S) -> PathBuf {
    let canonicalized_path = match PathBuf::from(&path.as_ref()).canonicalize() {
        Ok(path) => path,
        Err(e) => {
            error!("{}{} - {e}", ERROR_CANONICALIZE_INPUT_FILE_, path.as_ref().display());
            return path.as_ref().to_path_buf();
        }
    };
    match canonicalized_path.strip_prefix(UNIX_BASE) {
        Ok(stripped) => {
            let mut path_buf = PathBuf::from(prefix.as_ref());
            path_buf.push(stripped);
            path_buf
        },
        Err(e) => {
            error!("{}{} - {e}", ERROR_STRIPPING_PREFIX_INPUT_FILE_, path.as_ref().display());
            canonicalized_path
        }
    }
}

#[cfg(target_family = "windows")]
pub fn concat_prefix_path<P: AsRef<Path>, S: AsRef<Path>>(_: P, path: S) -> PathBuf {
    path.as_ref().to_path_buf()
}

#[cfg(target_family = "unix")]
fn open_physical_drive(input_file: PathBuf) -> std::io::Result<File> {
    let input_file = concat_prefix_path(INPUTFILES_PATH_PREFIX, input_file);
    File::open(input_file)
}

pub fn get_physical_input_file(input_file: PathBuf, try_uncompress: bool) -> Result<Box<dyn Read>, String> {
    let file = open_physical_drive(input_file).map_err(|e| e.to_string())?;
    if try_uncompress {
        Ok(decompress(file).map_err(|e| e.to_string())?)
    } else {
        Ok(Box::new(file))
    }
}

#[cfg(target_os = "linux")]
pub fn get_size_of_inputfile(input_file: PathBuf) -> Result<u64, String> {
    let is_device = input_file.starts_with(UNIX_BASE_DEV);
    let input_file = concat_prefix_path(INPUTFILES_PATH_PREFIX, input_file);
    if !is_device {
        let metadata = std::fs::metadata(&input_file).map_err(|e| e.to_string())?;
        Ok(metadata.len())
    } else {
        let block_device = input_file.strip_prefix(UNIX_BASE_DEV)
            .unwrap_or(&input_file);
        let block_device = block_device.to_string_lossy();
        let udev_device = udev::Device::from_subsystem_sysname(
            String::from(UDEV_SUBSYSTEM_BLOCK),
            String::from(block_device)
        ).map_err(|e| e.to_string())?;
        let size = udev_device.attribute_value(UDEV_ATTRIBUTE_SIZE)
            .ok_or_else(|| "Could not read device size attribute".to_string())?;
        let size = size.to_string_lossy().parse::<u64>().map_err(|e| e.to_string())?;
        Ok(size)
    }
}

#[cfg(target_family = "windows")]
pub fn get_size_of_inputfile(_input_file: PathBuf) -> Result<u64, String> {
    Err("Windows get_size_of_inputfile not yet implemented in common".to_string())
}

#[cfg(all(target_family = "unix", not(target_os = "linux")))]
pub fn get_size_of_inputfile(input_file: PathBuf) -> Result<u64, String> {
    let input_file = concat_prefix_path(INPUTFILES_PATH_PREFIX, input_file);
    let metadata = std::fs::metadata(input_file).map_err(|e| e.to_string())?;
    Ok(metadata.len())
}

pub fn open_files<P, V>(input_paths: V) -> Vec<File>
where
    P: AsRef<Path>,
    V: Borrow<Vec<P>>,
{
    let mut inputfiles = Vec::new();
    debug!("Opening {} segment files.", input_paths.borrow().len());
    for path in input_paths.borrow() {
        match File::open(path.as_ref()) {
            Ok(file) => inputfiles.push(file),
            Err(e) => {
                error!("Error opening file {}: {e}", path.as_ref().display());
            },
        };
    }
    inputfiles
}
