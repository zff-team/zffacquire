//STD
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::exit;

// - modules
pub mod constants;
pub mod traits;

// - internal
use constants::*;

// - external
#[cfg(target_family = "windows")]
use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    os::windows::ffi::OsStrExt,
    os::windows::io::FromRawHandle,
};
#[cfg(target_family = "windows")]
use winapi::{
    shared::minwindef::DWORD,
    um::{
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::INVALID_HANDLE_VALUE,
        winbase::FILE_FLAG_NO_BUFFERING,
        winnt::{FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_SHARE_READ},
    },
};

#[cfg(target_family = "unix")]
use std::fs::File;

use log::error;

pub(crate) fn hrs_parser<V: Into<String>>(value: V) -> Option<u64> {
    let mut value = value.into();
    if let Ok(val) = value.parse() { return Some(val) };
    let mut last_char = value.pop()?;
    if last_char == 'b' || last_char == 'B' {
        last_char = value.pop()?;
    }
    if last_char == 'k' || last_char == 'K' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(1)?)),
            Err(_) => return None
        }
    }
    if last_char == 'm' || last_char == 'M' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(2)?)),
            Err(_) => return None,
        }
    }
    if last_char == 'g' || last_char == 'G' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(3)?)),
            Err(_) => return None,
        }
    }
    if last_char == 't' || last_char == 'T' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(4)?)),
            Err(_) => return None,
        }
    }
    if last_char == 'p' || last_char == 'P' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(5)?)),
            Err(_) => return None,
        }
    }
    None
}

/// Parse a single key-value pair
pub(crate) fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find(':')
        .ok_or_else(|| format!("invalid KEY:value -> no `:` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

// workaround to enable the correct construction of snap packages. Will be replaced by something more elegant in the future.
#[cfg(target_family = "unix")]
pub fn concat_prefix_path<P: AsRef<Path>, S: AsRef<Path>>(prefix: P, path: S) -> PathBuf {
    let canonicalized_path = match PathBuf::from(&path.as_ref()).canonicalize() {
        Ok(path) => path,
        Err(e) => {
            error!("{ERROR_CANONICALIZE_INPUT_FILE_}{} - {e}", path.as_ref().display());
            exit(EXIT_STATUS_ERROR);
        }
    };
    match canonicalized_path.strip_prefix(UNIX_BASE) {
        Ok(path) => {
            let mut path_buf = PathBuf::from(prefix.as_ref());
            path_buf.push(path);
            path_buf
        },
        Err(e) => {
            error!("{ERROR_STRIPPING_PREFIX_INPUT_FILE_}{} - {e}", path.as_ref().display());
            exit(EXIT_STATUS_ERROR);
        }
    }
}

#[cfg(target_family = "windows")]
pub fn concat_prefix_path<P: AsRef<Path>, S: AsRef<Path>>(prefix: P, path: S) -> PathBuf {
    path.as_ref().to_path_buf()
}

#[cfg(target_family = "windows")]
fn open_physical_drive(drive_path: PathBuf) -> std::io::Result<File> {
    let drive_path_u16: Vec<u16> = drive_path.as_os_str().encode_wide().chain(Some(0).into_iter()).collect();
    unsafe {
        let handle = CreateFileW(
            drive_path_u16.as_ptr(),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING,
            std::ptr::null_mut(),
        );
        if handle == std::ptr::null_mut() || handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        //convert the winapi-handle to a ffi handle
        let ffi_handle: *mut std::ffi::c_void = handle as *mut std::ffi::c_void;

        Ok(File::from_raw_handle(ffi_handle))
    }
}

#[cfg(target_family = "unix")]
fn open_physical_drive(input_file: PathBuf) -> std::io::Result<File> {
    let input_file = concat_prefix_path(INPUTFILES_PATH_PREFIX ,input_file);
    File::open(input_file)
}


pub(crate) fn get_physical_input_file(input_file: PathBuf) -> std::io::Result<File> {
    open_physical_drive(input_file)
}