//STD
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::io::Read;
#[cfg(target_family = "windows")]
use std::{io, ptr};

// - modules
pub mod constants;
pub mod traits;
pub mod list_devices;

// - internal
use constants::*;
use traits::HumanReadable;

// - types
type Result<T> = std::result::Result<T, Box<dyn Error>>;

// - external
use comfy_table::{Table, Attribute, Cell, ContentArrangement};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;

#[cfg(target_family = "windows")]
use windows_drives::drive::{BufferedPhysicalDrive, BufferedHarddiskVolume};
#[cfg(target_family = "windows")]
use winapi::{
    shared::{
        minwindef::{MAX_PATH, DWORD},
    },
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
pub(crate) fn parse_key_val<T, U>(s: &str) -> std::result::Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
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
pub fn concat_prefix_path<P: AsRef<Path>, S: AsRef<Path>>(_: P, path: S) -> PathBuf {
    path.as_ref().to_path_buf()
}

#[cfg(target_family = "windows")]
fn open_physical_drive(drive_path: PathBuf) -> Result<Box<dyn Read>> {
    match open_physical_disk(drive_path.clone()) {
        Ok(drive) => Ok(Box::new(drive)),
        Err(_) => match open_harddisk_volume(drive_path) {
            Ok(volume) => Ok(Box::new(volume)),
            Err(e) => Err(e),
        },
    }
}

#[cfg(target_family = "windows")]
fn open_physical_disk(drive_path: PathBuf) -> Result<BufferedPhysicalDrive> {
    let drive_number = extract_physical_drive_digits(drive_path.to_string_lossy().as_ref())?;

    match BufferedPhysicalDrive::open(drive_number) {
        Ok(drive) => Ok(drive),
        Err(e) => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
    }
}

#[cfg(target_family = "windows")]
fn extract_physical_drive_digits<S: Into<String>>(s: S) -> Result<u8> {
    let s = s.into();
    let lower_s = s.to_lowercase();
    if lower_s.contains(PHYSICALDISK_LOWERCASE_PREFIX) {
        let suffix_start = match s.to_lowercase().find(PHYSICALDISK_LOWERCASE_PREFIX) {
            Some(start) => start + PHYSICALDISK_LOWERCASE_PREFIX.len(),
            None => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid drive path"))),
        };
        let suffix = &s[suffix_start..];
        return extract_suffix_digits(suffix);
    }
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid drive path")))
}

#[cfg(target_family = "windows")]
fn open_harddisk_volume(drive_path: PathBuf) -> Result<BufferedHarddiskVolume> {
    let volume_number = extract_harddiskvolume_digits(drive_path.to_string_lossy().as_ref())?;

    match BufferedHarddiskVolume::open(volume_number) {
        Ok(volume) => Ok(volume),
        Err(e) => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
    }
}

#[cfg(target_family = "windows")]
fn extract_harddiskvolume_digits<S: Into<String>>(s: S) -> Result<u8> {
    let s = s.into();
    let lower_s = s.to_lowercase();
    if lower_s.contains(HARDDISKVOLUME_LOWERCASE_PREFIX) {
        let suffix_start = match s.to_lowercase().find(HARDDISKVOLUME_LOWERCASE_PREFIX) {
            Some(start) => start + HARDDISKVOLUME_LOWERCASE_PREFIX.len(),
            None => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid drive path"))),
        };
        let suffix = &s[suffix_start..];
        return extract_suffix_digits(suffix);
    }
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid drive path")))
}

#[cfg(target_family = "windows")]
fn extract_suffix_digits(suffix: &str) -> Result<u8> {
    if suffix.chars().all(|c| c.is_digit(10)) {
        return Ok(suffix.parse::<u8>()?);
    }
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid drive path")))
}

#[cfg(target_family = "unix")]
fn open_physical_drive(input_file: PathBuf) -> Result<File> {
    let input_file = concat_prefix_path(INPUTFILES_PATH_PREFIX ,input_file);
    Ok(File::open(input_file)?)
}


pub(crate) fn get_physical_input_file(input_file: PathBuf) -> Result<impl Read> {
    open_physical_drive(input_file)
}