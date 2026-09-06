use std::borrow::Borrow;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use log::{debug, error};

#[cfg(target_family = "unix")]
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

#[cfg(target_family = "windows")]
trait ReadSeek: Read + std::io::Seek {}

#[cfg(target_family = "windows")]
impl<T: Read + std::io::Seek> ReadSeek for T {}

#[cfg(target_family = "windows")]
fn open_physical_drive(input_file: PathBuf) -> std::io::Result<Box<dyn ReadSeek>> {
    use windows_drives::drive::{BufferedHarddiskVolume, BufferedPhysicalDrive};

    match windows_device(&input_file)? {
        Some((true, number)) => BufferedPhysicalDrive::open(number)
            .map(|drive| Box::new(drive) as Box<dyn ReadSeek>)
            .map_err(std::io::Error::other),
        Some((false, number)) => BufferedHarddiskVolume::open(number)
            .map(|volume| Box::new(volume) as Box<dyn ReadSeek>)
            .map_err(std::io::Error::other),
        None => Ok(Box::new(File::open(input_file)?)),
    }
}

// Recognize device names without mistaking ordinary image filenames for devices.
#[cfg(any(target_family = "windows", test))]
fn windows_device(path: &Path) -> std::io::Result<Option<(bool, u8)>> {
    let path = path.to_string_lossy().to_ascii_lowercase();
    let name = path.strip_prefix(r"\\.\")
        .or_else(|| path.strip_prefix(r"\\?\"))
        .unwrap_or(&path);
    let (physical, number) = if let Some(number) = name.strip_prefix("physicaldrive") {
        (true, number)
    } else if let Some(number) = name.strip_prefix("harddiskvolume") {
        (false, number)
    } else {
        return Ok(None);
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid drive number"));
    }
    let number = number.parse::<u8>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    Ok(Some((physical, number)))
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
pub fn get_size_of_inputfile(input_file: PathBuf) -> Result<u64, String> {
    use windows_drives::drive::{HarddiskVolume, PhysicalDrive};

    match windows_device(&input_file).map_err(|e| e.to_string())? {
        Some((true, number)) => PhysicalDrive::open(number).map(|drive| drive.size()),
        Some((false, number)) => HarddiskVolume::open(number).map(|volume| volume.size()),
        None => std::fs::metadata(input_file).map(|metadata| metadata.len())
            .map_err(|e| e.to_string()),
    }
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_device_paths() {
        for (path, expected) in [
            (r"\\.\PhysicalDrive0", (true, 0)),
            (r"\\?\PHYSICALDRIVE12", (true, 12)),
            ("PhysicalDrive255", (true, 255)),
            (r"\\?\HarddiskVolume1", (false, 1)),
        ] {
            assert_eq!(windows_device(Path::new(path)).unwrap(), Some(expected));
        }
    }

    #[test]
    fn windows_image_paths_are_not_devices() {
        for path in [r"C:\images\PhysicalDrive0.raw", r"\\server\images\disk.raw", "disk.raw"] {
            assert_eq!(windows_device(Path::new(path)).unwrap(), None);
        }
    }

    #[test]
    fn invalid_windows_device_numbers_are_rejected() {
        for path in [r"\\.\PhysicalDrive", r"\\.\PhysicalDrive256", r"\\.\PhysicalDrive+1", r"\\?\HarddiskVolume1x"] {
            assert_eq!(windows_device(Path::new(path)).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}
