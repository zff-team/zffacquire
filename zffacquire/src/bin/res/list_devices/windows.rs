// Parent use
use super::*;

#[cfg(target_family = "windows")]
#[derive(Debug)]
pub(crate) struct WindowsPhysicalDevice {
    device_number: u32,
    volumes: Vec<WindowsVolume>,
    size: u64
}

#[cfg(target_family = "windows")]
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct WindowsVolume {
    device_identifier: String,
    volume_name: String,
    mounted_paths: String,
    volume_serial_number: u32,
    file_system_name: String,
    file_system_flags: u32,
    max_component_length: u32,
}

#[cfg(target_family = "windows")]
fn get_windows_drives() -> Result<Vec<WindowsPhysicalDevice>> {
    let mut windows_physical_devices: Vec<WindowsPhysicalDevice> = Vec::new();

    // Setup volume_name buffer and starts with the first volume.
    let mut volume_name = vec![0u16; MAX_PATH];
    let find_handle = unsafe { FindFirstVolumeW(volume_name.as_mut_ptr(), volume_name.len() as u32) };
    if find_handle == INVALID_HANDLE_VALUE {
        return Err(Box::new(io::Error::last_os_error()));
    }

    // Loop through all volumes.
    loop {
        // Get the mounted paths for the volume.
        let mut mounted_paths = vec![0u16; MAX_PATH];
        let _ = unsafe { GetVolumePathNamesForVolumeNameW(
            volume_name.as_ptr(), 
            mounted_paths.as_mut_ptr(), 
            mounted_paths.len() as u32,
            ptr::null_mut()); 
        };

        // Workaround for the fact that QueryDosDeviceW expects a volume name without the prefix "\\?\Volume{" and,
        // needs a null byte at the end of the string.
        // See [https://learn.microsoft.com/en-us/windows/win32/fileio/displaying-volume-paths] for further details.
        let null_byte_index_volume_name = volume_name.iter().position(|&x| x == 0).unwrap_or(volume_name.len());
        let mut temp_volume_name = volume_name[..null_byte_index_volume_name].to_vec();
        let len = temp_volume_name.len();
        temp_volume_name[len - 1] = '\0' as u16;
        
        // Get the device identifier for the volume.
        let mut device_identifier = vec![0u16; MAX_PATH];
        let _ = unsafe { QueryDosDeviceW(
            temp_volume_name[4..].as_ptr(), 
            device_identifier.as_mut_ptr(), 
            device_identifier.len() as u32) 
        };

        // Get the volume information.
        let mut volume_serial_number = 0u32;
        let mut max_component_length = 0u32;
        let mut file_system_flags = 0u32;
        let mut file_system_name = vec![0u16; MAX_PATH];
        let _ = unsafe { GetVolumeInformationByHandleW(
            find_handle, 
            volume_name.as_mut_ptr(), 
            volume_name.len() as u32, 
            &mut volume_serial_number, 
            &mut max_component_length, 
            &mut file_system_flags, 
            file_system_name.as_mut_ptr(), 
            file_system_name.len() as u32) 
        };
        
        // Find the null byte index for the strings (otherwise they will be printed with garbage at the end).
        let null_byte_index_filesystem = file_system_name.iter().position(|&x| x == 0).unwrap_or(file_system_name.len());
        let null_byte_index_device_identifier = device_identifier.iter().position(|&x| x == 0).unwrap_or(device_identifier.len());
        let null_byte_index_mounted_paths = mounted_paths.iter().position(|&x| x == 0).unwrap_or(mounted_paths.len());

        // Create a WindowsVolume struct and add it to the list.
        let windows_volume = WindowsVolume {
            device_identifier: String::from_utf16_lossy(&device_identifier[..null_byte_index_device_identifier]),
            volume_name: String::from_utf16_lossy(&volume_name[..null_byte_index_volume_name]),
            mounted_paths: String::from_utf16_lossy(&mounted_paths[..null_byte_index_mounted_paths]),
            volume_serial_number,
            file_system_name: String::from_utf16_lossy(&file_system_name[..null_byte_index_filesystem]),
            file_system_flags,
            max_component_length,
        };

        // Open the volume handle to obtain the storage device number and the disk size.
        let volume_handle = unsafe { CreateFileW(
            temp_volume_name.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        ) };
        if volume_handle == INVALID_HANDLE_VALUE {
            return Err(Box::new(io::Error::last_os_error()));
        }
        
        let sdn = get_storage_device_number_by_handle(volume_handle)?;
        
        // Calculate the size of the physical disk.
        let disk_size = get_disk_size_by_handle(volume_handle)?;
        
        // Close the volume handle.
        unsafe { CloseHandle(volume_handle) };

        if let Some(physical_device) = windows_physical_devices.iter_mut().find(|x| x.device_number == sdn) {
            physical_device.volumes.push(windows_volume);
        } else {
            windows_physical_devices.push(WindowsPhysicalDevice {
                device_number: sdn,
                volumes: vec![windows_volume],
                size: disk_size as u64,
            });
        }

        // First, go to next volume and close the handle to the current one.
        if unsafe { FindNextVolumeW(find_handle, volume_name.as_mut_ptr(), volume_name.len() as u32) } == 0 {
            // if this is the last handle, sets the break_loop flag to true and closes the handle.
            break;
        }
    }
    Ok(windows_physical_devices)
}

#[cfg(target_family = "windows")]
fn get_storage_device_number_by_handle(handle: HANDLE) -> Result<u32> {
    let mut bytes_returned: DWORD = 0;
    let mut sdn: STORAGE_DEVICE_NUMBER = STORAGE_DEVICE_NUMBER::default();

    let result = unsafe { DeviceIoControl(
        handle,
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        ptr::null_mut(),
        0,
        &mut sdn as *mut _ as *mut _,
        std::mem::size_of::<STORAGE_DEVICE_NUMBER>() as DWORD,
        &mut bytes_returned,
        ptr::null_mut(),
    ) };
    if result == 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    Ok(sdn.DeviceNumber)
}

#[cfg(target_family = "windows")]
fn get_disk_size_by_handle(handle: HANDLE) -> Result<u64> {
    let mut bytes_returned: DWORD = 0;
    let mut dg: DISK_GEOMETRY = DISK_GEOMETRY::default();

    let result = unsafe { DeviceIoControl(
        handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        ptr::null_mut(),
        0,
        &mut dg as *mut _ as *mut _,
        std::mem::size_of::<DISK_GEOMETRY>() as DWORD,
        &mut bytes_returned,
        ptr::null_mut(),
    ) };
    if result == 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    let size = unsafe { dg.Cylinders.QuadPart() * dg.TracksPerCylinder as i64 * dg.SectorsPerTrack as i64 * dg.BytesPerSector as i64 };
    Ok(size as u64)
}

#[cfg(target_family = "windows")]
pub(crate) fn print_devices_table() {
    let physical_drives = match get_windows_drives() {
        Ok(volumes) => volumes,
        Err(e) => {
            error!("{ERROR_GETTING_WINDOWS_VOLUME_LIST_}{}", e);
            exit(EXIT_STATUS_ERROR);
        }
    };

    let mut table = Table::new();
    table
    .load_preset(UTF8_FULL)
    .apply_modifier(UTF8_ROUND_CORNERS)
    .set_content_arrangement(ContentArrangement::Dynamic)
    .set_header(vec![
        Cell::new("Device Number").add_attribute(Attribute::Bold),
        Cell::new("Volumes").add_attribute(Attribute::Bold),
        Cell::new("Disk Size").add_attribute(Attribute::Bold),
    ]);
    for physical_drive in physical_drives {
        let mut subtable = Table::new();
        subtable
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Device Identifier").add_attribute(Attribute::Bold),
            Cell::new("Mounted Paths").add_attribute(Attribute::Bold),
            Cell::new("Volume S/N").add_attribute(Attribute::Bold),
        ]);
        for volume in physical_drive.volumes {
            subtable.add_row(vec![
                Cell::new(&volume.device_identifier),
                Cell::new(&volume.mounted_paths),
                Cell::new(&format!("{:X}", volume.volume_serial_number)),
            ]);
        }
        table.add_row(vec![
            Cell::new(&format!("\\\\?\\PhysicalDrive{}", physical_drive.device_number)),
            Cell::new(subtable.to_string()),
            Cell::new(&physical_drive.size.bytes_as_hrb()),
        ]);
    }
    println!("{}", table);
}