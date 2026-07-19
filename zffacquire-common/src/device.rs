use std::path::Path;
use udev;

pub struct DeviceInfo {
    pub logical_sector_size: Option<String>,
    pub physical_sector_size: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub firmware: Option<String>,
    pub media_type: Option<String>,
}

pub fn get_device_info(input_path: &Path) -> Option<DeviceInfo> {
    let device_name = input_path.file_name()?.to_str()?;
    let device = match udev::Device::from_subsystem_sysname("block".to_string(), device_name.to_string()) {
        Ok(dev) => dev,
        Err(_) => return None,
    };
    let logical_sector_size = device.attribute_value("queue/logical_block_size").map(|v| v.to_string_lossy().to_string());
    let physical_sector_size = device.attribute_value("queue/physical_block_size").map(|v| v.to_string_lossy().to_string());
    let model = device.attribute_value("id_model").or_else(|| device.attribute_value("model")).map(|v| v.to_string_lossy().trim().to_string());
    let serial_number = device.attribute_value("id_serial").or_else(|| device.attribute_value("serial")).map(|v| v.to_string_lossy().trim().to_string());
    let firmware = device.attribute_value("id_revision").or_else(|| device.attribute_value("device/firmware_rev")).map(|v| v.to_string_lossy().trim().to_string());
    let media_type = detect_media_type(&device);
    Some(DeviceInfo { logical_sector_size, physical_sector_size, model, serial_number, firmware, media_type })
}

fn detect_media_type(device: &udev::Device) -> Option<String> {
    if let Some(attr) = device.attribute_value("id_bus") {
        let bus = attr.to_string_lossy();
        if bus == "nvme" { return Some("nvme".to_string()); }
        if bus == "usb" { return Some("usb".to_string()); }
        if bus == "mmc" {
            if let Some(attr) = device.attribute_value("id_type") {
                let t = attr.to_string_lossy();
                if t == "SD" || t == "SDHC" || t == "SDXC" { return Some("sd".to_string()); }
            }
            return Some("emmc".to_string());
        }
    }
    if let Some(attr) = device.attribute_value("queue/rotational") {
        match attr.to_string_lossy().as_ref() {
            "0" => return Some("ssd".to_string()),
            "1" => return Some("hdd".to_string()),
            _ => {}
        }
    }
    let device_name = device.sysname().to_string_lossy();
    if device_name.starts_with("nvme") { return Some("nvme".to_string()); }
    if device_name.starts_with("mmc") || device_name.starts_with("mmcblk") { return Some("emmc".to_string()); }
    if device_name.starts_with("sd") { return Some("usb".to_string()); }
    None
}
