use std::process::Command;

pub fn get_os_string() -> String {
    #[cfg(target_os = "linux")]
    {
        match Command::new("uname").arg("-a").output() {
            Ok(output) if output.status.success() => {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
            _ => {}
        }
    }

    #[cfg(target_os = "windows")]
    {
        let os = std::env::consts::OS;
        if let Ok(output) = Command::new("cmd").args(["/c", "ver"]).output() {
            let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ver.is_empty() {
                return format!("{} {}", os, ver);
            }
        }
        return format!("{} {}", os, std::env::consts::ARCH);
    }

    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}
