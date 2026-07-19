use crate::constants::HRS_PARSER_BASE;

pub fn hrs_parser<V: Into<String>>(value: V) -> Option<u64> {
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

pub fn parse_key_val<T, U>(s: &str) -> std::result::Result<(T, U), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let pos = s
        .find(':')
        .ok_or_else(|| format!("invalid KEY:value -> no `:` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

pub fn get_os_string() -> String {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        match Command::new("uname").arg("-a").output() {
            Ok(output) if output.status.success() => {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() { return s; }
            }
            _ => {}
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let os = std::env::consts::OS;
        if let Ok(output) = Command::new("cmd").args(["/c", "ver"]).output() {
            let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ver.is_empty() { return format!("{} {}", os, ver); }
        }
        return format!("{} {}", os, std::env::consts::ARCH);
    }
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}
