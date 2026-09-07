use crate::constants::HRS_PARSER_BASE;

/// Parses a human readable size into a number of bytes.
///
/// Every unit is binary: `K` is 1024 bytes, `M` is 1024 KiB and so on. The
/// suffixes `K`, `KB` and `KiB` are therefore all accepted and all mean the
/// same thing; the `B` is decoration. [`crate::HumanReadable::bytes_as_hrb`]
/// formats on the same base, so a size printed by this tool parses back to
/// itself.
///
/// Returns `None` for anything unparsable and for a value that would overflow
/// a `u64` -- silently wrapping a segment size is worse than refusing it.
pub fn hrs_parser<V: Into<String>>(value: V) -> Option<u64> {
    let mut value = value.into().trim().to_string();
    if let Ok(val) = value.parse() { return Some(val) };

    let mut last_char = value.pop()?;
    if last_char == 'b' || last_char == 'B' {
        last_char = value.pop()?;
    }
    // The `i` of the IEC spelling (KiB, MiB, ...); the base is 1024 either way.
    if last_char == 'i' || last_char == 'I' {
        last_char = value.pop()?;
    }
    let exponent = match last_char.to_ascii_lowercase() {
        'k' => 1,
        'm' => 2,
        'g' => 3,
        't' => 4,
        'p' => 5,
        _ => return None,
    };
    let factor = HRS_PARSER_BASE.checked_pow(exponent)?;
    value.trim().parse::<u64>().ok()?.checked_mul(factor)
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
    }
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_suffixed_sizes() {
        assert_eq!(hrs_parser("4096"), Some(4096));
        assert_eq!(hrs_parser("32K"), Some(32 * 1024));
        assert_eq!(hrs_parser("32KB"), Some(32 * 1024));
        assert_eq!(hrs_parser("32KiB"), Some(32 * 1024));
        assert_eq!(hrs_parser("32kb"), Some(32 * 1024));
        assert_eq!(hrs_parser(" 32K "), Some(32 * 1024));
        assert_eq!(hrs_parser("1M"), Some(1024 * 1024));
        assert_eq!(hrs_parser("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(hrs_parser("2T"), Some(2 * 1024_u64.pow(4)));
        assert_eq!(hrs_parser("1P"), Some(1024_u64.pow(5)));
    }

    #[test]
    fn rejects_unparsable_values() {
        for value in ["", "K", "KB", "abc", "32X", "-1", "3.5G", "32 K B"] {
            assert_eq!(hrs_parser(value), None, "{value} should not parse");
        }
    }

    #[test]
    fn rejects_values_that_would_overflow() {
        // Wrapping here would silently produce a nonsensical segment size.
        assert_eq!(hrs_parser("18446744073709551P"), None);
        assert_eq!(hrs_parser(format!("{}K", u64::MAX)), None);
        assert_eq!(hrs_parser(format!("{}", u64::MAX)), Some(u64::MAX));
    }
}
