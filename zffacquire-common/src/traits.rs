pub trait HumanReadable {
    fn bytes_as_hrb(self) -> String;
}

impl HumanReadable for u64 {
    /// Formats a byte count on base 1024, labelled with the IEC units that
    /// base actually denotes.
    ///
    /// [`crate::hrs_parser`] parses on the same base, so what this prints is
    /// what that accepts. Reporting 1024-based numbers under the decimal SI
    /// labels would misstate every size the tool shows by up to 10%.
    fn bytes_as_hrb(self) -> String {
        const DIVISOR: f64 = 1024.0;
        const UNIT: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
        let size = self as f64;
        let mut exponent = 0;
        while size >= DIVISOR.powi(exponent + 1) && (exponent as usize) < UNIT.len() - 1 {
            exponent += 1;
        }
        format!(
            "{:.2}{}",
            size / DIVISOR.powi(exponent),
            UNIT[exponent as usize]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hrs_parser;

    #[test]
    fn formats_on_the_binary_base() {
        assert_eq!(0u64.bytes_as_hrb(), "0.00B");
        assert_eq!(512u64.bytes_as_hrb(), "512.00B");
        assert_eq!(1024u64.bytes_as_hrb(), "1.00KiB");
        assert_eq!((32 * 1024u64).bytes_as_hrb(), "32.00KiB");
        assert_eq!((5 * 1024 * 1024u64).bytes_as_hrb(), "5.00MiB");
        assert_eq!(u64::MAX.bytes_as_hrb(), "16.00EiB");
    }

    #[test]
    fn what_is_printed_parses_back() {
        for bytes in [1024u64, 32 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024 * 1024] {
            let printed = bytes.bytes_as_hrb();
            let round_tripped = hrs_parser(printed.replace(".00", ""))
                .unwrap_or_else(|| panic!("{printed} did not parse back"));
            assert_eq!(round_tripped, bytes, "{printed}");
        }
    }
}
