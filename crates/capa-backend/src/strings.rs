//! String extraction utilities
//!
//! Porting Python capa's `capa.features.extractors.strings` module.

/// An extracted string with its offset in the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
}

/// Returns true if the entire buffer is filled with the given byte.
/// Empty buffers return false.
pub fn buf_filled_with(buf: &[u8], byte: u8) -> bool {
    !buf.is_empty() && buf.iter().all(|&b| b == byte)
}

/// Returns true if every character in the string is "printable":
/// ASCII 0x20..=0x7E, plus \t (0x09), \n (0x0A), \r (0x0D).
/// Empty strings return true.
pub fn is_printable_str(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, 0x20..=0x7E | 0x09 | 0x0A | 0x0D))
}

fn is_ascii_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
}

/// Extract ASCII printable strings of at least `min_len` characters.
/// Non-printable bytes and bytes >= 0x80 act as terminators.
pub fn extract_ascii_strings(buf: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut start = 0u64;

    for (i, &b) in buf.iter().enumerate() {
        if is_ascii_printable(b) {
            if current.is_empty() {
                start = i as u64;
            }
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                result.push(ExtractedString {
                    value: current.clone(),
                    offset: start,
                });
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        result.push(ExtractedString {
            value: current,
            offset: start,
        });
    }
    result
}

/// Extract UTF-16LE strings of at least `min_len` characters.
/// Each character is 2 bytes (low, high). Only characters where high byte == 0
/// and low byte is ASCII printable are accepted. \x00\x00 is a terminator.
/// Runs of repeating null bytes are skipped.
pub fn extract_unicode_strings(buf: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut start = 0u64;
    let mut i = 0;

    while i + 1 < buf.len() {
        let lo = buf[i];
        let hi = buf[i + 1];

        if lo == 0 && hi == 0 {
            // Null terminator
            if current.len() >= min_len {
                // Check the string wasn't from a run of repeating bytes
                if !buf_filled_with(&buf[start as usize..i], 0x00) {
                    result.push(ExtractedString {
                        value: current.clone(),
                        offset: start,
                    });
                }
            }
            current.clear();
            i += 2;
            continue;
        }

        if hi == 0 && is_ascii_printable(lo) {
            if current.is_empty() {
                start = i as u64;
            }
            current.push(lo as char);
        } else {
            // Invalid char - discard current string
            current.clear();
        }
        i += 2;
    }

    if current.len() >= min_len {
        if !buf_filled_with(&buf[start as usize..buf.len()], 0x00) {
            result.push(ExtractedString {
                value: current,
                offset: start,
            });
        }
    }

    result
}
