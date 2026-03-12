// Port of capa/tests/test_strings.py

use capa_backend::strings::{buf_filled_with, extract_ascii_strings, extract_unicode_strings, is_printable_str, ExtractedString};

// ---------- test_buf_filled_with ----------

#[test]
fn test_buf_filled_with_zeros() {
    assert!(buf_filled_with(&[0x00; 8], 0x00));
}

#[test]
fn test_buf_filled_with_ff() {
    assert!(buf_filled_with(&[0xFF; 8], 0xFF));
}

#[test]
fn test_buf_filled_with_mixed_bytes() {
    let buf: Vec<u8> = [0x00, 0x01].iter().copied().cycle().take(16).collect();
    assert!(!buf_filled_with(&buf, 0x00));
}

#[test]
fn test_buf_filled_with_abcd_pattern() {
    let buf: Vec<u8> = b"ABCD".iter().copied().cycle().take(32).collect();
    assert!(!buf_filled_with(&buf, b'A'));
}

#[test]
fn test_buf_filled_with_empty() {
    assert!(!buf_filled_with(b"", 0x00));
}

#[test]
fn test_buf_filled_with_single_byte() {
    assert!(buf_filled_with(&[0x00], 0x00));
}

// ---------- test_extract_ascii_strings ----------

#[test]
fn test_extract_ascii_empty() {
    assert!(extract_ascii_strings(b"", 4).is_empty());
}

#[test]
fn test_extract_ascii_two_strings() {
    let buf = b"Hello World\x00This is a test\x00";
    let strings = extract_ascii_strings(buf, 4);
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0], ExtractedString { value: "Hello World".to_string(), offset: 0 });
    assert_eq!(strings[1], ExtractedString { value: "This is a test".to_string(), offset: 12 });
}

#[test]
fn test_extract_ascii_min_length() {
    let buf = b"Hi\x00Test\x00";
    let strings = extract_ascii_strings(buf, 4);
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0], ExtractedString { value: "Test".to_string(), offset: 3 });
}

#[test]
fn test_extract_ascii_non_ascii_terminator() {
    let buf = b"Hello\xffWorld\x00";
    let strings = extract_ascii_strings(buf, 4);
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0], ExtractedString { value: "Hello".to_string(), offset: 0 });
    assert_eq!(strings[1], ExtractedString { value: "World".to_string(), offset: 6 });
}

#[test]
fn test_extract_ascii_only_non_ascii() {
    assert!(extract_ascii_strings(b"\xff\xff\xff", 4).is_empty());
}

#[test]
fn test_extract_ascii_null_padding() {
    let mut buf = vec![0x00u8; 8];
    buf.extend_from_slice(b"ValidString\x00");
    let strings = extract_ascii_strings(&buf, 4);
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0], ExtractedString { value: "ValidString".to_string(), offset: 8 });
}

// ---------- test_extract_unicode_strings ----------

#[test]
fn test_extract_unicode_hello() {
    let buf = b"H\x00e\x00l\x00l\x00o\x00\x00\x00";
    let strings = extract_unicode_strings(buf, 4);
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0], ExtractedString { value: "Hello".to_string(), offset: 0 });
}

#[test]
fn test_extract_unicode_min_length() {
    let buf = b"H\x00i\x00\x00\x00T\x00e\x00s\x00t\x00\x00\x00";
    let strings = extract_unicode_strings(buf, 4);
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0], ExtractedString { value: "Test".to_string(), offset: 6 });
}

#[test]
fn test_extract_unicode_invalid_sequences() {
    // H\x00 then \xff\x00 (non-ASCII high byte invalidates)
    let buf = b"H\x00\xff\x00l\x00l\x00o\x00\x00\x00";
    let strings = extract_unicode_strings(buf, 4);
    assert_eq!(strings.len(), 0);
}

#[test]
fn test_extract_unicode_null_padding() {
    let mut buf = vec![0x00u8; 8];
    buf.extend_from_slice(b"V\x00a\x00l\x00i\x00d\x00\x00\x00");
    let strings = extract_unicode_strings(&buf, 4);
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0], ExtractedString { value: "Valid".to_string(), offset: 8 });
}

// ---------- test_is_printable_str ----------

#[test]
fn test_printable_hello() {
    assert!(is_printable_str("Hello World"));
}

#[test]
fn test_printable_special() {
    assert!(is_printable_str("123!@#"));
}

#[test]
fn test_printable_whitespace() {
    assert!(is_printable_str("\t\n\r"));
}

#[test]
fn test_not_printable_control() {
    assert!(!is_printable_str("\x00\x01\x02"));
}

#[test]
fn test_not_printable_bell() {
    assert!(!is_printable_str("Hello\x07World"));
}

#[test]
fn test_not_printable_ansi_escape() {
    assert!(!is_printable_str("\x1b[31m"));
}

#[test]
fn test_printable_empty() {
    assert!(is_printable_str(""));
}

#[test]
fn test_printable_space() {
    assert!(is_printable_str(" "));
}

#[test]
fn test_not_printable_del() {
    assert!(!is_printable_str("\x7f"));
}
