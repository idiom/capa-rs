//! Sample hashing utilities
//!
//! Computes MD5, SHA1, and SHA256 hashes for binary samples,
//! matching Python capa's `SampleHashes` / `get_sample_hashes()`.

use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Digest;

/// Hashes for a binary sample
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Compute MD5, SHA1, and SHA256 hashes of raw bytes.
pub fn get_sample_hashes(bytes: &[u8]) -> SampleHashes {
    let md5 = format!("{:x}", Md5::digest(bytes));
    let sha1 = format!("{:x}", Sha1::digest(bytes));
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    SampleHashes { md5, sha1, sha256 }
}

/// Compute hashes from a file path.
pub fn get_file_hashes(path: &std::path::Path) -> std::io::Result<SampleHashes> {
    let bytes = std::fs::read(path)?;
    Ok(get_sample_hashes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let h = get_sample_hashes(b"");
        // Well-known hashes of empty input
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(h.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_known_input() {
        let h = get_sample_hashes(b"Hello, world!");
        assert_eq!(h.md5, "6cd3556deb0da54bca060b4c39479839");
        assert_eq!(h.sha1, "943a702d06f34599aee1f8da8ef9f7296031d699");
        assert_eq!(
            h.sha256,
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        );
    }
}
