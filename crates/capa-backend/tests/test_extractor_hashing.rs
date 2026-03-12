// Port of capa/tests/test_extractor_hashing.py
//
// Tests sample hash extraction (MD5, SHA1, SHA256) for binary files,
// mirroring Python capa's SampleHashes / get_sample_hashes().

use std::path::PathBuf;

use capa_backend::{get_file_hashes, get_sample_hashes, SampleHashes};

/// Resolve a sample path relative to the workspace samples/ directory.
fn sample_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // workspace root
    p.push("samples");
    p.push(name);
    p
}

// ---------- Unit tests (no sample files needed) ----------

#[test]
fn test_hash_empty_bytes() {
    let h = get_sample_hashes(b"");
    assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(h.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        h.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_hash_known_bytes() {
    let h = get_sample_hashes(b"Hello, world!");
    assert_eq!(h.md5, "6cd3556deb0da54bca060b4c39479839");
    assert_eq!(h.sha1, "943a702d06f34599aee1f8da8ef9f7296031d699");
    assert_eq!(
        h.sha256,
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
    );
}

#[test]
fn test_sample_hashes_equality() {
    let a = SampleHashes {
        md5: "aaa".to_string(),
        sha1: "bbb".to_string(),
        sha256: "ccc".to_string(),
    };
    let b = SampleHashes {
        md5: "aaa".to_string(),
        sha1: "bbb".to_string(),
        sha256: "ccc".to_string(),
    };
    let c = SampleHashes {
        md5: "xxx".to_string(),
        sha1: "bbb".to_string(),
        sha256: "ccc".to_string(),
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------- Sample file hashing tests (port of test_extractor_hashing.py) ----------
// These mirror the Python tests: each extractor's get_sample_hashes() is replaced
// by our get_file_hashes() since the Rust backend uses a unified hashing path.

#[test]
fn test_dotnet_sample_hash_extraction() {
    let path = sample_path("dotnet");
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return;
    }
    assert_eq!(
        get_file_hashes(&path).unwrap(),
        SampleHashes {
            md5: "aa396d15d643b7a4993d016520acdf9e".to_string(),
            sha1: "442d03be21ab90e895c0f0a709870a14b18a0f82".to_string(),
            sha256: "10037d0b72adf8287e169f95da8d02ad5578a511a93974e3cd1a1177da4ee731".to_string(),
        }
    );
}

#[test]
fn test_elf_sample_hash_extraction() {
    let path = sample_path("elf");
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return;
    }
    assert_eq!(
        get_file_hashes(&path).unwrap(),
        SampleHashes {
            md5: "6f207e2a7d571bcf58239ce723cda186".to_string(),
            sha1: "8e68f3d2d444e9b0176c7566a4b19c4057b8fcf3".to_string(),
            sha256: "aeea7f349cf2bcbfa407f7cb34b5b7adaa1b0de1cb4e33e8f4c890af026c8316".to_string(),
        }
    );
}

#[test]
fn test_pe_sample_hash_extraction() {
    let path = sample_path("shellcode_beacon");
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return;
    }
    assert_eq!(
        get_file_hashes(&path).unwrap(),
        SampleHashes {
            md5: "94f6b55643b1ccec22d5194cc1e06195".to_string(),
            sha1: "113c96ae749635c9417c0ac1c878cd3f87740d1f".to_string(),
            sha256: "63101038b04ac1387a6e8849f6a9c7723120c748a57d663491f81e3b88b96f37".to_string(),
        }
    );
}

#[test]
fn test_pe_sample2_hash_extraction() {
    let path = sample_path("shellcode_beacon2");
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return;
    }
    assert_eq!(
        get_file_hashes(&path).unwrap(),
        SampleHashes {
            md5: "bb78e11f93e1cf0a1394026fad745249".to_string(),
            sha1: "19ad7a9282f0db2b2e7422ddcabc8f79e4a254ec".to_string(),
            sha256: "521dc30386c3192a26cd3e5efdacbe728dc9f4c02586865996571b87d76804b2".to_string(),
        }
    );
}

#[test]
fn test_golang_sample_hash_extraction() {
    let path = sample_path("golang");
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return;
    }
    assert_eq!(
        get_file_hashes(&path).unwrap(),
        SampleHashes {
            md5: "3f08e9817f973b656ab03b79390bf73b".to_string(),
            sha1: "7b29894a8395cca5b4899dc3e5d5f9266ea2cd0d".to_string(),
            sha256: "010793ae53772d29b026bc6a3860fc8c45f9dd480c02f950c87072ba1562256b".to_string(),
        }
    );
}

#[test]
fn test_graalvm_sample_hash_extraction() {
    let path = sample_path("graalvm");
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return;
    }
    assert_eq!(
        get_file_hashes(&path).unwrap(),
        SampleHashes {
            md5: "dd32d7233f5feccd3e8ea34ae09fe682".to_string(),
            sha1: "2bc247405355a5b54dccc04d1d0b5d5dd7516ede".to_string(),
            sha256: "f224b8db6ebd9845b9da8c22576854e39cd0ae10bab1e472be7891d241242648".to_string(),
        }
    );
}

// ---------- get_file_hashes error handling ----------

#[test]
fn test_hash_nonexistent_file() {
    let result = get_file_hashes(std::path::Path::new("/nonexistent/path/to/file"));
    assert!(result.is_err());
}

// ---------- Consistency: get_sample_hashes == get_file_hashes ----------

#[test]
fn test_hash_bytes_vs_file_consistency() {
    let path = sample_path("dotnet");
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return;
    }
    let bytes = std::fs::read(&path).unwrap();
    let from_bytes = get_sample_hashes(&bytes);
    let from_file = get_file_hashes(&path).unwrap();
    assert_eq!(from_bytes, from_file);
}
