use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use autocxx_bindgen::Builder as BindgenBuilder;

/// IDA SDK GitHub repository (public since IDA 9.2).
const IDA_SDK_REPO: &str = "https://github.com/HexRaysSA/ida-sdk.git";

/// Default SDK git tag, matching the idalib-sys package version (9.2).
const IDA_SDK_DEFAULT_TAG: &str = "v9.2";

fn configure_and_generate(builder: BindgenBuilder, ida: &Path, output: impl AsRef<Path>) {
    let rs = PathBuf::from(env::var("OUT_DIR").unwrap()).join(output.as_ref());
    let bindings = builder
        .clang_arg("-xc++")
        .clang_arg(format!("-I{}", ida.display()))
        .clang_args(
            #[cfg(target_os = "linux")]
            &["-std=c++17", "-D__LINUX__=1", "-D__EA64__=1"],
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            &["-std=c++17", "-D__MACOS__=1", "-D__ARM__=1", "-D__EA64__=1"],
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            &["-std=c++17", "-D__MACOS__=1", "-D__EA64__=1"],
            #[cfg(target_os = "windows")]
            &["-std=c++17", "-D__NT__=1", "-D__EA64__=1"],
        )
        .respect_cxx_access_specs(true)
        .generate()
        .expect("generate bindings");

    bindings.write_to_file(rs).expect("write bindings");
}

/// Resolve the IDA SDK path, auto-fetching from GitHub if necessary.
fn resolve_sdk_path() -> PathBuf {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR should be set"));

    // 1. Explicit override via environment variable
    if let Ok(sdk_root) = env::var("IDASDK_ROOT") {
        let sdk_path = PathBuf::from(&sdk_root);
        if sdk_path.join("include").join("pro.h").exists() {
            println!("cargo::warning=Using IDA SDK from IDASDK_ROOT={}", sdk_root);
            return sdk_path;
        }
        let src_path = sdk_path.join("src");
        if src_path.join("include").join("pro.h").exists() {
            println!("cargo::warning=Using IDA SDK from IDASDK_ROOT={}/src", sdk_root);
            return src_path;
        }
        panic!("IDASDK_ROOT={} does not contain include/pro.h.", sdk_root);
    }

    // 2. Git submodule at sdk/src
    let submodule_path = manifest_dir.join("sdk").join("src");
    if submodule_path.join("include").join("pro.h").exists() {
        return submodule_path;
    }

    // Try initializing the submodule
    if manifest_dir.join("..").join(".gitmodules").exists() {
        println!("cargo::warning=IDA SDK submodule not initialized, attempting git submodule update...");
        let status = Command::new("git")
            .args(["submodule", "update", "--init", "--depth", "1", "idalib-sys/sdk"])
            .current_dir(manifest_dir.join(".."))
            .status();
        if let Ok(s) = status {
            if s.success() && submodule_path.join("include").join("pro.h").exists() {
                println!("cargo::warning=IDA SDK submodule initialized successfully.");
                return submodule_path;
            }
        }
    }

    // 3. Auto-fetch from GitHub
    let sdk_tag = env::var("IDASDK_GIT_TAG").unwrap_or_else(|_| IDA_SDK_DEFAULT_TAG.to_string());
    let cache_dir = out_dir
        .parent().and_then(|p| p.parent()).and_then(|p| p.parent())
        .map(|p| p.join("ida-sdk-cache"))
        .unwrap_or_else(|| out_dir.join("ida-sdk-cache"));
    let cached_sdk = cache_dir.join("src");

    if cached_sdk.join("include").join("pro.h").exists() {
        return cached_sdk;
    }

    println!("cargo::warning=Auto-fetching IDA SDK {} (tag {}) ...", IDA_SDK_REPO, sdk_tag);
    if cache_dir.exists() { let _ = std::fs::remove_dir_all(&cache_dir); }

    let status = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", &sdk_tag, IDA_SDK_REPO, &cache_dir.display().to_string()])
        .status()
        .expect("failed to run git");

    if !status.success() {
        panic!("Failed to clone IDA SDK from {} (tag {}).", IDA_SDK_REPO, sdk_tag);
    }

    assert!(cached_sdk.join("include").join("pro.h").exists(), "SDK cloned but pro.h not found");
    cached_sdk
}

fn main() {
    let sdk_path = resolve_sdk_path();
    let ida = sdk_path.join("include");

    cxx_build::CFG.exported_header_dirs.push(&ida);

    let ffi_path = Path::new("src");

    let mut builder = autocxx_build::Builder::new(ffi_path.join("lib.rs"), [ffi_path, &*ida])
        .extra_clang_args(
            #[cfg(target_os = "linux")]
            &["-std=c++17", "-D__LINUX__=1", "-D__EA64__=1"],
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            &["-std=c++17", "-D__MACOS__=1", "-D__ARM__=1", "-D__EA64__=1"],
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            &["-std=c++17", "-D__MACOS__=1", "-D__EA64__=1"],
            #[cfg(target_os = "windows")]
            &["-std=c++17", "-D__NT__=1", "-D__EA64__=1"],
        )
        .build()
        .expect("parsed correctly");

    #[cfg(target_os = "linux")]
    {
        builder
            .cargo_warnings(false)
            .flag_if_supported("-std=c++17")
            .define("__LINUX__", "1")
            .define("__EA64__", "1")
            .compile("libida-stubs");
    }

    #[cfg(target_os = "macos")]
    {
        let b = builder
            .cargo_warnings(false)
            .flag_if_supported("-std=c++17")
            .define("__MACOS__", "1")
            .define("__EA64__", "1");

        #[cfg(target_arch = "aarch64")]
        let b = b.define("__ARM__", "1");

        b.compile("libida-stubs");
    }

    #[cfg(target_os = "windows")]
    {
        builder
            .cargo_warnings(false)
            .cpp(true)
            .std("c++17")
            .define("__NT__", "1")
            .define("__EA64__", "1")
            .compile("libida-stubs");
    }

    let pod = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("ua.hpp").to_str().expect("path is valid string"))
        .allowlist_type("insn_t")
        .allowlist_type("op_t")
        .allowlist_type("optype_t")
        .allowlist_item("OF_.*");

    configure_and_generate(pod, &ida, "pod.rs");

    let idp = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("idp.hpp").to_str().expect("path is valid string"))
        .allowlist_item("PLFM_.*");

    configure_and_generate(idp, &ida, "idp.rs");

    let inf = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("ida.hpp").to_str().expect("path is valid string"))
        .header(
            ida.join("typeinf.hpp")
                .to_str()
                .expect("path is valid string"),
        )
        .allowlist_item("AF_.*")
        .allowlist_item("AF2_.*")
        .allowlist_item("CM_.*")
        .allowlist_item("COMP_.*")
        .allowlist_item("INFFL_.*")
        .allowlist_item("LFLG_.*")
        .allowlist_item("STT_.*")
        .allowlist_item("SW_.*")
        .allowlist_item("compiler_info_t");

    configure_and_generate(inf, &ida, "inf.rs");

    let insn_consts = [
        ("ARM_.*", "insn_arm.rs"),
        ("NN_.*", "insn_x86.rs"),
        ("MIPS_.*", "insn_mips.rs"),
    ];

    for (prefix, output) in insn_consts {
        let arch = autocxx_bindgen::builder()
            .header(ida.join("pro.h").to_str().expect("path is valid string"))
            .header(
                ida.join("allins.hpp")
                    .to_str()
                    .expect("path is a valid string"),
            )
            .clang_arg("-fshort-enums")
            .allowlist_item(prefix);

        configure_and_generate(arch, &ida, output);
    }

    let hexrays = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(
            ida.join("hexrays.hpp")
                .to_str()
                .expect("path is valid string"),
        )
        .opaque_type("std::.*")
        .opaque_type("carglist_t")
        .allowlist_item("cfunc_t")
        .allowlist_item("citem_t")
        .allowlist_item("cexpr_t")
        .allowlist_item("cinsn_t")
        .allowlist_item("cblock_t")
        .allowlist_item("cswitch_t")
        .allowlist_item("ctry_t")
        .allowlist_item("cthrow_t")
        .allowlist_item("cnumber_t")
        .allowlist_item("lvar_t")
        .allowlist_item("lvar_locator_t")
        .allowlist_item("vdloc_t")
        .allowlist_item("CV_.*")
        .allowlist_item("DECOMP_.*");

    configure_and_generate(hexrays, &ida, "hexrays.rs");

    println!("cargo::metadata=sdk={}", sdk_path.display());

    println!(
        "cargo::rerun-if-changed={}",
        ffi_path.join("lib.rs").display()
    );
}
