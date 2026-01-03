use std::{env, path::PathBuf, process::Command};

fn main() {
    // Rebuild if BPF crate changes
    println!("cargo:rerun-if-changed=../io-scope-ebpf/src/lib.rs");
    println!("cargo:rerun-if-changed=../io-scope-ebpf/Cargo.toml");

    // Build io-scope-ebpf for bpf target
    let status = Command::new("cargo")
        .args([
            "-Z",
            "unstable-options",
            "-C",
            "../io-scope-ebpf",
            "build-ebpf",
            "--release",
        ])
        .status()
        .expect("failed to run cargo build for eBPF");

    if !status.success() {
        panic!("eBPF build failed");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("echo {:?}", out_dir);

    let bpf_src = PathBuf::from("../target/bpfel-unknown-none/release/libio_scope_ebpf.so");
    let bpf_dst = out_dir.join("io-scope-ebpf.so");

    std::fs::copy(&bpf_src, &bpf_dst).expect("Failed to copy BPF object");

    println!(
        "cargo:rustc-env=IO_SCOPE_EBPF_PATH={}",
        bpf_dst.to_string_lossy()
    );
}
