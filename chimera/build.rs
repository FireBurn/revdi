//! Only does anything for the `revdi` feature: points the linker at `library/target/{release,debug}`
//! so `#[link(name = "evdi")]` in `src/revdi.rs` resolves without a system-wide `libevdi` install.
fn main() {
    if std::env::var("CARGO_FEATURE_REVDI").is_err() {
        return;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR unset");
    let base = std::path::Path::new(&manifest_dir).join("../library/target");
    for profile in ["release", "debug"] {
        let dir = base.join(profile);
        if dir.join("libevdi.so").exists() {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
    }
    println!("cargo:rustc-link-lib=dylib=evdi");
    println!("cargo:rerun-if-changed=build.rs");
}
