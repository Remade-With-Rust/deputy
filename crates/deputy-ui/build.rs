//! Build script — embeds `Info.plist` into the macOS desktop binary.
//!
//! Without this, a `cargo run` Mach-O has no `CFBundleURLTypes`, so the OS won't route
//! `deputy://` deep links (the mID sign-in callback) to it. We add the plist via the
//! `__TEXT,__info_plist` linker section. Gated on the **target** OS (`CARGO_CFG_TARGET_OS`) so the
//! wasm32 web build — which runs this script on a macOS host — is never affected.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        // Resolve relative to the crate (the linker's CWD varies), so the path is always found.
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is always set during build");
        let plist_path = format!("{manifest_dir}/Info.plist");
        if std::path::Path::new(&plist_path).exists() {
            println!("cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__info_plist,{plist_path}");
            println!("cargo:rerun-if-changed=Info.plist");
        }
    }
}
