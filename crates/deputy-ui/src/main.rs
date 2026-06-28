//! # deputy-ui
//!
//! Dioxus app — a thin client of the Deputy API (`deputy-api`). It signs in with mID, then drives
//! the pipeline (discover / analyze / scan / gate) against `http://127.0.0.1:7878`.
//!
//! Two platforms, one [`app`]:
//! - **Web (WASM):** `dx serve --platform web` — renders in the browser, talks to the API via the
//!   browser's fetch.
//! - **Desktop (native):** `dx serve --platform desktop` (or `cargo run --features desktop`) —
//!   renders in a native window, talks to the API via reqwest.
//!
//! Either way, start the API first with `deputy serve`. With no platform feature on a non-wasm
//! host the crate is just a stub `main`, so `cargo build --workspace` stays light and green.
#![forbid(unsafe_code)]

#[cfg(any(target_arch = "wasm32", feature = "desktop"))]
mod app;

// Web (WASM) entry point.
#[cfg(target_arch = "wasm32")]
fn main() {
    app::launch();
}

// Desktop (native) entry point — a self-contained app. It opens (or creates on first run) the
// local vault, starts the embedded Deputy API on a background thread, then opens the native
// window. Persistence is the same `~/.deputy` SpaceDB vault the CLI uses — no separate
// `deputy serve` needed. `dioxus::launch` opens a desktop window because `dioxus/desktop` is on.
#[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
fn main() {
    let dir = match deputy_api::default_vault_dir() {
        Some(d) => d,
        None => {
            eprintln!("deputy-ui: couldn't resolve a home directory — set DEPUTY_VAULT to a path.");
            std::process::exit(1);
        }
    };
    let passphrase = std::env::var("DEPUTY_PASSPHRASE").unwrap_or_default();
    if passphrase.trim().is_empty() {
        eprintln!(
            "deputy-ui: set DEPUTY_PASSPHRASE to unlock (or create) the vault at {}.",
            dir.display()
        );
        std::process::exit(1);
    }
    let service = match deputy_api::open_or_create_local(&dir, passphrase.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("deputy-ui: {e:?}");
            std::process::exit(1);
        }
    };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 7878));
    eprintln!(
        "deputy-ui: vault {} — embedded API on http://{addr}",
        dir.display()
    );
    std::thread::spawn(move || {
        if let Err(e) = deputy_api::serve_blocking(service, addr) {
            eprintln!("deputy-ui: embedded API stopped: {e}");
        }
    });
    app::launch();
}

// Host build with no platform feature: a stub so `cargo build --workspace` stays green.
#[cfg(all(not(target_arch = "wasm32"), not(feature = "desktop")))]
fn main() {
    eprintln!(
        "deputy-ui needs a platform.\n\
         Web:     dx serve --platform web\n\
         Desktop: dx serve --platform desktop   (or: cargo run -p deputy-ui --features desktop)\n\
         Either way, start the API first with `deputy serve`."
    );
}
