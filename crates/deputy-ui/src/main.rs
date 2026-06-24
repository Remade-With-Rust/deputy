//! # deputy-ui
//!
//! Dioxus web app — a pure HTTP client of the Deputy API (`deputy-api`). It signs in with mID,
//! then drives the pipeline (discover / analyze / scan / gate) against `http://127.0.0.1:7878`.
//!
//! Build and serve it with `dx serve --platform web` from this crate (start the API first with
//! `deputy serve`). On non-wasm targets the crate is a stub so `cargo build --workspace` stays
//! green; the real app lives in [`app`] behind `cfg(target_arch = "wasm32")`.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
mod app;

#[cfg(target_arch = "wasm32")]
fn main() {
    app::launch();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!(
        "deputy-ui is a WebAssembly app.\n\
         Run it with:  dx serve --platform web   (from crates/deputy-ui)\n\
         It talks to the Deputy API at http://127.0.0.1:7878 — start that with `deputy serve`."
    );
}
