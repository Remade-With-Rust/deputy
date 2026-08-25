//! # deputy-alloc
//!
//! The one-crate allocator seam. Deliverables (`deputy-cli`, `deputy-ui`) declare
//! [`Alloc`] as `#[global_allocator]` exactly once. Library crates must not depend
//! on `rusty_alloc-api` directly — they go through this crate if they need the type,
//! and they never install the global allocator.
//!
//! [`configure`] turns **purging** on for long-lived processes (the API server and
//! the desktop app). Purging is opt-in in rusty_alloc; without it RSS is unbounded
//! on a soak. CLIs and one-shots stay on the short-lived default.

/// The process-wide allocator handle (zero-sized).
pub use rusty_alloc_api::RustyAlloc as Alloc;

/// rusty_alloc option index for `purge_delay` (mimalloc v2.4.5 ABI order).
const PURGE_DELAY: usize = 15;

/// How this process uses the heap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Daemons, the HTTP API, the desktop app — turn purging on so RSS stays flat.
    LongLived,
    /// CLIs and one-shots — leave purging off (the rusty_alloc default).
    ShortLived,
}

/// Apply the allocator profile. Call once at the start of `main`.
///
/// Long-lived processes set `purge_delay` to 10 ms (mimalloc's historical default)
/// so empty pages are returned to the OS. Short-lived processes leave the built-in
/// opt-out (`-1`) in place.
pub fn configure(profile: Profile) {
    match profile {
        Profile::LongLived => rusty_alloc::options::set(PURGE_DELAY, 10),
        Profile::ShortLived => rusty_alloc::options::set(PURGE_DELAY, -1),
    }
}
