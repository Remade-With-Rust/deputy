use std::collections::HashSet;
use std::sync::Mutex;

/// A single-use nonce store. Deputy issues a nonce per sign-in (embedded in the mID request)
/// and consumes it when the returned token is verified; a second presentation of the same
/// nonce fails, defeating token replay (`docs/AUTH.md` §5). The verifier only checks nonce
/// *equality* — single-use enforcement is this store's job.
pub trait NonceStore: Send + Sync {
    /// Issue and record a fresh single-use nonce.
    fn issue(&self) -> String;
    /// Consume a nonce. Returns `true` iff it had been issued and not yet used.
    fn consume(&self, nonce: &str) -> bool;
}

/// Process-local [`NonceStore`]. A persistent implementation arrives with the API layer.
#[derive(Default)]
pub struct InMemoryNonceStore {
    live: Mutex<HashSet<String>>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn issue(&self) -> String {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("OS RNG must be available to issue a nonce");
        let nonce = to_hex(&bytes);
        self.live
            .lock()
            .expect("nonce mutex poisoned")
            .insert(nonce.clone());
        nonce
    }

    fn consume(&self, nonce: &str) -> bool {
        self.live
            .lock()
            .expect("nonce mutex poisoned")
            .remove(nonce)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
