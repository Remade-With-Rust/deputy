use zeroize::{Zeroize, ZeroizeOnDrop};

/// The 256-bit master key derived from the user passphrase. Lives in memory only and
/// zeroizes on drop. It is never serialized, logged, or persisted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey(****)")
    }
}

/// A purpose-separated 256-bit subkey derived from the master key via HKDF. Used directly as
/// an AES-256-GCM key. Zeroizes on drop; never persisted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SubKey([u8; 32]);

impl SubKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy the raw 32-byte key out for interop with an external key provider — e.g. as the
    /// vault key (KEK) handed to SpaceDB's `KeyProvider`, which wraps a per-collection DEK under
    /// it. Use sparingly: this deliberately moves the key material out of the zeroizing wrapper.
    pub fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for SubKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SubKey(****)")
    }
}
