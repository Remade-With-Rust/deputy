use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use deputy_crypto::{open, seal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, StoreError};
use crate::vault::Vault;

/// The sealed-on-disk plaintext of one audit record. Each entry chains to the previous via
/// `prev_hex`, and its own hash anchors the next entry — so any reordering, omission, or edit
/// breaks the chain (`docs/STORAGE.md` §5).
#[derive(Serialize, Deserialize)]
struct AuditPlain {
    seq: u64,
    prev_hex: String,
    kind: String,
    payload: serde_json::Value,
}

/// A verified audit-log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hex: String,
    pub this_hex: String,
    pub kind: String,
    pub payload: serde_json::Value,
}

fn genesis_prev() -> String {
    "0".repeat(64)
}

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest.as_slice() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl Vault {
    fn audit_path(&self) -> PathBuf {
        self.root().join("logs").join("audit.log")
    }

    /// Append a record to the hash-chained audit log and return the verified entry. Re-reads
    /// and verifies the existing chain first, so a corrupted log cannot be silently extended.
    pub fn audit_append(&self, kind: &str, payload: serde_json::Value) -> Result<AuditEntry> {
        let entries = self.audit_entries()?;
        let (seq, prev_hex) = match entries.last() {
            Some(last) => (last.seq + 1, last.this_hex.clone()),
            None => (0, genesis_prev()),
        };

        let plain = AuditPlain {
            seq,
            prev_hex: prev_hex.clone(),
            kind: kind.to_owned(),
            payload,
        };
        let plain_bytes = serde_json::to_vec(&plain)?;
        let this_hex = hex_sha256(&plain_bytes);

        let sealed = seal(self.audit_key(), &plain_bytes, &seq.to_be_bytes())?;
        self.append_frame(&sealed)?;

        Ok(AuditEntry {
            seq,
            prev_hex,
            this_hex,
            kind: plain.kind,
            payload: plain.payload,
        })
    }

    /// Read and verify the entire audit chain, returning every entry in order. Fails with
    /// [`StoreError::AuditChain`] at the first record whose decryption, sequence, or back-link
    /// does not check out.
    pub fn audit_entries(&self) -> Result<Vec<AuditEntry>> {
        let data = match fs::read(self.audit_path()) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut entries = Vec::new();
        let mut cursor = 0usize;
        let mut expected_seq = 0u64;
        let mut expected_prev = genesis_prev();

        while cursor < data.len() {
            if cursor + 4 > data.len() {
                return Err(StoreError::AuditChain { seq: expected_seq });
            }
            let len = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            if cursor + len > data.len() {
                return Err(StoreError::AuditChain { seq: expected_seq });
            }
            let sealed = &data[cursor..cursor + len];
            cursor += len;

            // The AAD is the expected sequence number, so a record moved to a different position
            // fails to decrypt — reordering is caught here, not just by the back-link check.
            let plain_bytes = open(self.audit_key(), sealed, &expected_seq.to_be_bytes())
                .map_err(|_| StoreError::AuditChain { seq: expected_seq })?;
            let plain: AuditPlain = serde_json::from_slice(&plain_bytes)
                .map_err(|_| StoreError::AuditChain { seq: expected_seq })?;
            if plain.seq != expected_seq || plain.prev_hex != expected_prev {
                return Err(StoreError::AuditChain { seq: expected_seq });
            }

            let this_hex = hex_sha256(&plain_bytes);
            entries.push(AuditEntry {
                seq: plain.seq,
                prev_hex: plain.prev_hex,
                this_hex: this_hex.clone(),
                kind: plain.kind,
                payload: plain.payload,
            });
            expected_prev = this_hex;
            expected_seq += 1;
        }

        Ok(entries)
    }

    /// Verify the audit chain and return the number of entries.
    pub fn audit_verify(&self) -> Result<u64> {
        Ok(self.audit_entries()?.len() as u64)
    }

    fn append_frame(&self, sealed: &[u8]) -> Result<()> {
        let path = self.audit_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut framed = Vec::with_capacity(4 + sealed.len());
        framed.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        framed.extend_from_slice(sealed);

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(&framed)?;
        file.sync_all()?;
        Ok(())
    }
}
