//! Erasure-coded vault snapshots (SpaceDB Layer 2, cold path).
//!
//! A snapshot archives the vault's already-encrypted files into one blob, compresses
//! it with rusty_zstd, Reed-Solomon erasure-codes it into `data + parity` shards, and
//! writes the manifest + shards out (oxicode on the internal wire). Up to `parity`
//! shards can be lost and the vault still reconstructs from any `data` of them.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;
use spacedb_durability::{encode_snapshot, reconstruct_snapshot, Manifest, Shard};

use crate::error::{Result, StoreError};

/// Summary of a snapshot run.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub total_shards: usize,
    pub archive_bytes: usize,
}

/// Summary of a restore run.
#[derive(Debug, Clone)]
pub struct RestoreInfo {
    pub shards_used: usize,
    pub files_restored: usize,
}

const ZSTD_LEVEL: i32 = 3;

fn snap_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Snapshot(e.to_string())
}

fn wire_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    oxicode::serde::encode_to_vec(value, oxicode::config::standard()).map_err(snap_err)
}

fn wire_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, _) =
        oxicode::serde::decode_from_slice(bytes, oxicode::config::standard()).map_err(snap_err)?;
    Ok(value)
}

fn pack(bytes: &[u8]) -> Result<Vec<u8>> {
    rusty_zstd::compress(bytes, ZSTD_LEVEL).map_err(snap_err)
}

fn unpack(bytes: &[u8]) -> Result<Vec<u8>> {
    rusty_zstd::decompress(bytes).map_err(snap_err)
}

/// Snapshot the vault at `vault_root` into `out_dir` as `data_shards + parity_shards` shards
/// (tolerating up to `parity_shards` lost shards).
pub fn snapshot(
    vault_root: &Path,
    out_dir: &Path,
    data_shards: usize,
    parity_shards: usize,
) -> Result<SnapshotInfo> {
    let archive = archive_dir(vault_root)?;
    let encoded = wire_encode(&archive)?;
    let blob = pack(&encoded)?;
    let (manifest, shards) =
        encode_snapshot(&blob, data_shards, parity_shards).map_err(snap_err)?;

    fs::create_dir_all(out_dir)?;
    fs::write(out_dir.join("manifest.bin"), wire_encode(&manifest)?)?;
    for shard in &shards {
        let bytes = wire_encode(shard)?;
        fs::write(out_dir.join(format!("shard-{:03}.bin", shard.index)), bytes)?;
    }

    Ok(SnapshotInfo {
        data_shards,
        parity_shards,
        total_shards: shards.len(),
        archive_bytes: blob.len(),
    })
}

/// Restore a snapshot from `snapshot_dir` into `vault_root` (which must not already hold a
/// vault). Reconstructs from whatever shards are present, as long as at least `data_shards`
/// remain.
pub fn restore(snapshot_dir: &Path, vault_root: &Path) -> Result<RestoreInfo> {
    let manifest: Manifest = wire_decode(&fs::read(snapshot_dir.join("manifest.bin"))?)?;

    let mut shards = Vec::new();
    for entry in fs::read_dir(snapshot_dir)? {
        let path = entry?.path();
        let is_shard = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("shard-") && n.ends_with(".bin"));
        if is_shard {
            shards.push(wire_decode::<Shard>(&fs::read(&path)?)?);
        }
    }

    let blob = reconstruct_snapshot(&manifest, &shards).map_err(snap_err)?;
    let encoded = unpack(&blob)?;
    let archive: BTreeMap<String, Vec<u8>> = wire_decode(&encoded)?;
    let files_restored = archive.len();
    unarchive_dir(&archive, vault_root)?;

    Ok(RestoreInfo {
        shards_used: shards.len(),
        files_restored,
    })
}

/// Recursively read every file under `root` into a relative-path → bytes map.
fn archive_dir(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    collect(root, root, &mut files)?;
    Ok(files)
}

fn collect(base: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(base, &path, files)?;
        } else {
            let rel = path
                .strip_prefix(base)
                .map_err(snap_err)?
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(rel, fs::read(&path)?);
        }
    }
    Ok(())
}

fn unarchive_dir(files: &BTreeMap<String, Vec<u8>>, root: &Path) -> Result<()> {
    for (rel, data) in files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, data)?;
    }
    Ok(())
}
