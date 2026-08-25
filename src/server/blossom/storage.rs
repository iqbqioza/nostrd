//! Blossom blob storage: the `bucket/{npub1xxx}/{file}` layout on local
//! disk or in an S3-compatible bucket (AWS S3 / Cloudflare R2).
//!
//! The sha256 → owner mapping is **persisted in the relay database**
//! (LMDB, the `blossom` table): an upload writes the mapping first, and a
//! lookup reads it straight from LMDB — no in-memory index and no startup
//! scan, so lookups survive restarts, memory stays bounded and startup is
//! independent of the storage size. The blobs themselves are files in
//! `bucket/{npub1xxx}/{file}`; the multi-owner mapping lets every uploader
//! of identical content manage their own copy independently.

use std::path::{Path, PathBuf};

use crate::db::DbClient;
use crate::error::Result;

use super::s3::S3Client;

/// Metadata of a stored blob (the Blossom `BlobDescriptor` fields).
#[derive(Debug, Clone)]
pub(crate) struct Descriptor {
    pub sha256: String,
    pub size: u64,
    pub mime: String,
    pub uploaded: i64,
    /// The uploader's hex pubkey.
    pub pubkey: String,
}

impl Descriptor {
    pub(crate) fn npub(&self) -> String {
        npub_of(&self.pubkey)
    }
}

/// The file storage backend, chosen by `blossom.storage`.
enum Storage {
    Local(LocalStore),
    S3(S3Store),
}

/// Blob storage: the LMDB-persisted mapping plus the file backend.
pub(crate) struct BlobStore {
    storage: Storage,
    db: DbClient,
}

impl BlobStore {
    pub(crate) async fn new(
        storage: &str,
        local_path: &Path,
        s3: Option<S3Config>,
        db: DbClient,
    ) -> Result<BlobStore> {
        let storage = match storage {
            "local" => Storage::Local(LocalStore::new(local_path).await?),
            "s3" => Storage::S3(
                S3Store::new(s3.expect("s3 config validated by Config::validate")).await?,
            ),
            other => {
                return Err(crate::error::Error::Config(format!(
                    "unsupported blossom storage backend {other:?}"
                )));
            }
        };
        Ok(BlobStore { storage, db })
    }

    /// Stores a blob: the LMDB mapping first (so a crash leaves a healable
    /// state — a mapping without a file can be deleted), then the file.
    pub(crate) async fn put(
        &self,
        pubkey: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
    ) -> Result<Descriptor> {
        let uploaded = crate::util::unix_now() as i64;
        self.db
            .blossom_add_owner(sha256, mime, bytes.len() as u64, uploaded, pubkey)
            .await;
        let npub = npub_of(pubkey);
        match &self.storage {
            Storage::Local(s) => s.put(&npub, sha256, bytes, mime, uploaded).await?,
            Storage::S3(s) => s.put(&npub, sha256, bytes, mime, uploaded).await?,
        }
        Ok(Descriptor {
            sha256: sha256.to_string(),
            size: bytes.len() as u64,
            mime: mime.to_string(),
            uploaded,
            pubkey: pubkey.to_string(),
        })
    }

    /// Resolves a blob by its sha256 straight from LMDB.
    pub(crate) async fn find(&self, sha256: &str) -> Option<Descriptor> {
        let meta = self.db.blossom_load(sha256).await?;
        Some(Descriptor {
            sha256: meta.sha256,
            size: meta.size,
            mime: meta.mime,
            uploaded: meta.uploaded,
            pubkey: meta.owners.into_iter().next()?,
        })
    }

    /// Whether `pubkey` has uploaded this blob.
    pub(crate) async fn has(&self, pubkey: &str, sha256: &str) -> bool {
        self.db
            .blossom_load(sha256)
            .await
            .is_some_and(|meta| meta.owners.iter().any(|o| o == pubkey))
    }

    /// Reads the blob's bytes. `npub` comes from the resolved descriptor.
    pub(crate) async fn read(&self, npub: &str, sha256: &str) -> Result<Option<Vec<u8>>> {
        match &self.storage {
            Storage::Local(s) => s.read(npub, sha256).await,
            Storage::S3(s) => s.read(npub, sha256).await,
        }
    }

    /// Deletes the requester's copy: the file under their npub directory
    /// (blob first, so a crash leaves a healable state) and their entry in
    /// the LMDB mapping. Other uploaders of the same bytes keep theirs.
    pub(crate) async fn delete(&self, pubkey: &str, sha256: &str) -> Result<bool> {
        let npub = npub_of(pubkey);
        let existed = match &self.storage {
            Storage::Local(s) => s.delete(&npub, sha256).await?,
            Storage::S3(s) => s.delete(&npub, sha256).await?,
        };
        self.db.blossom_remove_owner(sha256, pubkey).await;
        Ok(existed)
    }

    /// One-time automatic migration: rebuilds the sha→owner mapping from
    /// blobs stored before the mapping existed (local files or bucket
    /// objects). Runs in the background at startup; the marker key makes
    /// it idempotent, so later restarts skip it instantly.
    pub(crate) async fn auto_migrate_legacy(&self) -> Result<usize> {
        if self.db.blossom_migration_done().await {
            return Ok(0);
        }
        let entries = match &self.storage {
            Storage::Local(s) => s.scan_legacy().await?,
            Storage::S3(s) => s.scan_legacy().await?,
        };
        let count = entries.len();
        // The writes are chunked: a legacy store with hundreds of
        // thousands of blobs must not hold one giant LMDB write
        // transaction (which would block the relay's event writes for the
        // whole duration of the migration).
        for chunk in entries.chunks(5000) {
            if !self.db.blossom_add_mappings(chunk.to_vec()).await {
                // The marker is not set: the migration retries on the next
                // startup (the failed chunk may need a bigger map).
                return Err(crate::error::Error::Other(
                    "blossom migration write failed; will retry on the next start".into(),
                ));
            }
        }
        self.db.mark_blossom_migration().await;
        Ok(count)
    }

    /// All blobs uploaded by `pubkey` (hex), via the persisted reverse
    /// index.
    pub(crate) async fn list(&self, pubkey: &str) -> Vec<Descriptor> {
        let mut out = Vec::new();
        for sha in self.db.blossom_list(pubkey).await {
            if let Some(desc) = self.find(&sha).await {
                out.push(desc);
            }
        }
        out
    }
}

/// Derives the uploader's hex pubkey from an npub directory name.
/// Shared with the automatic legacy migration.
pub(crate) fn npub_from_dir(dir: &Path) -> std::result::Result<String, ()> {
    let name = dir.file_name().and_then(|n| n.to_str()).ok_or(())?;
    if let Ok(crate::nips::nip19::Nip19Entity::Pubkey(pk)) = crate::nips::nip19::parse_nip19(name) {
        return Ok(hex::encode(pk));
    }
    if name.len() == 64 && hex::decode(name).is_ok() {
        return Ok(name.to_string());
    }
    Err(())
}

fn npub_of(pubkey: &str) -> String {
    match hex::decode(pubkey) {
        Ok(bytes) if bytes.len() == 32 => crate::nips::nip19::bech32m_encode("npub", &bytes)
            .unwrap_or_else(|_| pubkey.to_string()),
        _ => pubkey.to_string(),
    }
}

// ----- local storage --------------------------------------------------------

struct LocalStore {
    root: PathBuf,
}

impl LocalStore {
    async fn new(root: &Path) -> Result<LocalStore> {
        tokio::fs::create_dir_all(root).await?;
        Ok(LocalStore {
            root: root.to_path_buf(),
        })
    }

    fn blob_path(&self, npub: &str, sha256: &str) -> PathBuf {
        self.root.join(npub).join(sha256)
    }

    async fn put(
        &self,
        npub: &str,
        sha256: &str,
        bytes: &[u8],
        _mime: &str,
        _uploaded: i64,
    ) -> Result<()> {
        let dir = self.root.join(npub);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(self.blob_path(npub, sha256), bytes).await?;
        Ok(())
    }

    async fn read(&self, npub: &str, sha256: &str) -> Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.blob_path(npub, sha256)).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn delete(&self, npub: &str, sha256: &str) -> Result<bool> {
        let path = self.blob_path(npub, sha256);
        let existed = tokio::fs::try_exists(&path).await.unwrap_or(false);
        let _ = tokio::fs::remove_file(&path).await;
        Ok(existed)
    }

    /// Scans `<root>/<npub>/<sha>.meta.json` for the legacy migration.
    async fn scan_legacy(&self) -> Result<Vec<(String, String, u64, i64, String)>> {
        let mut out = Vec::new();
        // Metas take precedence: a sha found via its meta is not derived
        // again from the raw blob. A set keeps this O(n) for big stores.
        let mut via_meta: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut dirs = tokio::fs::read_dir(&self.root).await?;
        while let Some(entry) = dirs.next_entry().await? {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let Ok(pubkey) = npub_from_dir(&dir) else {
                continue;
            };
            // Pass 1: legacy meta files carry the full descriptor.
            let mut files = match tokio::fs::read_dir(&dir).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            while let Some(file) = files.next_entry().await? {
                let name = file.file_name().to_string_lossy().into_owned();
                let Some(sha) = name.strip_suffix(".meta.json") else {
                    continue;
                };
                if let Ok(raw) = tokio::fs::read(file.path()).await
                    && let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&raw)
                {
                    out.push((
                        sha.to_string(),
                        crate::server::blossom::sanitize_mime(meta["mime"].as_str().unwrap_or("")),
                        meta["size"].as_u64().unwrap_or(0),
                        meta["uploaded"].as_i64().unwrap_or(0),
                        pubkey.clone(),
                    ));
                    via_meta.insert(sha.to_string());
                }
            }
            // Pass 2: blobs without a meta (written after the metadata
            // moved to LMDB) are derived from the file itself.
            let mut files = match tokio::fs::read_dir(&dir).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            while let Some(file) = files.next_entry().await? {
                let name = file.file_name().to_string_lossy().into_owned();
                if name.len() != 64 || hex::decode(&name).is_err() || via_meta.contains(&name) {
                    continue;
                }
                let (size, uploaded) = match tokio::fs::metadata(file.path()).await {
                    Ok(meta) => (
                        meta.len(),
                        meta.modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0),
                    ),
                    Err(_) => continue,
                };
                out.push((
                    name,
                    "application/octet-stream".to_string(),
                    size,
                    uploaded,
                    pubkey.clone(),
                ));
            }
        }
        Ok(out)
    }
}

// ----- S3 / R2 storage ------------------------------------------------------

pub(crate) struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

struct S3Store {
    client: S3Client,
}

impl S3Store {
    async fn new(cfg: S3Config) -> Result<S3Store> {
        Ok(S3Store {
            client: S3Client::new(
                &cfg.endpoint,
                &cfg.region,
                &cfg.bucket,
                &cfg.access_key,
                &cfg.secret_key,
            ),
        })
    }

    async fn put(
        &self,
        npub: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
        _uploaded: i64,
    ) -> Result<()> {
        self.client
            .put_object(&format!("{npub}/{sha256}"), bytes, mime)
            .await
    }

    async fn read(&self, npub: &str, sha256: &str) -> Result<Option<Vec<u8>>> {
        match self.client.get_object(&format!("{npub}/{sha256}")).await? {
            Some(bytes) => Ok(Some(bytes)),
            None => Ok(None),
        }
    }

    async fn delete(&self, npub: &str, sha256: &str) -> Result<bool> {
        // The blob is removed first: a crash in between leaves the LMDB
        // mapping (a later delete cleans it up), never an invisible
        // orphan object.
        let existed = self
            .client
            .delete_object(&format!("{npub}/{sha256}"))
            .await?;
        Ok(existed)
    }

    /// Lists the bucket and fetches the meta objects (bounded parallelism)
    /// for the legacy migration.
    async fn scan_legacy(&self) -> Result<Vec<(String, String, u64, i64, String)>> {
        let keys = self.client.list_keys("").await?;
        // Only the legacy meta objects are fetched (small): the sizes of
        // the blob objects come straight from the listing, so a bucket
        // with many blobs is not downloaded during the migration.
        let mut out = Vec::new();
        let mut via_meta: std::collections::HashSet<String> = std::collections::HashSet::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
        let mut tasks = tokio::task::JoinSet::new();
        for (key, size) in keys {
            let (npub, file) = match key.split_once('/') {
                Some((n, f)) => (n, f),
                None => continue,
            };
            let Ok(pubkey) = npub_from_dir(std::path::Path::new(npub)) else {
                continue;
            };
            if let Some(sha) = file.strip_suffix(".meta.json") {
                via_meta.insert(sha.to_string());
                let client = self.client.clone();
                let semaphore = std::sync::Arc::clone(&semaphore);
                tasks.spawn(async move {
                    let _permit = semaphore.acquire().await;
                    let raw = client.get_object(&key).await;
                    (key, pubkey, raw)
                });
                continue;
            }
            // Blobs without a meta (metadata moved to LMDB): the size
            // comes from the listing; mime falls back to octet-stream.
            if file.len() == 64 && hex::decode(file).is_ok() {
                out.push((
                    file.to_string(),
                    "application/octet-stream".to_string(),
                    size,
                    0,
                    pubkey,
                ));
            }
        }
        while let Some(Ok((key, pubkey, raw))) = tasks.join_next().await {
            let Some(sha) = key
                .strip_suffix(".meta.json")
                .and_then(|k| k.split_once('/'))
                .map(|(_, f)| f)
            else {
                continue;
            };
            if let Ok(Some(raw)) = raw
                && let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&raw)
            {
                out.push((
                    sha.to_string(),
                    crate::server::blossom::sanitize_mime(meta["mime"].as_str().unwrap_or("")),
                    meta["size"].as_u64().unwrap_or(0),
                    meta["uploaded"].as_i64().unwrap_or(0),
                    pubkey,
                ));
            }
        }
        // The derived entries must not duplicate meta-backed ones.
        out.retain(|(sha, _, _, _, _)| !via_meta.contains(sha));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(i: u8) -> String {
        format!("{:02x}", i).repeat(32)
    }

    async fn db(tmp: &str) -> (DbClient, std::path::PathBuf) {
        let cfg = crate::config::DatabaseConfig {
            path: std::env::temp_dir().join(format!(
                "nostrd-blossom-store-test-{tmp}-{}",
                std::process::id()
            )),
            ..Default::default()
        };
        let _ = std::fs::remove_dir_all(&cfg.path);
        let db = DbClient::open(
            &cfg,
            false,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        (db, cfg.path)
    }

    async fn store(tmp: &str) -> (BlobStore, std::path::PathBuf) {
        let (db, db_path) = db(tmp).await;
        let dir =
            std::env::temp_dir().join(format!("nostrd-blossom-test-{tmp}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = BlobStore::new("local", &dir, None, db).await.unwrap();
        (s, db_path)
    }

    #[tokio::test]
    async fn multi_owner_put_find_list_delete() {
        let (s, _db_path) = store("multi").await;
        let a = pk(1);
        let b = pk(2);
        let sha = "ab".repeat(32);
        let bytes = b"hello blossom";

        let da = s.put(&a, &sha, bytes, "text/plain").await.unwrap();
        assert_eq!(da.pubkey, a);
        // Same bytes by another pubkey: both become owners.
        let db = s.put(&b, &sha, bytes, "text/plain").await.unwrap();
        assert_eq!(db.pubkey, b);

        assert_eq!(s.find(&sha).await.unwrap().pubkey, a);
        assert!(s.has(&a, &sha).await);
        assert!(s.has(&b, &sha).await);
        assert!(!s.has(&pk(3), &sha).await);
        assert_eq!(s.list(&a).await.len(), 1);
        assert_eq!(s.list(&b).await.len(), 1);
        assert_eq!(s.list(&pk(3)).await.len(), 0);

        let npub_a = npub_of(&a);
        let npub_b = npub_of(&b);
        assert_eq!(s.read(&npub_a, &sha).await.unwrap().unwrap(), bytes);
        assert_eq!(s.read(&npub_b, &sha).await.unwrap().unwrap(), bytes);

        // One owner deletes: the other owner's copy survives.
        assert!(s.delete(&b, &sha).await.unwrap());
        assert!(s.find(&sha).await.is_some());
        assert!(s.read(&npub_a, &sha).await.unwrap().is_some());
        assert!(s.read(&npub_b, &sha).await.unwrap().is_none());
        assert!(!s.has(&b, &sha).await);
        assert!(s.has(&a, &sha).await);
        assert_eq!(s.list(&a).await.len(), 1);
        assert_eq!(s.list(&b).await.len(), 0);

        // The last owner's delete removes the mapping.
        assert!(s.delete(&a, &sha).await.unwrap());
        assert!(s.find(&sha).await.is_none());
    }

    #[tokio::test]
    async fn mapping_survives_reopen() {
        // The mapping lives in LMDB: a reopened store (new process, no
        // scan, no index) resolves everything.
        let (db, db_path) = db("reopen").await;
        let dir =
            std::env::temp_dir().join(format!("nostrd-blossom-test-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = BlobStore::new("local", &dir, None, db).await.unwrap();
            let sha = "cd".repeat(32);
            s.put(&pk(1), &sha, b"x", "image/png").await.unwrap();
            s.put(&pk(2), &sha, b"x", "image/png").await.unwrap();
            let sha2 = "ef".repeat(32);
            s.put(&pk(1), &sha2, b"y", "text/plain").await.unwrap();
        }
        let db = DbClient::open(
            &crate::config::DatabaseConfig {
                path: db_path,
                ..Default::default()
            },
            false,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let s = BlobStore::new("local", &dir, None, db).await.unwrap();
        let sha = "cd".repeat(32);
        assert_eq!(s.find(&sha).await.unwrap().pubkey, pk(1));
        assert!(s.has(&pk(1), &sha).await);
        assert!(s.has(&pk(2), &sha).await);
        assert_eq!(s.list(&pk(1)).await.len(), 2);
        assert_eq!(s.list(&pk(2)).await.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn auto_migration_merges_multi_owner_blobs() {
        let (db, db_path) = db("mig2").await;
        let dir =
            std::env::temp_dir().join(format!("nostrd-blossom-test-mig2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // レガシー: 同一 blob が 2 つの npub ディレクトリに存在（メタあり）
        let sha = "dd".repeat(32);
        for pk in [pk(1), pk(2)] {
            let npub = npub_of(&pk);
            let npub_dir = dir.join(&npub);
            std::fs::create_dir_all(&npub_dir).unwrap();
            std::fs::write(npub_dir.join(&sha), b"x").unwrap();
            std::fs::write(
                npub_dir.join(format!("{sha}.meta.json")),
                br#"{"sha256":"dddd","size":1,"mime":"image/png","uploaded":1787000000}"#,
            )
            .unwrap();
        }
        let s = BlobStore::new("local", &dir, None, db).await.unwrap();
        let migrated = s.auto_migrate_legacy().await.unwrap();
        assert_eq!(migrated, 2, "both owners are mapped");
        assert!(s.has(&pk(1), &sha).await);
        assert!(
            s.has(&pk(2), &sha).await,
            "second owner survives the migration"
        );
        assert_eq!(s.list(&pk(1)).await.len(), 1);
        assert_eq!(s.list(&pk(2)).await.len(), 1);
        // 一人削除してももう一人は残る
        assert!(s.delete(&pk(1), &sha).await.unwrap());
        assert!(s.find(&sha).await.is_some());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = db_path;
    }

    #[test]
    fn npub_of_roundtrip() {
        let hex = pk(7);
        let npub = npub_of(&hex);
        assert!(npub.starts_with("npub1"));
        assert_eq!(npub_of(&hex), npub, "stable");
    }
}

#[cfg(test)]
mod scan_debug {
    use super::*;

    #[tokio::test]
    async fn scan_legacy_finds_legacy_files() {
        let dir =
            std::env::temp_dir().join(format!("nostrd-blossom-scan-debug-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The directory name comes from the same npub_of() the uploads use
        // (bech32m) — never handcraft a checksum in the test.
        let npub = npub_of(&"01".repeat(32));
        let npub_dir = dir.join(&npub);
        std::fs::create_dir_all(&npub_dir).unwrap();
        std::fs::write(
            npub_dir.join("34f66c6a736a7ee87f5f908bbc48e651f94bcdc4c5d3006dbaa4d8fa5fa4cf5a"),
            b"x",
        )
        .unwrap();
        std::fs::write(
            npub_dir.join("34f66c6a736a7ee87f5f908bbc48e651f94bcdc4c5d3006dbaa4d8fa5fa4cf5a.meta.json"),
            br#"{"sha256":"34f66c6a736a7ee87f5f908bbc48e651f94bcdc4c5d3006dbaa4d8fa5fa4cf5a","size":1,"mime":"image/png","uploaded":1787000000}"#,
        ).unwrap();
        assert!(
            npub_from_dir(&npub_dir).is_ok(),
            "npub_from_dir must accept the bech32m npub"
        );
        let s = LocalStore::new(&dir).await.unwrap();
        let entries = s.scan_legacy().await.unwrap();
        assert_eq!(entries.len(), 1, "scan must find the legacy meta");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
