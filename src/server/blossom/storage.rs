//! Blossom blob storage: the `bucket/{npub1xxx}/{file}` layout on local
//! disk or in an S3-compatible bucket (AWS S3 / Cloudflare R2).
//!
//! Files are content-addressed by their SHA-256 and stored under the
//! uploader's npub directory. An in-memory index (`sha256 → descriptors`,
//! one per uploader of the same bytes) is warmed at startup (scanning the
//! local directories or listing the bucket) and kept in sync at runtime,
//! so `GET /<sha256>` resolves in O(1) without scanning directories on
//! every request. The multi-owner list lets every uploader of identical
//! content manage their own copy independently.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::error::Result;

use super::s3::S3Client;

/// The in-memory index: sha256 → one descriptor per uploader.
type Index = HashMap<String, Vec<Descriptor>>;

/// Metadata of a stored blob (the Blossom `BlobDescriptor` fields).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
        crate::nips::nip19::bech32m_encode("npub", &hex::decode(&self.pubkey).unwrap_or_default())
            .unwrap_or_else(|_| self.pubkey.clone())
    }
}

/// The storage backend, chosen by `blossom.storage`.
pub(crate) enum BlobStore {
    Local(LocalStore),
    S3(S3Store),
}

impl BlobStore {
    /// Creates the store and warms the in-memory index from existing files.
    pub(crate) async fn new(
        storage: &str,
        local_path: &Path,
        s3: Option<S3Config>,
    ) -> Result<BlobStore> {
        let (store, index) = match storage {
            "local" => {
                let store = LocalStore::new(local_path).await?;
                let index = store.scan().await?;
                (BlobStore::Local(store), index)
            }
            "s3" => {
                let cfg = s3.expect("s3 config validated by Config::validate");
                let store = S3Store::new(cfg).await?;
                let index = store.scan().await?;
                (BlobStore::S3(store), index)
            }
            other => {
                return Err(crate::error::Error::Config(format!(
                    "unsupported blossom storage backend {other:?}"
                )));
            }
        };
        Ok(store.with_index(index))
    }

    fn with_index(self, index: Index) -> BlobStore {
        let index = Arc::new(Mutex::new(index));
        match self {
            BlobStore::Local(mut s) => {
                s.index = Arc::clone(&index);
                BlobStore::Local(s)
            }
            BlobStore::S3(mut s) => {
                s.index = Arc::clone(&index);
                BlobStore::S3(s)
            }
        }
    }

    /// Stores a blob under `npub_dir/<sha256>` and records it in the index.
    /// `pubkey` is the uploader's hex pubkey.
    pub(crate) async fn put(
        &self,
        pubkey: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
    ) -> Result<Descriptor> {
        let npub = npub_of(pubkey);
        let uploaded = crate::util::unix_now() as i64;
        match self {
            BlobStore::Local(s) => s.put(&npub, sha256, bytes, mime, uploaded).await?,
            BlobStore::S3(s) => s.put(&npub, sha256, bytes, mime, uploaded).await?,
        }
        let descriptor = Descriptor {
            sha256: sha256.to_string(),
            size: bytes.len() as u64,
            mime: mime.to_string(),
            uploaded,
            pubkey: pubkey.to_string(),
        };
        // Content-addressed: identical bytes uploaded again (by the same
        // or another pubkey) keep every uploader's descriptor, so each
        // owner can manage their own copy.
        let mut index = self.index().lock().await;
        let owners = index.entry(sha256.to_string()).or_default();
        if !owners.iter().any(|d| d.pubkey == pubkey) {
            owners.push(descriptor.clone());
        }
        Ok(descriptor)
    }

    /// Resolves a blob by its sha256 (O(1) via the index).
    pub(crate) async fn find(&self, sha256: &str) -> Option<Descriptor> {
        self.index()
            .lock()
            .await
            .get(sha256)
            .and_then(|owners| owners.first())
            .cloned()
    }

    /// Whether `pubkey` has uploaded this blob.
    pub(crate) async fn has(&self, pubkey: &str, sha256: &str) -> bool {
        self.index()
            .lock()
            .await
            .get(sha256)
            .is_some_and(|owners| owners.iter().any(|d| d.pubkey == pubkey))
    }

    /// Reads the blob's bytes. `npub` comes from the resolved descriptor.
    pub(crate) async fn read(&self, npub: &str, sha256: &str) -> Result<Option<Vec<u8>>> {
        match self {
            BlobStore::Local(s) => s.read(npub, sha256).await,
            BlobStore::S3(s) => s.read(npub, sha256).await,
        }
    }

    /// Deletes the requester's copy of a blob: the file under their npub
    /// directory and their descriptor in the index. Other uploaders of the
    /// same bytes keep their own copies.
    pub(crate) async fn delete(&self, pubkey: &str, sha256: &str) -> Result<bool> {
        let npub = npub_of(pubkey);
        let existed = match self {
            BlobStore::Local(s) => s.delete(&npub, sha256).await?,
            BlobStore::S3(s) => s.delete(&npub, sha256).await?,
        };
        let mut index = self.index().lock().await;
        if let Some(owners) = index.get_mut(sha256) {
            owners.retain(|d| d.pubkey != pubkey);
            if owners.is_empty() {
                index.remove(sha256);
            }
        }
        Ok(existed)
    }

    /// All blobs uploaded by `pubkey` (hex).
    pub(crate) async fn list(&self, pubkey: &str) -> Vec<Descriptor> {
        let npub = npub_of(pubkey);
        self.index()
            .lock()
            .await
            .values()
            .flat_map(|owners| owners.iter())
            .filter(|d| d.npub() == npub)
            .cloned()
            .collect()
    }

    fn index(&self) -> &Mutex<Index> {
        match self {
            BlobStore::Local(s) => &s.index,
            BlobStore::S3(s) => &s.index,
        }
    }
}

fn npub_of(pubkey: &str) -> String {
    match hex::decode(pubkey) {
        Ok(bytes) if bytes.len() == 32 => crate::nips::nip19::bech32m_encode("npub", &bytes)
            .unwrap_or_else(|_| pubkey.to_string()),
        _ => pubkey.to_string(),
    }
}

// ----- local storage --------------------------------------------------------

pub(crate) struct LocalStore {
    root: PathBuf,
    index: Arc<Mutex<Index>>,
}

impl LocalStore {
    async fn new(root: &Path) -> Result<LocalStore> {
        tokio::fs::create_dir_all(root).await?;
        Ok(LocalStore {
            root: root.to_path_buf(),
            index: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn blob_path(&self, npub: &str, sha256: &str) -> PathBuf {
        self.root.join(npub).join(sha256)
    }

    fn meta_path(&self, npub: &str, sha256: &str) -> PathBuf {
        self.root.join(npub).join(format!("{sha256}.meta.json"))
    }

    async fn put(
        &self,
        npub: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
        uploaded: i64,
    ) -> Result<()> {
        let dir = self.root.join(npub);
        tokio::fs::create_dir_all(&dir).await?;
        // Write the meta first, then the blob, so a crash never leaves a
        // blob without its descriptor.
        let meta = serde_json::to_vec(&serde_json::json!({
            "sha256": sha256, "size": bytes.len(), "mime": mime, "uploaded": uploaded,
        }))?;
        tokio::fs::write(self.meta_path(npub, sha256), meta).await?;
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
        let _ = tokio::fs::remove_file(self.meta_path(npub, sha256)).await;
        Ok(existed)
    }

    /// Warms the index by scanning `<root>/<npub>/<sha256>.meta.json`.
    async fn scan(&self) -> Result<Index> {
        let mut index = Index::new();
        let mut dirs = tokio::fs::read_dir(&self.root).await?;
        while let Some(entry) = dirs.next_entry().await? {
            let npub_dir = entry.path();
            let Ok(pubkey) = npub_from_dir(&npub_dir) else {
                continue;
            };
            let mut files = match tokio::fs::read_dir(&npub_dir).await {
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
                    index.entry(sha.to_string()).or_default().push(Descriptor {
                        sha256: sha.to_string(),
                        size: meta["size"].as_u64().unwrap_or(0),
                        mime: meta["mime"].as_str().unwrap_or("").to_string(),
                        uploaded: meta["uploaded"].as_i64().unwrap_or(0),
                        pubkey: pubkey.clone(),
                    });
                }
            }
        }
        Ok(index)
    }
}

/// Derives the uploader's hex pubkey from an npub directory name.
fn npub_from_dir(dir: &Path) -> std::result::Result<String, ()> {
    let name = dir.file_name().and_then(|n| n.to_str()).ok_or(())?;
    if let Ok(crate::nips::nip19::Nip19Entity::Pubkey(pk)) = crate::nips::nip19::parse_nip19(name) {
        return Ok(hex::encode(pk));
    }
    // A directory named with a plain hex pubkey is also accepted.
    if name.len() == 64 && hex::decode(name).is_ok() {
        return Ok(name.to_string());
    }
    Err(())
}

// ----- S3 / R2 storage ------------------------------------------------------

pub(crate) struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

pub(crate) struct S3Store {
    client: S3Client,
    index: Arc<Mutex<Index>>,
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
            index: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn meta_key(&self, npub: &str, sha256: &str) -> String {
        format!("{npub}/{sha256}.meta.json")
    }

    async fn put(
        &self,
        npub: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
        uploaded: i64,
    ) -> Result<()> {
        let meta = serde_json::to_vec(&serde_json::json!({
            "sha256": sha256, "size": bytes.len(), "mime": mime, "uploaded": uploaded,
        }))?;
        self.client
            .put_object(&self.meta_key(npub, sha256), &meta, "application/json")
            .await?;
        self.client
            .put_object(&format!("{npub}/{sha256}"), bytes, mime)
            .await?;
        Ok(())
    }

    async fn read(&self, npub: &str, sha256: &str) -> Result<Option<Vec<u8>>> {
        match self.client.get_object(&format!("{npub}/{sha256}")).await? {
            Some(bytes) => Ok(Some(bytes)),
            None => Ok(None),
        }
    }

    async fn delete(&self, npub: &str, sha256: &str) -> Result<bool> {
        let _ = self
            .client
            .delete_object(&self.meta_key(npub, sha256))
            .await?;
        self.client.delete_object(&format!("{npub}/{sha256}")).await
    }

    /// Warms the index by listing the bucket and reading the meta objects.
    async fn scan(&self) -> Result<Index> {
        let mut index = Index::new();
        let entries = self.client.list_objects("").await?;
        for (key, _, _) in entries {
            let Some(meta) = key.strip_suffix(".meta.json") else {
                continue;
            };
            let (npub, sha) = match meta.split_once('/') {
                Some((n, s)) => (n, s),
                None => continue,
            };
            let Ok(pubkey) = npub_from_dir(std::path::Path::new(npub)) else {
                continue;
            };
            if let Ok(Some(raw)) = self.client.get_object(&key).await
                && let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&raw)
            {
                index.entry(sha.to_string()).or_default().push(Descriptor {
                    sha256: sha.to_string(),
                    size: meta["size"].as_u64().unwrap_or(0),
                    mime: meta["mime"].as_str().unwrap_or("").to_string(),
                    uploaded: meta["uploaded"].as_i64().unwrap_or(0),
                    pubkey,
                });
            }
        }
        Ok(index)
    }
}
