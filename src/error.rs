//! Error type shared across the crate.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Heed(heed::Error),
    Secp(secp256k1::Error),
    Hex(hex::FromHexError),
    Config(String),
    Protocol(String),
    /// The storage backend is out of space: the free space on the
    /// filesystem hosting the Blossom blobs dropped below
    /// `blossom.min_free_bytes`.
    StorageFull,
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Json(e) => write!(f, "json error: {e}"),
            Error::Heed(e) => write!(f, "database error: {e}"),
            Error::Secp(e) => write!(f, "crypto error: {e}"),
            Error::Hex(e) => write!(f, "hex error: {e}"),
            Error::Config(e) => write!(f, "config error: {e}"),
            Error::Protocol(e) => write!(f, "protocol error: {e}"),
            Error::StorageFull => write!(f, "storage is full"),
            Error::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<heed::Error> for Error {
    fn from(e: heed::Error) -> Self {
        Error::Heed(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp(e)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::Hex(e)
    }
}
