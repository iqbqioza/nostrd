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

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Heed(e) => Some(e),
            Error::Secp(e) => Some(e),
            Error::Hex(e) => Some(e),
            _ => None,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_every_variant() {
        let io = Error::Io(std::io::Error::other("io"));
        let json = Error::Json(serde_json::from_str::<()>("x").unwrap_err());
        let heed = Error::Heed(heed::Error::Mdb(heed::MdbError::NotFound));
        let secp = Error::Secp(secp256k1::Error::InvalidSignature);
        let hex = Error::Hex(hex::FromHexError::InvalidHexCharacter { c: 'z', index: 0 });
        for e in [
            &io,
            &json,
            &heed,
            &secp,
            &hex,
            &Error::Config("cfg".into()),
            &Error::Protocol("proto".into()),
            &Error::StorageFull,
            &Error::Other("other".into()),
        ] {
            let text = e.to_string();
            assert!(!text.is_empty(), "every variant must display something");
        }
    }

    #[test]
    fn source_reports_inner_errors() {
        let io = Error::Io(std::io::Error::other("io"));
        assert!(std::error::Error::source(&io).is_some());
        let hex = Error::Hex(hex::FromHexError::OddLength);
        assert!(std::error::Error::source(&hex).is_some());
        let config = Error::Config("x".into());
        assert!(
            std::error::Error::source(&config).is_none(),
            "String variants have no source"
        );
        assert!(std::error::Error::source(&Error::StorageFull).is_none());
    }

    #[test]
    fn conversions_build_the_right_variant() {
        let io: Error = std::io::Error::other("io").into();
        assert!(matches!(io, Error::Io(_)));
        let hex: Error = hex::FromHexError::OddLength.into();
        assert!(matches!(hex, Error::Hex(_)));
        let json: Error = serde_json::from_str::<()>("x").unwrap_err().into();
        assert!(matches!(json, Error::Json(_)));
    }
}
