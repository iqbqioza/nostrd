//! Small shared helpers without a natural home elsewhere.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current Unix timestamp in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
