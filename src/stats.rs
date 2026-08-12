use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

#[derive(Debug, Default)]
pub struct Stats {
    pub started_at: AtomicU64,
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub subscriptions_total: AtomicU64,
    pub subscriptions_active: AtomicU64,
    pub events_received: AtomicU64,
    pub events_accepted: AtomicU64,
    pub events_rejected: AtomicU64,
    pub events_duplicate: AtomicU64,
    pub events_deleted: AtomicU64,
    pub messages_in: AtomicU64,
    pub messages_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub buffers_dropped: AtomicU64,
    pub db_errors: AtomicU64,
    pub db_size_bytes: AtomicU64,
}

impl Stats {
    pub fn new() -> Arc<Stats> {
        let stats = Stats::default();
        stats.started_at.store(unix_now(), Ordering::Relaxed);
        Arc::new(stats)
    }

    pub fn bump(&self, counter: &AtomicU64, delta: u64) {
        counter.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn as_json(&self) -> Value {
        json!({
            "started_at": self.started_at.load(Ordering::Relaxed),
            "uptime_secs": unix_now().saturating_sub(self.started_at.load(Ordering::Relaxed)),
            "connections": {
                "active": self.connections_active.load(Ordering::Relaxed),
                "total": self.connections_total.load(Ordering::Relaxed),
            },
            "subscriptions": {
                "active": self.subscriptions_active.load(Ordering::Relaxed),
                "total": self.subscriptions_total.load(Ordering::Relaxed),
            },
            "events": {
                "received": self.events_received.load(Ordering::Relaxed),
                "accepted": self.events_accepted.load(Ordering::Relaxed),
                "rejected": self.events_rejected.load(Ordering::Relaxed),
                "duplicate": self.events_duplicate.load(Ordering::Relaxed),
                "deleted": self.events_deleted.load(Ordering::Relaxed),
            },
            "messages": {
                "in": self.messages_in.load(Ordering::Relaxed),
                "out": self.messages_out.load(Ordering::Relaxed),
            },
            "bytes": {
                "in": self.bytes_in.load(Ordering::Relaxed),
                "out": self.bytes_out.load(Ordering::Relaxed),
            },
            "buffers_dropped": self.buffers_dropped.load(Ordering::Relaxed),
            "db_errors": self.db_errors.load(Ordering::Relaxed),
            "db_size_bytes": self.db_size_bytes.load(Ordering::Relaxed),
        })
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
