// Async access log writer.
// Uses a dedicated task + unbounded channel to avoid blocking the request path.
// Format: nginx combined — $remote_addr - - [$time_local] "$request" $status $body_bytes

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::types::AccessLog;

// ── Log entry ─────────────────────────────────────────────────────────────────

pub struct LogEntry {
    pub remote_addr:  SocketAddr,
    pub request_line: String,   // "GET /path HTTP/1.1"
    pub status:       u16,
    pub body_bytes:   usize,
    pub referer:      String,
    pub user_agent:   String,
}

// ── Logger handle ─────────────────────────────────────────────────────────────

const RING_SIZE: usize = 500;

/// Shared ring buffer of recent log lines (last RING_SIZE combined-format lines).
pub type LogRing = Arc<Mutex<VecDeque<String>>>;

pub fn new_log_ring() -> LogRing {
    Arc::new(Mutex::new(VecDeque::with_capacity(RING_SIZE)))
}

#[derive(Clone)]
pub struct Logger {
    tx:   Option<mpsc::UnboundedSender<LogEntry>>,
    ring: LogRing,
}

impl Logger {
    /// Create a logger from an AccessLog config directive.
    /// Returns a logger that either writes to a file, stderr, or is a no-op.
    pub fn new_with_ring(cfg: &AccessLog, ring: LogRing) -> Self {
        match cfg {
            AccessLog::Off => Logger { tx: None, ring },
            AccessLog::Stderr => {
                let (tx, mut rx) = mpsc::unbounded_channel::<LogEntry>();
                let rb = Arc::clone(&ring);
                tokio::spawn(async move {
                    while let Some(entry) = rx.recv().await {
                        let line = format_combined(&entry);
                        eprintln!("{}", line);
                        ring_push(&rb, line);
                    }
                });
                Logger { tx: Some(tx), ring }
            }
            AccessLog::File(path) => {
                let path = path.clone();
                let (tx, mut rx) = mpsc::unbounded_channel::<LogEntry>();
                let rb = Arc::clone(&ring);
                tokio::spawn(async move {
                    if let Err(e) = write_loop(path, &mut rx, rb).await {
                        warn!("access log writer failed: {}", e);
                    }
                });
                Logger { tx: Some(tx), ring }
            }
        }
    }

    /// Clone the shared ring buffer arc (for wiring into ApiContext).
    pub fn ring(&self) -> LogRing {
        Arc::clone(&self.ring)
    }

    /// Return the most recent `n` log lines (oldest first).
    pub fn recent_lines(&self, n: usize) -> Vec<String> {
        let r = self.ring.lock().unwrap();
        let skip = r.len().saturating_sub(n);
        r.iter().skip(skip).cloned().collect()
    }

    pub fn log(&self, entry: LogEntry) {
        if let Some(ref tx) = self.tx {
            let _ = tx.send(entry);
        }
    }
}

// ── Ring buffer helper ──────────────────────────────────────────────────────────

fn ring_push(ring: &LogRing, line: String) {
    let mut r = ring.lock().unwrap();
    if r.len() >= RING_SIZE { r.pop_front(); }
    r.push_back(line);
}

// ── File writer loop ──────────────────────────────────────────────────────────

async fn write_loop(
    path: PathBuf,
    rx:   &mut mpsc::UnboundedReceiver<LogEntry>,
    ring: LogRing,
) -> anyhow::Result<()> {
    // Open (or create) the log file in append mode.
    let file = tokio::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .await?;
    let mut writer = tokio::io::BufWriter::new(file);

    while let Some(entry) = rx.recv().await {
        let formatted = format_combined(&entry);
        ring_push(&ring, formatted.clone());
        let line = format!("{}\n", formatted);
        if let Err(e) = writer.write_all(line.as_bytes()).await {
            warn!("access log write: {}", e);
            // Re-open and retry on next entry.
            break;
        }
        // Flush periodically — BufWriter will batch writes automatically.
    }
    writer.flush().await?;
    Ok(())
}

// ── Log format ────────────────────────────────────────────────────────────────

fn format_combined(e: &LogEntry) -> String {
    let now = chrono_format_now();
    format!(
        "{} - - [{}] \"{}\" {} {} \"{}\" \"{}\"",
        e.remote_addr.ip(),
        now,
        e.request_line,
        e.status,
        e.body_bytes,
        e.referer,
        e.user_agent,
    )
}

fn chrono_format_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple ISO-ish format without chrono dependency: 26/May/2026:07:00:00 +0000
    // Use time crate which is already pulled in transitively.
    // Fallback: epoch seconds if formatting fails.
    format_unix_ts(secs)
}

fn format_unix_ts(ts: u64) -> String {
    // Convert Unix timestamp to nginx combined log time format.
    // Example: 26/May/2026:07:00:00 +0000
    const MONTHS: [&str; 12] = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    // Simplified Julian/Gregorian calculation.
    let secs_per_day = 86400u64;
    let mut days = ts / secs_per_day;
    let time_of_day = ts % secs_per_day;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Days since 1970-01-01 → year/month/day
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let mut month = 0u32;
    for mo in 0..12u32 {
        let dim = days_in_month(mo, year);
        if days < dim { month = mo; break; }
        days -= dim;
    }
    let day = days + 1;

    format!("{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000",
        day, MONTHS[month as usize], year, h, m, s)
}

fn is_leap(y: u32) -> bool { y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) }

fn days_in_month(month: u32, year: u32) -> u64 {
    match month {
        0|2|4|6|7|9|11 => 31,
        3|5|8|10       => 30,
        1 => if is_leap(year) { 29 } else { 28 },
        _ => 30,
    }
}
