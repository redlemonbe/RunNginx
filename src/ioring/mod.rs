// io_uring file-read service.
//
// Architecture:
//   - N worker threads (N = min(cpus, 4)), each owning one IoUring ring.
//   - Requests arrive via std::sync::mpsc (non-blocking try_send from tokio).
//   - Results return via tokio::sync::oneshot (Sender::send is sync, safe from any thread).
//   - Caller falls back to tokio::fs if the queue is full or the feature is off.
//
// Limitations:
//   - Sequential within each worker (one SQE at a time). Future: batch multiple ops.
//   - Files > MAX_IORING_FILE_BYTES fall back to tokio::fs to avoid large buffer alloc.

#[cfg(feature = "io_uring")]
pub use enabled::{init, read_file};
#[cfg(not(feature = "io_uring"))]
pub use disabled::read_file;

const MAX_IORING_FILE_BYTES: usize = 4 * 1024 * 1024; // 4 MB

// ── Enabled path ──────────────────────────────────────────────────────────────

#[cfg(feature = "io_uring")]
mod enabled {
    use super::MAX_IORING_FILE_BYTES;

    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{mpsc, OnceLock};

    use io_uring::{IoUring, opcode, types};
    use tracing::{debug, warn};

    struct ReadRequest {
        path: PathBuf,
        tx:   tokio::sync::oneshot::Sender<io::Result<Vec<u8>>>,
    }

    static POOL: OnceLock<mpsc::SyncSender<ReadRequest>> = OnceLock::new();

    /// Spawn worker threads. Call once at startup.
    pub fn init() {
        let n_workers = std::cmp::min(num_cpus::get(), 4);
        let (tx, rx) = mpsc::sync_channel::<ReadRequest>(512);
        POOL.get_or_init(|| tx);

        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        for i in 0..n_workers {
            let rx = std::sync::Arc::clone(&rx);
            std::thread::Builder::new()
                .name(format!("runnginx-ioring-{}", i))
                .spawn(move || worker(rx))
                .expect("failed to spawn io_uring worker");
        }
    }

    fn worker(rx: std::sync::Arc<std::sync::Mutex<mpsc::Receiver<ReadRequest>>>) {
        let mut ring = match IoUring::new(64) {
            Ok(r) => r,
            Err(e) => {
                warn!("io_uring unavailable: {} — file reads will use tokio::fs fallback", e);
                return;
            }
        };
        loop {
            let req = {
                let guard = rx.lock().unwrap();
                match guard.recv() {
                    Ok(r) => r,
                    Err(_) => return, // channel closed
                }
            };
            let result = read_file_uring(&mut ring, &req.path);
            let _ = req.tx.send(result);
        }
    }

    fn read_file_uring(ring: &mut IoUring, path: &Path) -> io::Result<Vec<u8>> {
        // stat first (fast, avoids over-allocating for the read buffer)
        let meta = std::fs::metadata(path)?;
        let size = meta.len() as usize;
        if size == 0 { return Ok(Vec::new()); }
        if size > MAX_IORING_FILE_BYTES {
            // Large file: skip io_uring and use regular blocking read.
            return std::fs::read(path);
        }

        let path_cstr = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "null byte in path"))?;

        // ── openat ────────────────────────────────────────────────────────────
        const AT_FDCWD: i32 = -100;
        const O_RDONLY: i32 = 0;
        const O_CLOEXEC: i32 = 0o200_0000; // 0x80000

        let open_op = opcode::OpenAt::new(types::Fd(AT_FDCWD), path_cstr.as_ptr())
            .flags(O_RDONLY | O_CLOEXEC)
            .build()
            .user_data(0x01);

        // SAFETY: path_cstr lives for the duration of the submission.
        unsafe { ring.submission().push(&open_op) }
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "ring full"))?;
        ring.submit_and_wait(1)?;

        let fd = {
            let cqe = ring.completion().next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no CQE"))?;
            let r = cqe.result();
            if r < 0 { return Err(io::Error::from_raw_os_error(-r)); }
            r
        };

        // ── read ──────────────────────────────────────────────────────────────
        let mut buf = vec![0u8; size];

        let read_op = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), size as u32)
            .build()
            .user_data(0x02);

        // SAFETY: buf lives for the duration of the submission.
        unsafe { ring.submission().push(&read_op) }
            .map_err(|_| {
                unsafe { close_fd(fd); }
                io::Error::new(io::ErrorKind::Other, "ring full on read")
            })?;
        ring.submit_and_wait(1)?;

        let n = {
            let cqe = ring.completion().next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no read CQE"))?;
            let r = cqe.result();
            unsafe { close_fd(fd); }
            if r < 0 { return Err(io::Error::from_raw_os_error(-r)); }
            r as usize
        };

        buf.truncate(n);
        Ok(buf)
    }

    unsafe fn close_fd(fd: i32) {
        // Use io_uring close or direct syscall. Direct syscall is simpler here.
        libc::close(fd);
    }

    /// Read a file, using the io_uring pool if available, falling back to tokio::fs.
    pub async fn read_file(path: &Path) -> io::Result<Vec<u8>> {
        // Large files skip the pool.
        if let Ok(m) = std::fs::metadata(path) {
            if m.len() > MAX_IORING_FILE_BYTES as u64 {
                return tokio::fs::read(path).await;
            }
        }

        if let Some(tx) = POOL.get() {
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            let req = ReadRequest { path: path.to_path_buf(), tx: resp_tx };
            match tx.try_send(req) {
                Ok(()) => {
                    return resp_rx.await
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "io_uring pool gone"))?;
                }
                Err(e) => {
                    debug!("io_uring pool full ({}), falling back to tokio::fs", e);
                }
            }
        }
        tokio::fs::read(path).await
    }
}

// ── Disabled path (no-op, delegates to tokio::fs) ─────────────────────────────

#[cfg(not(feature = "io_uring"))]
mod disabled {
    use std::io;
    use std::path::Path;

    pub async fn read_file(path: &Path) -> io::Result<Vec<u8>> {
        tokio::fs::read(path).await
    }
}
