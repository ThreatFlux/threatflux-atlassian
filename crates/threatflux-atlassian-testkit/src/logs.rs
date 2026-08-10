//! Captures `tracing` output into a buffer a test can assert on.

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, Mutex, Once};

use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;

/// A shared buffer that a `tracing` subscriber writes into.
#[derive(Debug, Clone, Default)]
pub struct LogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    /// Creates an empty capture buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns everything written so far.
    ///
    /// Invalid UTF-8 is replaced rather than rejected: a leak test must be able
    /// to scan whatever the formatter emitted, including a mangled byte string.
    ///
    /// # Panics
    ///
    /// Panics if the buffer lock was poisoned by a panicking test.
    pub fn contents(&self) -> String {
        let buffer = self
            .buffer
            .lock()
            .expect("log buffer lock should not be poisoned");
        String::from_utf8_lossy(&buffer).into_owned()
    }

    /// Builds a subscriber that writes into this buffer.
    ///
    /// The level is pinned to `TRACE` so a redaction sweep sees the most verbose
    /// output the code can produce, not the default filter's subset.
    pub fn subscriber(&self) -> impl Subscriber + Send + Sync + 'static {
        tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .finish()
    }
}

impl<'writer> MakeWriter<'writer> for LogCapture {
    type Writer = SharedWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        SharedWriter(Arc::clone(&self.buffer))
    }
}

/// The writer handed to a `tracing` subscriber by [`LogCapture`].
#[derive(Debug)]
pub struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        {
            let mut buffer = self
                .0
                .lock()
                .map_err(|_| io::Error::other("log buffer lock poisoned"))?;
            buffer.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

thread_local! {
    /// The buffer the capture running on this thread writes into, if any.
    static ACTIVE: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
}

/// Sends a formatted event to whichever capture is active on the emitting thread.
///
/// An event raised on a thread with no capture active is dropped.
#[derive(Debug)]
pub struct RoutedWriter;

impl io::Write for RoutedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        ACTIVE.with(|slot| {
            if let Some(buffer) = slot.borrow().as_ref() {
                if let Ok(mut buffer) = buffer.lock() {
                    buffer.extend_from_slice(buf);
                }
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Points this thread at `buffer` until dropped, then restores the previous one.
struct Active(Option<Arc<Mutex<Vec<u8>>>>);

impl Active {
    fn install(buffer: Arc<Mutex<Vec<u8>>>) -> Self {
        Self(ACTIVE.with(|slot| slot.replace(Some(buffer))))
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        let previous = self.0.take();
        ACTIVE.with(|slot| *slot.borrow_mut() = previous);
    }
}

/// Installs the one dispatcher every capture shares.
///
/// `tracing` caches each callsite's interest process-wide and rebuilds that cache
/// whenever a dispatcher is created. A capture that installed its own dispatcher
/// therefore churned the cache for the whole process: a callsite evaluated while
/// no dispatcher was installed is cached as "never", and from then on a capture on
/// another thread silently misses that event even though its own subscriber would
/// have accepted it. Tests make that constant, because most exercise the code with
/// no capture at all, so an expected line went missing purely on thread
/// scheduling - often enough to fail CI on the slower runners.
///
/// One permissive dispatcher installed once keeps every callsite interesting for
/// good. Routing moves into the writer, per thread, so a capture no longer touches
/// the dispatcher at all.
fn install_router() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let router = tracing_subscriber::fmt()
            .with_writer(|| RoutedWriter)
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .finish();
        // A global default someone else installed first is left alone.
        let _ = tracing::subscriber::set_global_default(router);
    });
}

/// Runs `body` with every `tracing` event captured, returning its result and the log.
///
/// Only events raised on the calling thread are captured.
pub fn capture<T>(body: impl FnOnce() -> T) -> (T, String) {
    install_router();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let active = Active::install(Arc::clone(&buffer));
    let result = body();
    drop(active);

    let bytes = buffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (result, String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{capture, LogCapture};
    use std::io::Write;
    use std::sync::Arc;
    use tracing_subscriber::fmt::MakeWriter;

    #[test]
    fn capture_returns_the_body_result_and_the_log() {
        let (result, log) = capture(|| {
            tracing::info!("searching for KAN-42");
            7
        });

        assert_eq!(result, 7);
        assert!(log.contains("searching for KAN-42"), "log was: {log}");
    }

    #[test]
    fn trace_level_events_are_captured() {
        let ((), log) = capture(|| tracing::trace!("verbose detail"));
        assert!(log.contains("verbose detail"), "log was: {log}");
    }

    #[test]
    fn nothing_logged_leaves_the_buffer_empty() {
        let ((), log) = capture(|| ());
        assert!(log.is_empty(), "log was: {log}");
    }

    #[test]
    fn concurrent_captures_each_see_their_own_event() {
        // `tracing` caches callsite interest process-wide. Dispatchers installed
        // and dropped on different threads race on that cache, and a callsite
        // evaluated while no dispatcher is installed is cached as "never" — which
        // silently drops an expected line from an otherwise correct capture.
        // The same callsite both tests share. Other tests reach it with no
        // dispatcher installed, which is what poisons the cached interest.
        fn emit() {
            tracing::info!("the marker");
        }

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let noise: Vec<_> = (0..4)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        emit();
                    }
                })
            })
            .collect();

        let capturers: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..150 {
                        let ((), log) = capture(emit);
                        assert!(log.contains("the marker"), "log was: {log}");
                    }
                })
            })
            .collect();

        let mut lost = None;
        for thread in capturers {
            if let Err(panic) = thread.join() {
                lost = Some(panic);
            }
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for thread in noise {
            thread.join().expect("a noise thread should not panic");
        }

        if let Some(panic) = lost {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn a_capture_can_be_read_more_than_once() {
        // Written through the writer rather than a dispatcher: installing one
        // here would rebuild the process-wide interest cache and so perturb the
        // captures running in parallel.
        let capture = LogCapture::new();
        capture
            .make_writer()
            .write_all(b"first")
            .expect("the buffer accepts a write");

        assert_eq!(capture.contents(), capture.contents());
        assert!(capture.contents().contains("first"));
    }
}
