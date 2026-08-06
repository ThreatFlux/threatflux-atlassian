//! Captures `tracing` output into a buffer a test can assert on.

use std::io;
use std::sync::{Arc, Mutex};

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

/// Runs `body` with every `tracing` event captured, returning its result and the log.
pub fn capture<T>(body: impl FnOnce() -> T) -> (T, String) {
    let capture = LogCapture::new();
    let result = tracing::subscriber::with_default(capture.subscriber(), body);
    (result, capture.contents())
}

#[cfg(test)]
mod tests {
    use super::{capture, LogCapture};

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
    fn a_capture_can_be_read_more_than_once() {
        let capture = LogCapture::new();
        tracing::subscriber::with_default(capture.subscriber(), || {
            tracing::warn!("first");
        });

        assert_eq!(capture.contents(), capture.contents());
        assert!(capture.contents().contains("first"));
    }
}
