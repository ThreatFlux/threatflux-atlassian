//! A sleeper that records requested delays instead of waiting for them.
//!
//! The retry work injects a `Sleeper` trait from the SDK. This crate does not
//! depend on the SDK, so the trait impl lives on the SDK side — a trait is
//! local to the crate that declares it, so `impl Sleeper for RecordingSleeper`
//! is legal there and would be an orphan here.
//!
//! `tokio::time::pause()` is not an alternative: wiremock shares the runtime and
//! real socket I/O stalls under a paused clock.

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Records every requested delay and returns immediately.
///
/// Clones share one journal, so a clone handed to the code under test still
/// reports through the handle the test holds.
#[derive(Debug, Clone, Default)]
pub struct RecordingSleeper {
    recorded: Arc<Mutex<Vec<Duration>>>,
}

impl RecordingSleeper {
    /// Creates a sleeper with an empty journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `duration` and returns immediately.
    // The signature has to match the SDK's async `Sleeper` trait method, which
    // is what this type is handed to production code as.
    #[allow(clippy::unused_async)]
    pub async fn sleep(&self, duration: Duration) {
        self.record(duration);
    }

    /// Records `duration` without an await point, for a synchronous caller.
    ///
    /// # Panics
    ///
    /// Panics if the journal lock was poisoned by a panicking test.
    pub fn record(&self, duration: Duration) {
        self.recorded
            .lock()
            .expect("sleep journal lock should not be poisoned")
            .push(duration);
    }

    /// Returns every recorded delay, in order.
    ///
    /// # Panics
    ///
    /// Panics if the journal lock was poisoned by a panicking test.
    pub fn recorded(&self) -> Vec<Duration> {
        self.recorded
            .lock()
            .expect("sleep journal lock should not be poisoned")
            .clone()
    }

    /// Returns every recorded delay in milliseconds, for terser assertions.
    pub fn recorded_millis(&self) -> Vec<u128> {
        self.recorded()
            .iter()
            .map(Duration::as_millis)
            .collect::<Vec<_>>()
    }

    /// Returns how many delays were requested.
    pub fn count(&self) -> usize {
        self.recorded().len()
    }

    /// Returns the wall-clock time the code under test believes it slept.
    pub fn total(&self) -> Duration {
        self.recorded().iter().sum()
    }

    /// Empties the journal.
    ///
    /// # Panics
    ///
    /// Panics if the journal lock was poisoned by a panicking test.
    pub fn clear(&self) {
        self.recorded
            .lock()
            .expect("sleep journal lock should not be poisoned")
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::RecordingSleeper;
    use std::time::{Duration, Instant};

    #[test]
    fn records_in_order_without_waiting() {
        let sleeper = RecordingSleeper::new();
        let started = Instant::now();

        sleeper.record(Duration::from_secs(2));
        sleeper.record(Duration::from_millis(250));

        assert_eq!(sleeper.recorded_millis(), vec![2000, 250]);
        assert_eq!(sleeper.count(), 2);
        assert_eq!(sleeper.total(), Duration::from_millis(2250));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn async_sleep_records_and_returns_immediately() {
        let sleeper = RecordingSleeper::new();
        let started = Instant::now();

        sleeper.sleep(Duration::from_secs(30)).await;

        assert_eq!(sleeper.recorded(), vec![Duration::from_secs(30)]);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn clones_share_one_journal() {
        let sleeper = RecordingSleeper::new();
        let handed_to_code_under_test = sleeper.clone();

        handed_to_code_under_test.record(Duration::from_millis(10));

        assert_eq!(sleeper.recorded_millis(), vec![10]);
    }

    #[test]
    fn clear_empties_the_journal() {
        let sleeper = RecordingSleeper::new();
        sleeper.record(Duration::from_millis(10));
        sleeper.clear();

        assert!(sleeper.recorded().is_empty());
    }
}
