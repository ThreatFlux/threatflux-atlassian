//! Scoped environment variables.
//!
//! The process environment is global, so every test that uses a guard must also
//! be `#[serial]`. The guard restores the prior value on drop, including on an
//! assertion failure, so one failing test cannot leak state into the next.

use std::ffi::{OsStr, OsString};

/// Sets environment variables and restores their prior values on drop.
#[derive(Debug, Default)]
pub struct EnvGuard {
    saved: Vec<(OsString, Option<OsString>)>,
}

impl EnvGuard {
    /// Creates a guard holding no variables.
    pub const fn new() -> Self {
        Self { saved: Vec::new() }
    }

    /// Sets `key` to `value` for as long as the guard lives.
    pub fn set<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, value: V) -> &mut Self {
        self.save(key.as_ref());
        std::env::set_var(key.as_ref(), value.as_ref());
        self
    }

    /// Removes `key` for as long as the guard lives.
    pub fn remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        self.save(key.as_ref());
        std::env::remove_var(key.as_ref());
        self
    }

    fn save(&mut self, key: &OsStr) {
        if self.saved.iter().any(|(saved, _)| saved == key) {
            return;
        }
        self.saved.push((key.to_os_string(), std::env::var_os(key)));
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..).rev() {
            match value {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EnvGuard;

    #[test]
    fn set_restores_the_previous_value() {
        std::env::set_var("TESTKIT_ENV_RESTORE", "before");
        {
            let mut guard = EnvGuard::new();
            guard.set("TESTKIT_ENV_RESTORE", "during");
            assert_eq!(
                std::env::var("TESTKIT_ENV_RESTORE").as_deref(),
                Ok("during")
            );
        }

        assert_eq!(
            std::env::var("TESTKIT_ENV_RESTORE").as_deref(),
            Ok("before")
        );
        std::env::remove_var("TESTKIT_ENV_RESTORE");
    }

    #[test]
    fn set_unsets_a_variable_that_did_not_exist() {
        std::env::remove_var("TESTKIT_ENV_ABSENT");
        {
            let mut guard = EnvGuard::new();
            guard.set("TESTKIT_ENV_ABSENT", "during");
        }

        assert!(std::env::var_os("TESTKIT_ENV_ABSENT").is_none());
    }

    #[test]
    fn remove_restores_the_previous_value() {
        std::env::set_var("TESTKIT_ENV_REMOVED", "before");
        {
            let mut guard = EnvGuard::new();
            guard.remove("TESTKIT_ENV_REMOVED");
            assert!(std::env::var_os("TESTKIT_ENV_REMOVED").is_none());
        }

        assert_eq!(
            std::env::var("TESTKIT_ENV_REMOVED").as_deref(),
            Ok("before")
        );
        std::env::remove_var("TESTKIT_ENV_REMOVED");
    }

    #[test]
    fn repeated_writes_restore_the_value_from_before_the_first_one() {
        std::env::set_var("TESTKIT_ENV_REPEATED", "before");
        {
            let mut guard = EnvGuard::new();
            guard.set("TESTKIT_ENV_REPEATED", "first");
            guard.set("TESTKIT_ENV_REPEATED", "second");
        }

        assert_eq!(
            std::env::var("TESTKIT_ENV_REPEATED").as_deref(),
            Ok("before")
        );
        std::env::remove_var("TESTKIT_ENV_REPEATED");
    }
}
