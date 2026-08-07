//! Caps on how far an iteration over search results may go.

/// Pages a bounded iteration will fetch before it stops.
pub const DEFAULT_MAX_PAGES: usize = 100;

/// Issues a bounded iteration will accumulate before it stops.
pub const DEFAULT_MAX_ISSUES: usize = 5_000;

/// How much of a result set a caller is willing to walk.
///
/// # Why a default cap rather than none
///
/// A JQL query's result set is chosen by Jira, not by the caller, so "iterate
/// until the pages run out" is an unbounded amount of work driven by data. A
/// mistyped query in an automation is the ordinary way to discover that: it
/// matches an entire project, and the run walks tens of thousands of issues
/// before anybody notices. The default caps make that a reported failure
/// instead.
///
/// # A cap is a failure, not a quiet truncation
///
/// Reaching a cap is not the same as reaching the end of the result set, and
/// the difference matters most exactly when a caller is deciding whether an
/// issue already exists. So a cap is meant to surface as a refusal to hand back
/// a partial answer, not as a shorter list — a bulk collect that hits one has
/// not answered the question it was asked.
///
/// ```
/// use threatflux_atlassian_sdk::search::SearchLimits;
///
/// let limits = SearchLimits::default().with_max_issues(Some(200));
///
/// assert!(!limits.issue_cap_reached(199));
/// assert!(limits.issue_cap_reached(200));
/// assert_eq!(limits.remaining_issues(180), Some(20));
/// assert_eq!(SearchLimits::unlimited().remaining_issues(180), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchLimits {
    /// Pages that may be fetched, `None` for no cap.
    max_pages: Option<usize>,

    /// Issues that may be accumulated, `None` for no cap.
    max_issues: Option<usize>,
}

impl Default for SearchLimits {
    /// [`DEFAULT_MAX_PAGES`] pages and [`DEFAULT_MAX_ISSUES`] issues.
    fn default() -> Self {
        Self {
            max_pages: Some(DEFAULT_MAX_PAGES),
            max_issues: Some(DEFAULT_MAX_ISSUES),
        }
    }
}

impl SearchLimits {
    /// No cap of either kind.
    ///
    /// For a caller that genuinely means "every match, however many that is"
    /// and has thought about what that costs.
    pub const fn unlimited() -> Self {
        Self {
            max_pages: None,
            max_issues: None,
        }
    }

    /// Sets the page cap, or removes it with `None`.
    ///
    /// `Some(0)` is a cap of zero pages, which no iteration can satisfy. It is
    /// accepted rather than rejected because it is unambiguous: a caller that
    /// computed a budget and arrived at zero gets the answer that budget
    /// implies.
    #[must_use]
    pub const fn with_max_pages(mut self, max_pages: Option<usize>) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// Sets the issue cap, or removes it with `None`.
    ///
    /// `Some(0)` behaves as [`with_max_pages`](Self::with_max_pages) describes.
    #[must_use]
    pub const fn with_max_issues(mut self, max_issues: Option<usize>) -> Self {
        self.max_issues = max_issues;
        self
    }

    /// The page cap, when there is one.
    pub const fn max_pages(&self) -> Option<usize> {
        self.max_pages
    }

    /// The issue cap, when there is one.
    pub const fn max_issues(&self) -> Option<usize> {
        self.max_issues
    }

    /// Whether `pages_fetched` pages have used the page budget up.
    pub const fn page_cap_reached(&self, pages_fetched: usize) -> bool {
        match self.max_pages {
            Some(cap) => pages_fetched >= cap,
            None => false,
        }
    }

    /// Whether `issues_seen` issues have used the issue budget up.
    pub const fn issue_cap_reached(&self, issues_seen: usize) -> bool {
        match self.max_issues {
            Some(cap) => issues_seen >= cap,
            None => false,
        }
    }

    /// How many more issues may be accumulated, `None` when uncapped.
    ///
    /// Saturates at zero rather than wrapping, so a caller that overshot a cap
    /// reads zero rather than a very large number.
    pub const fn remaining_issues(&self, issues_seen: usize) -> Option<usize> {
        match self.max_issues {
            Some(cap) => Some(cap.saturating_sub(issues_seen)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_caps_both_axes() {
        let limits = SearchLimits::default();

        assert_eq!(limits.max_pages(), Some(DEFAULT_MAX_PAGES));
        assert_eq!(limits.max_issues(), Some(DEFAULT_MAX_ISSUES));
    }

    #[test]
    fn unlimited_caps_neither_axis() {
        let limits = SearchLimits::unlimited();

        assert_eq!(limits.max_pages(), None);
        assert_eq!(limits.max_issues(), None);
        assert!(!limits.page_cap_reached(usize::MAX));
        assert!(!limits.issue_cap_reached(usize::MAX));
        assert_eq!(limits.remaining_issues(usize::MAX), None);
    }

    #[test]
    fn a_cap_is_reached_at_the_cap_and_not_before() {
        let limits = SearchLimits::default()
            .with_max_pages(Some(3))
            .with_max_issues(Some(10));

        assert!(!limits.page_cap_reached(2));
        assert!(limits.page_cap_reached(3));
        assert!(limits.page_cap_reached(4));
        assert!(!limits.issue_cap_reached(9));
        assert!(limits.issue_cap_reached(10));
    }

    #[test]
    fn a_zero_cap_is_reached_immediately() {
        let limits = SearchLimits::default()
            .with_max_pages(Some(0))
            .with_max_issues(Some(0));

        assert!(limits.page_cap_reached(0));
        assert!(limits.issue_cap_reached(0));
        assert_eq!(limits.remaining_issues(0), Some(0));
    }

    #[test]
    fn the_remaining_budget_saturates_rather_than_wrapping() {
        let limits = SearchLimits::default().with_max_issues(Some(10));

        assert_eq!(limits.remaining_issues(0), Some(10));
        assert_eq!(limits.remaining_issues(10), Some(0));
        assert_eq!(limits.remaining_issues(11), Some(0));
    }

    #[test]
    fn a_cap_can_be_removed_one_axis_at_a_time() {
        let limits = SearchLimits::default()
            .with_max_pages(None)
            .with_max_issues(Some(1));

        assert_eq!(limits.max_pages(), None);
        assert!(!limits.page_cap_reached(usize::MAX));
        assert!(limits.issue_cap_reached(1));
    }
}
