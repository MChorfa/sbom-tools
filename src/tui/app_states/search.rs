//! Search state types.

/// Search mode: substring (default) or regex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchMode {
    #[default]
    Substring,
    Regex,
}

impl SearchMode {
    /// Human-readable label for display in status bar.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Substring => "substring",
            Self::Regex => "regex",
        }
    }
}

/// One matching semantic for every search surface: case-insensitive
/// substring or case-insensitive regex, built once per query.
#[derive(Debug)]
pub struct SearchMatcher {
    mode: SearchMode,
    regex: Option<regex::Regex>,
    query_lower: String,
}

impl SearchMatcher {
    /// Build a matcher; invalid regex patterns return the error string the
    /// overlays display.
    pub fn build(query: &str, mode: SearchMode) -> Result<Self, String> {
        let regex = match mode {
            SearchMode::Regex => Some(
                regex::RegexBuilder::new(query)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| format!("Invalid regex: {e}"))?,
            ),
            SearchMode::Substring => None,
        };
        Ok(Self {
            mode,
            regex,
            query_lower: query.to_lowercase(),
        })
    }

    pub fn is_match(&self, text: &str) -> bool {
        match self.mode {
            SearchMode::Substring => text.to_lowercase().contains(&self.query_lower),
            SearchMode::Regex => self.regex.as_ref().is_some_and(|re| re.is_match(text)),
        }
    }
}

#[cfg(test)]
mod matcher_tests {
    use super::{SearchMatcher, SearchMode};

    #[test]
    fn substring_is_case_insensitive() {
        let m = SearchMatcher::build("AxIoS", SearchMode::Substring).unwrap();
        assert!(m.is_match("axios@1.4.0"));
        assert!(!m.is_match("lodash"));
    }

    #[test]
    fn substring_treats_metacharacters_literally() {
        let m = SearchMatcher::build("a.c", SearchMode::Substring).unwrap();
        assert!(m.is_match("a.c-parser"));
        assert!(
            !m.is_match("abc"),
            "'.' must not act as a regex wildcard in Substring mode"
        );
    }

    #[test]
    fn regex_matches_and_reports_errors() {
        let m = SearchMatcher::build("CVE-2024-.*", SearchMode::Regex).unwrap();
        assert!(m.is_match("cve-2024-1234"), "regex is case-insensitive");
        assert!(!m.is_match("CVE-2023-1"));
        let err = SearchMatcher::build("(", SearchMode::Regex).unwrap_err();
        assert!(err.starts_with("Invalid regex:"), "{err}");
    }
}

/// Search state for diff mode.
#[derive(Debug, Clone)]
pub struct DiffSearchState {
    pub active: bool,
    pub query: String,
    pub results: Vec<DiffSearchResult>,
    pub selected: usize,
    /// Current search mode (substring or regex).
    pub mode: SearchMode,
    /// Error message from invalid regex pattern.
    pub search_error: Option<String>,
}

impl DiffSearchState {
    pub const fn new() -> Self {
        Self {
            active: false,
            query: String::new(),
            results: Vec::new(),
            selected: 0,
            mode: SearchMode::Substring,
            search_error: None,
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.query.push(c);
    }

    pub fn pop_char(&mut self) {
        self.query.pop();
    }

    pub fn select_next(&mut self) {
        if !self.results.is_empty() && self.selected < self.results.len() - 1 {
            self.selected += 1;
        }
    }

    pub const fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn clear(&mut self) {
        self.query.clear();
        self.results.clear();
        self.selected = 0;
        self.search_error = None;
    }
}

impl Default for DiffSearchState {
    fn default() -> Self {
        Self::new()
    }
}

/// Search result for diff mode.
#[derive(Debug, Clone)]
pub enum DiffSearchResult {
    Component {
        name: String,
        version: Option<String>,
        change_type: ChangeType,
    },
    Vulnerability {
        id: String,
        component_name: String,
        severity: Option<String>,
        change_type: VulnChangeType,
    },
    License {
        license: String,
        component_name: String,
        change_type: ChangeType,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    /// Inventory entry produced under --include-unchanged
    Unchanged,
}

impl ChangeType {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Modified => "modified",
            Self::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnChangeType {
    Introduced,
    Resolved,
}

impl VulnChangeType {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Introduced => "introduced",
            Self::Resolved => "resolved",
        }
    }
}
