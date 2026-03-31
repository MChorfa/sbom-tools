//! Shared rendering functions used by both App (diff mode) and `ViewApp` (view mode).
//!
//! These pure rendering functions take domain types directly (`&QualityReport`,
//! `&Violation`) with no app-specific dependencies, enabling both TUIs to
//! delegate to common code.

pub mod compliance;
pub mod components;
pub mod export;
pub mod licenses;
pub mod quality;
pub mod source;
pub mod vulnerabilities;

/// Find the largest byte index <= `index` that is on a UTF-8 char boundary.
///
/// Equivalent to `str::floor_char_boundary` (stabilized in Rust 1.94,
/// but our MSRV is 1.88).
pub(crate) const fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        s.len()
    } else {
        let bytes = s.as_bytes();
        let mut i = index;
        // Walk backwards to find a leading byte (0xxxxxxx or 11xxxxxx).
        while i > 0 && bytes[i] & 0b1100_0000 == 0b1000_0000 {
            i -= 1;
        }
        i
    }
}
