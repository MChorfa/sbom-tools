//! C ABI thin wrapper — all implementation lives in `sbom_tools::ffi`.
//!
//! Building this crate as cdylib/staticlib exports the `#[no_mangle]` extern "C"
//! symbols defined in the sbom-tools dependency.

pub use sbom_tools::ffi::*;
