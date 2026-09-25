//! An RSP plugin in Rust, split the way the Go and TypeScript ones are: the
//! shape `SPEC.md` requires on one side, the tool being wrapped on the other.

pub mod gitleaks;
pub mod protocol;

/// Anything that stops this plugin answering. A plugin reports failure by
/// failing — the host is what turns that into a verdict (E1, D3).
pub type Error = Box<dyn std::error::Error>;
