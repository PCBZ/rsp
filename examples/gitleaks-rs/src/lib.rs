//! An RSP plugin that wraps gitleaks.

pub mod gitleaks;
pub mod protocol;

/// Anything that stops this plugin answering; the host makes that a verdict (E1, D3).
pub type Error = Box<dyn std::error::Error>;
