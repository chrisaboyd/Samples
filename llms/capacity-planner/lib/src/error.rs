//! Central error type for the calculation library.
//!
//! Deliberately feature-free: the network error from `reqwest` (gated behind the
//! `sources` feature) is mapped into [`CalcError::Other`] at the call site so the
//! pure math core never references an optional dependency.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CalcError {
    #[error("config.json missing required field: {0}")]
    MissingField(String),
    #[error("inconsistent config value: {0}")]
    Inconsistent(String),
    #[error("unknown model_type: {0}")]
    UnknownModelType(String),
    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
    #[error("requested GPU SKU not found in catalog: {0}")]
    UnknownGpu(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CalcError>;
