//! Portable LLM Capacity & Performance Planner — calculation core.
//!
//! Phase 1 (this crate) implements the pure calculation library described in
//! PRD §31 "Phase 1: Formula prototype": parse a model `config.json`, normalize
//! it into [`model::NormalizedModel`], compute weight memory, KV-cache capacity,
//! and memory-fit against a [`hardware::Gpu`] catalog, and emit a structured
//! [`result::ScenarioResult`] (PRD §25).
//!
//! The mathematical core is intentionally network-free and feature-gated so it
//! can be unit-tested offline. Optional model-source fetching (Hugging Face)
//! lives in [`sources`] and is enabled by the `sources` cargo feature.
//!
//! No remote code is ever executed (PRD §10.3): configuration files are parsed
//! as data only.

pub mod adapter;
pub mod confidence;
pub mod error;
pub mod explain;
pub mod hardware;
pub mod kv;
pub mod memory;
pub mod model;
pub mod performance;
pub mod precision;
pub mod result;
pub mod sources;
pub mod weight;

pub use error::{CalcError, Result};
pub use model::NormalizedModel;
pub use result::ScenarioResult;

#[cfg(feature = "sources")]
pub use sources::SourceService;

/// Convenience: bytes in one GiB (2^30). PRD §33 requires exact GPU-memory
/// unit conversion, which this constant provides.
pub const GIB_BYTES: u128 = 1024 * 1024 * 1024;
pub const GB_BYTES: u128 = 1_000_000_000;
