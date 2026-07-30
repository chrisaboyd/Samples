//! Confidence model (PRD §10.1 confidence hierarchy + §16.5 performance
//! grades). Every result carries a grade and human-readable reasons so nothing
//! is ever presented as more certain than it is (PRD §35 #8).

use serde::{Deserialize, Serialize};

/// Source-of-truth level for the memory/parameter math (PRD §10.1).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AnalyzeLevel {
    /// A: exact tensor metadata (safetensors headers).
    A,
    /// B: checkpoint index + repository file sizes.
    B,
    /// C: architecture-derived from config.json.
    C,
    /// D: generic transformer approximation.
    D,
}

impl AnalyzeLevel {
    pub fn label(self) -> &'static str {
        match self {
            AnalyzeLevel::A => "Exact checkpoint inspection",
            AnalyzeLevel::B => "Checkpoint index and repository sizes",
            AnalyzeLevel::C => "Architecture-derived calculation",
            AnalyzeLevel::D => "Generic approximation",
        }
    }
}

/// End-to-end confidence grade for a result slice (PRD §16.5).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceGrade {
    /// Imported or locally run benchmark for the exact stack.
    Measured,
    /// Benchmark exists for a closely related model/hardware.
    Calibrated,
    /// Calculated from architecture + roofline.
    Analytical,
    /// Missing architectural or engine-specific information.
    Speculative,
}

impl ConfidenceGrade {
    pub fn label(self) -> &'static str {
        match self {
            ConfidenceGrade::Measured => "Measured",
            ConfidenceGrade::Calibrated => "Calibrated",
            ConfidenceGrade::Analytical => "Analytical",
            ConfidenceGrade::Speculative => "Speculative",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confidence {
    pub grade: ConfidenceGrade,
    pub level: AnalyzeLevel,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
}

impl Confidence {
    pub fn new(level: AnalyzeLevel, grade: ConfidenceGrade, reason: impl Into<String>) -> Self {
        Self {
            grade,
            level,
            reasons: vec![reason.into()],
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    pub fn add_reason(mut self, reason: impl Into<String>) -> Self {
        self.reasons.push(reason.into());
        self
    }
}
