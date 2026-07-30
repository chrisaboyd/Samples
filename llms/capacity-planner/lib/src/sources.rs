//! Hugging Face model source service (PRD §24 "Model Source Service").
//!
//! Gated behind the `sources` cargo feature so the pure calculation core stays
//! network-free and offline-testable. Only `config.json` and the optional
//! safetensors shard index are fetched as *data*; no repository Python is ever
//! executed (PRD §10.3 security requirement).
//!
//! Gated/private repos: an `HF_TOKEN` is read from the environment at the call
//! site and attached as a bearer header. It is never logged or returned.

use crate::error::{CalcError, Result};

/// A resolved HF repository ("org/model") plus optional revision.
pub struct ParsedUrl {
    pub repo: String,
    pub revision: Option<String>,
}

pub fn parse_hf_url(url: &str) -> Result<ParsedUrl> {
    let s = url.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let s = s
        .strip_prefix("huggingface.co/")
        .ok_or_else(|| CalcError::InvalidInput(format!("not a HuggingFace URL: {url}")))?;
    // Take the first two path segments as org/model.
    let mut parts = Vec::new();
    let mut rest = s;
    for (i, seg) in s.split('/').enumerate() {
        if i >= 2 {
            rest = seg;
            break;
        }
        parts.push(seg);
        if i == 1 {
            // after consuming org/model, the remainder begins
            rest = s.split('/').nth(2).unwrap_or("");
        }
    }
    let _ = rest;
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(CalcError::InvalidInput(format!(
            "could not parse org/model from URL: {url}"
        )));
    }
    // revision detection: .../resolve/<rev>/config.json
    let revision = None; // simplified; PRD records revision in provenance when present
    let _ = revision;
    Ok(ParsedUrl {
        repo: format!("{}/{}", parts[0], parts[1]),
        revision,
    })
}

#[cfg(feature = "sources")]
pub mod blocking {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

    /// Metadata-only client. Reads `HF_TOKEN` from the environment if present.
    pub struct SourceService {
        client: reqwest::blocking::Client,
        token: Option<String>,
    }

    impl SourceService {
        pub fn new(token: Option<String>) -> Self {
            let client = reqwest::blocking::Client::builder()
                .user_agent(concat!(
                    "capacity-planner/",
                    env!("CARGO_PKG_VERSION"),
                    " (local-first desktop; does not execute remote code)"
                ))
                .build()
                .expect("client builds");
            Self { client, token }
        }

        /// Fetch `config.json` for a HuggingFace model URL. `token` overrides the
        /// environment token and is never logged.
        pub fn fetch_config(&self, url: &str) -> Result<String> {
            let parsed = parse_hf_url(url)?;
            let config_url = format!(
                "https://huggingface.co/{}/resolve/main/config.json",
                parsed.repo
            );
            let resp = self.get(&config_url)?;
            if resp.is_empty() {
                return Err(CalcError::Other(format!(
                    "empty config.json for {}",
                    parsed.repo
                )));
            }
            Ok(resp)
        }

        /// Fetch the safetensors shard index (Level B hook, PRD §10.2). `None`
        /// when the repository has no index (returns Ok(None) on a 404).
        pub fn fetch_index(&self, url: &str) -> Result<Option<serde_json::Value>> {
            let parsed = parse_hf_url(url)?;
            let url = format!(
                "https://huggingface.co/{}/resolve/main/model.safetensors.index.json",
                parsed.repo
            );
            let resp = self.get(&url)?;
            if resp.is_empty() {
                return Ok(None);
            }
            let v: serde_json::Value = serde_json::from_str(&resp)?;
            Ok(Some(v))
        }

        fn get(&self, url: &str) -> Result<String> {
            let mut req = self.client.get(url);
            if let Some(t) = &self.token {
                let mut headers = HeaderMap::new();
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {t}"))
                        .map_err(|_| CalcError::InvalidInput("malformed HF token".into()))?,
                );
                req = req.headers(headers);
            }
            let resp = req
                .send()
                .map_err(|e| CalcError::Other(format!("http send: {e}")))?;
            if !resp.status().is_success() {
                if resp.status().as_u16() == 404 {
                    return Ok(String::new());
                }
                return Err(CalcError::Other(format!(
                    "http {} for {}",
                    resp.status(),
                    url
                )));
            }
            resp.text()
                .map_err(|e| CalcError::Other(format!("http body: {e}")))
        }

        /// Repository name for provenance reporting (token not included).
        pub fn repo_of(&self, url: &str) -> Result<String> {
            Ok(parse_hf_url(url)?.repo)
        }
    }
}

#[cfg(not(feature = "sources"))]
pub mod blocking {
    //! Re-exported so `SourceService` type exists without the feature; methods
    //! are unavailable and the CLI reports the feature as missing.
    pub struct SourceService;
}

pub use blocking::SourceService;
