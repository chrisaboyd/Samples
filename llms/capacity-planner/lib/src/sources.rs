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
    let path = s
        .strip_prefix("huggingface.co/")
        .ok_or_else(|| CalcError::InvalidInput(format!("not a HuggingFace URL: {url}")))?;
    // The first two non-empty segments are always org/model; trailing path
    // components (blob/main/config.json, resolve/<rev>/..., params) are ignored.
    let mut segs = path.split('/').filter(|seg| !seg.is_empty());
    let org = segs
        .next()
        .ok_or_else(|| CalcError::InvalidInput(format!("missing org/model in URL: {url}")))?;
    let repo = segs
        .next()
        .ok_or_else(|| CalcError::InvalidInput(format!("missing repo name in URL: {url}")))?;
    // Optional revision from .../resolve/<rev>/... or .../blob/<rev>/...
    let mut maybe_rev = segs.peekable();
    let revision = match maybe_rev.peek() {
        Some(first) if *first == "resolve" || *first == "blob" => {
            maybe_rev.nth(1).map(|s| s.to_string())
        }
        _ => None,
    };
    Ok(ParsedUrl {
        repo: format!("{org}/{repo}"),
        revision,
    })
}

/// `metadata.total_size` from a `model.safetensors.index.json`: the summed byte
/// length of every tensor in the checkpoint, quantization scales included.
///
/// Pure parsing, so it works on a file the user supplied as well as on a fetched
/// one, and needs no `sources` feature. Returns `None` for an index that omits
/// the field rather than guessing from the shard list.
pub fn index_total_size(index: &serde_json::Value) -> Option<u128> {
    index
        .get("metadata")?
        .get("total_size")?
        .as_u64()
        .map(u128::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_total_size_from_an_index() {
        let idx = serde_json::json!({
            "metadata": { "total_size": 131_264_796_160u64 },
            "weight_map": { "lm_head.weight": "model-00001-of-00049.safetensors" }
        });
        assert_eq!(index_total_size(&idx), Some(131_264_796_160));
    }

    #[test]
    fn index_without_metadata_is_none_not_zero() {
        assert_eq!(
            index_total_size(&serde_json::json!({ "weight_map": {} })),
            None
        );
        assert_eq!(
            index_total_size(&serde_json::json!({ "metadata": {} })),
            None
        );
    }

    #[test]
    fn bare_repo_url() {
        let p = parse_hf_url("https://huggingface.co/poolside/Laguna-S-2.1").unwrap();
        assert_eq!(p.repo, "poolside/Laguna-S-2.1");
        assert_eq!(p.revision, None);
    }

    #[test]
    fn blob_url_strips_path_and_reads_revision() {
        let p = parse_hf_url("https://huggingface.co/poolside/Laguna-S-2.1/blob/main/config.json")
            .unwrap();
        assert_eq!(p.repo, "poolside/Laguna-S-2.1");
        assert_eq!(p.revision.as_deref(), Some("main"));
    }

    #[test]
    fn resolve_url_reads_revision() {
        let p =
            parse_hf_url("https://huggingface.co/org/model/resolve/abc123/config.json").unwrap();
        assert_eq!(p.repo, "org/model");
        assert_eq!(p.revision.as_deref(), Some("abc123"));
    }

    #[test]
    fn rejects_non_hf_url() {
        assert!(parse_hf_url("https://example.com/org/model").is_err());
        assert!(parse_hf_url("not a url").is_err());
    }

    // A token passed to SourceService must never surface in any result.
    #[cfg(feature = "sources")]
    #[test]
    fn token_is_not_exposed_by_repo_of() {
        let svc = SourceService::new(Some("secret-token".to_string()));
        // repo_of can only ever return the parsed repo name, never the token.
        let repo = svc
            .repo_of("https://huggingface.co/poolside/Laguna-S-2.1")
            .unwrap();
        assert_eq!(repo, "poolside/Laguna-S-2.1");
        assert!(!repo.contains("secret-token"));
    }
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
