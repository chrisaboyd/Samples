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

/// Where a checkpoint's `generation_config.json` says its drafter lives.
///
/// vLLM does not read this file for speculative config; a serving layer does
/// (Poolside's atlas synthesizes `--speculative-config` from it when
/// `--self-contained-checkpoint` is set). It is the only machine-readable link
/// from a target checkpoint to its drafter, and it is not in `config.json`,
/// which is why a planner that reads only `config.json` cannot see the drafter
/// at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeculatorRef {
    pub method: String,
    /// `huggingface` (model is a repo id) or `bundled` (model is a subfolder
    /// path inside the target repo). Absent means "infer from the shape".
    pub source: Option<String>,
    pub model: Option<String>,
    pub num_speculative_tokens: Option<u32>,
}

impl SpeculatorRef {
    /// Resolve `model` against the target repo into something fetchable.
    ///
    /// `poolside/Laguna-S-2.1-DFlash` is already a repo id. `./DFlash` is a
    /// subfolder of the target repo, which is how a packaged checkpoint rewrites
    /// the reference once the drafter travels with it. Returns
    /// `(repo, subfolder)`.
    pub fn resolve(&self, target_repo: &str) -> Option<(String, Option<String>)> {
        let model = self.model.as_deref()?.trim();
        if model.is_empty() {
            return None;
        }
        let looks_bundled = self.source.as_deref() == Some("bundled")
            || model.starts_with("./")
            || model.starts_with('/');
        if looks_bundled {
            let sub = model.trim_start_matches("./").trim_start_matches('/');
            if sub.is_empty() {
                return None;
            }
            return Some((target_repo.to_string(), Some(sub.to_string())));
        }
        Some((model.to_string(), None))
    }
}

/// Read `speculative_config` out of a `generation_config.json` blob.
///
/// Pure parsing so it works on a file the user supplied as well as a fetched
/// one. Returns `None` when the checkpoint declares no drafter.
pub fn parse_speculator_ref(generation_config: &serde_json::Value) -> Option<SpeculatorRef> {
    let spec = generation_config.get("speculative_config")?.as_object()?;
    let method = spec.get("method")?.as_str()?.trim().to_string();
    if method.is_empty() {
        return None;
    }
    Some(SpeculatorRef {
        method,
        source: spec
            .get("source")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        model: spec
            .get("model")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        num_speculative_tokens: spec
            .get("num_speculative_tokens")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
    })
}

/// Summed `.safetensors` byte size from a HuggingFace repo listing.
///
/// The fallback for a drafter, which typically ships one `model.safetensors`
/// and no `model.safetensors.index.json` at all — so [`index_total_size`] has
/// nothing to read. Slightly larger than an index's `total_size`, which counts
/// tensor bytes only and excludes each shard's header (about 8.3 MiB across
/// Laguna-S's 49 shards, or 0.007%).
pub fn siblings_safetensors_bytes(repo_info: &serde_json::Value, subfolder: Option<&str>) -> u128 {
    let prefix = subfolder.map(|s| format!("{}/", s.trim_end_matches('/')));
    repo_info
        .get("siblings")
        .and_then(|s| s.as_array())
        .map(|files| {
            files
                .iter()
                .filter_map(|f| {
                    let name = f.get("rfilename")?.as_str()?;
                    if !name.ends_with(".safetensors") {
                        return None;
                    }
                    match &prefix {
                        Some(p) if !name.starts_with(p.as_str()) => return None,
                        // Without a subfolder, ignore nested ones so a bundled
                        // drafter is not counted into its target's total.
                        None if name.contains('/') => return None,
                        _ => {}
                    }
                    f.get("size").and_then(|s| s.as_u64()).map(u128::from)
                })
                .sum()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_speculative_config_from_generation_config() {
        let gc = serde_json::json!({
            "temperature": 1.0,
            "speculative_config": {
                "method": "dflash",
                "source": "huggingface",
                "model": "poolside/Laguna-S-2.1-DFlash",
                "num_speculative_tokens": 15
            }
        });
        let s = parse_speculator_ref(&gc).unwrap();
        assert_eq!(s.method, "dflash");
        assert_eq!(s.num_speculative_tokens, Some(15));
        assert_eq!(
            s.resolve("poolside/Laguna-S-2.1-FP8"),
            Some(("poolside/Laguna-S-2.1-DFlash".to_string(), None))
        );
    }

    #[test]
    fn a_bundled_drafter_resolves_to_a_subfolder_of_its_target() {
        // How a packaged checkpoint rewrites the reference once the drafter
        // travels inside it.
        let gc = serde_json::json!({
            "speculative_config": {
                "method": "dflash", "source": "bundled",
                "model": "./DFlash", "num_speculative_tokens": 15
            }
        });
        let s = parse_speculator_ref(&gc).unwrap();
        assert_eq!(
            s.resolve("poolside/spec-decoding-subfolder-fixture"),
            Some((
                "poolside/spec-decoding-subfolder-fixture".to_string(),
                Some("DFlash".to_string())
            ))
        );
    }

    #[test]
    fn no_speculative_config_is_none_not_a_default() {
        assert!(parse_speculator_ref(&serde_json::json!({ "temperature": 1.0 })).is_none());
        assert!(parse_speculator_ref(&serde_json::json!({
            "speculative_config": { "model": "x" }
        }))
        .is_none());
    }

    #[test]
    fn sums_only_top_level_safetensors_unless_a_subfolder_is_named() {
        let info = serde_json::json!({ "siblings": [
            { "rfilename": "model.safetensors", "size": 100u64 },
            { "rfilename": "config.json", "size": 7u64 },
            { "rfilename": "DFlash/model.safetensors", "size": 40u64 },
        ]});
        // A bundled drafter must not be counted into its target's total.
        assert_eq!(siblings_safetensors_bytes(&info, None), 100);
        assert_eq!(siblings_safetensors_bytes(&info, Some("DFlash")), 40);
    }

    #[test]
    fn ngram_loads_no_model_so_costs_nothing() {
        use crate::model::{method_allocates_full_context, method_loads_draft_model};
        assert!(!method_loads_draft_model("ngram"));
        assert!(method_loads_draft_model("dflash"));
        // A DFlash drafter's declared sliding window is ignored for KV sizing.
        assert!(method_allocates_full_context("dflash"));
        assert!(method_allocates_full_context("eagle"));
        assert!(!method_allocates_full_context("ngram"));
    }

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

        /// Fetch `generation_config.json`. `Ok(None)` on a 404, which is the
        /// common case: most repos publish one, some do not, and neither is an
        /// error.
        pub fn fetch_generation_config(&self, url: &str) -> Result<Option<serde_json::Value>> {
            let parsed = parse_hf_url(url)?;
            let resp = self.get(&format!(
                "https://huggingface.co/{}/resolve/main/generation_config.json",
                parsed.repo
            ))?;
            if resp.is_empty() {
                return Ok(None);
            }
            Ok(Some(serde_json::from_str(&resp)?))
        }

        /// Fetch a file from an arbitrary repo, optionally under a subfolder.
        /// Used for a drafter, which lives in its own repo or in a subfolder of
        /// its target's.
        fn fetch_repo_file(
            &self,
            repo: &str,
            subfolder: Option<&str>,
            file: &str,
        ) -> Result<Option<String>> {
            let path = match subfolder {
                Some(s) => format!("{}/{file}", s.trim_end_matches('/')),
                None => file.to_string(),
            };
            let resp = self.get(&format!(
                "https://huggingface.co/{repo}/resolve/main/{path}"
            ))?;
            Ok(if resp.is_empty() { None } else { Some(resp) })
        }

        /// Resolve a declared drafter into a [`crate::model::Speculator`].
        ///
        /// Two hops: the drafter's `config.json` for its shape, then its byte
        /// total. Prefers the drafter's safetensors index and falls back to
        /// summing blob sizes from the repo listing, because a drafter is
        /// usually a single unsharded `model.safetensors` with no index.
        pub fn fetch_speculator(
            &self,
            target_url: &str,
            spec: &SpeculatorRef,
        ) -> Result<Option<crate::model::Speculator>> {
            use crate::model::{method_allocates_full_context, method_loads_draft_model};

            if !method_loads_draft_model(&spec.method) {
                return Ok(None);
            }
            let target_repo = parse_hf_url(target_url)?.repo;
            let Some((repo, subfolder)) = spec.resolve(&target_repo) else {
                return Ok(None);
            };
            let Some(cfg_text) =
                self.fetch_repo_file(&repo, subfolder.as_deref(), "config.json")?
            else {
                return Ok(None);
            };
            let cfg: serde_json::Value = serde_json::from_str(&cfg_text)?;

            let layers = cfg
                .get("num_hidden_layers")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            // A drafter that declares a window still allocates full-context KV
            // under the EAGLE-family methods; see `model::Speculator`.
            let full_context_layers = if method_allocates_full_context(&spec.method) {
                layers
            } else {
                cfg.get("layer_types")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter(|t| t.as_str() == Some("full_attention"))
                            .count() as u32
                    })
                    .unwrap_or(layers)
            };

            let weight_bytes = self
                .fetch_repo_file(&repo, subfolder.as_deref(), "model.safetensors.index.json")?
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|idx| index_total_size(&idx))
                .or_else(|| {
                    let info = self
                        .get(&format!(
                            "https://huggingface.co/api/models/{repo}?blobs=true"
                        ))
                        .ok()?;
                    let info: serde_json::Value = serde_json::from_str(&info).ok()?;
                    let n = siblings_safetensors_bytes(&info, subfolder.as_deref());
                    (n > 0).then_some(n)
                });

            Ok(Some(crate::model::Speculator {
                method: spec.method.clone(),
                source: Some(match &subfolder {
                    Some(s) => format!("{repo}/{s}"),
                    None => repo.clone(),
                }),
                num_speculative_tokens: spec.num_speculative_tokens,
                full_context_layers,
                kv_heads: cfg
                    .get("num_key_value_heads")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32),
                head_dimension: cfg
                    .get("head_dim")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32),
                weight_bytes,
                // The drafter's precision is its own: the FP8 Laguna-S repo
                // pairs with a BF16 drafter, so inheriting the target's would
                // halve the drafter's weight bytes.
                weight_precision: cfg
                    .get("torch_dtype")
                    .and_then(|v| v.as_str())
                    .and_then(crate::precision::Precision::from_torch_dtype),
            }))
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
