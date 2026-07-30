# LLM Capacity Planner — calculation library (Phase 1)

Portable Rust calculation core for the [LLM Capacity & Performance Planner](PRD.md)
(PRD §31 "Phase 1: Formula prototype"). Given a model `config.json` — local
file, pasted on stdin, or fetched from a Hugging Face URL — it produces a
structured [`ScenarioResult`](lib/src/result.rs) (PRD §25) JSON describing
**memory fit + KV-cache capacity + confidence**.

Phase 2 (the Tauri + React desktop UI) will consume this library as a dependency.

## Build

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

cargo test            # library + integration tests (offline)
cargo build           # CLI binary, no network
cargo build --features sources   # CLI binary with HuggingFace fetch
cargo clippy --all-targets --features sources -- -D warnings
cargo fmt --check
```

## CLI

```text
capacity-planner --url https://huggingface.co/poolside/Laguna-S-2.1 \
    --gpu "RTX PRO 6000 Blackwell Workstation Edition" --count 2 --tp 1

capacity-planner --file ./config.json --gpu "B200 SXM 180 GB"

cat config.json | capacity-planner                    # paste via stdin
```

Flags: `--weight-precision` (NVFP4|FP8|BF16|FP16|INT8|INT4|FP32),
`--kv-precision`, `--avg-context`, `--max-context`, `--hypothetical`.
Gated HuggingFace repos read `HF_TOKEN` from the environment (never logged).

## Architecture (Phase 1 surface)

```
lib/src/
  adapter/   Laguna / Llama / Mixtral / generic config.json -> NormalizedModel
  kv.rs      PRD §13 KV-cache (dense + hybrid sliding-window, block rounding)
  weight.rs  PRD §12 weight memory + hypothetical quantization + NVFP4 scales
  memory.rs  PRD §15 memory-fit (freeForKV = available − weights − runtime − …)
  hardware.rs  PRD §9 GPU catalog (RTX/H100/H200/B200) + topology defaults
  result.rs  PRD §25 ScenarioResult schema (performance/topology stubbed)
  sources.rs  optional HF fetcher (feature = `sources`)
```

The mathematical core is feature-gated and network-free; `cargo test` runs entirely offline.
