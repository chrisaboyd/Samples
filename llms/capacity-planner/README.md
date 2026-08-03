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

By default weights are sized from the checkpoint's own `quantization_config`,
including the tensors its `ignore` list left at full precision — so a model whose
routed experts are NVFP4 but whose attention, embeddings, and last eight expert
layers are BF16 is reported as the mix it is. `--hypothetical true` replaces that
with `--weight-precision` to answer "what if this model were quantized to X?";
the result is then labelled and warned as an estimate, not a checkpoint.

## Architecture (Phase 1 surface)

```
lib/src/
  adapter/   Laguna / Llama / Mixtral / generic config.json -> NormalizedModel
  quant.rs   compressed-tensors quantization_config -> per-tensor precision
  kv.rs      PRD §13 KV-cache (dense + hybrid sliding-window, block rounding)
  weight.rs  PRD §12 weight memory + hypothetical quantization + NVFP4 scales
  memory.rs  PRD §15 memory-fit (freeForKV = available − weights − runtime − …)
  hardware.rs  PRD §9 GPU catalog (RTX/H100/H200/B200) + topology defaults
  result.rs  PRD §25 ScenarioResult schema (topology stubbed)
  performance.rs  PRD §16 roofline: batch-aware decode step, SLO concurrency
  explain.rs  worked derivations + the inputs each formula consumes
  sources.rs  optional HF fetcher (feature = `sources`)
```

### Performance model (PRD §16)

The decode unit of work is one **step at batch `B`**, not one request. Continuous
batching reads each weight matrix once per step and reuses it across the batch, so
only KV and activation traffic scale with `B`:

```text
T_step(B) = max( (W_step(B) + B × (KV_seq + temp)) / BW_eff,
                 B × FLOPs_per_token / Compute_eff )
W_step(B) = dense_bytes + routed_bytes × (1 − (1 − k/E)^B)
```

The MoE term matters: at `B = 1` a 10-of-256 router touches ~4% of experts, but a
large batch touches nearly all of them, which is why MoE loses its batch-1 bandwidth
advantage at scale. `slo_concurrency` is the largest `B` satisfying
`T_prefill + avg_output × T_step(B) ≤ target`, capped by `C_memory` — a batch that
does not fit in KV memory is not a candidate however fast it would run.

### Showing the math (`explain.rs`)

A number with no visible derivation is an assertion, not an estimate. Every
published figure therefore ships with its own worked derivation, and
`ScenarioResult` carries two extra blocks:

- **`derivations`** — one entry per figure: plain-English `meaning`, the symbolic
  `formula`, that formula with this scenario's numbers substituted, and the
  `result`. Keyed by a stable `id` (`c-comfortable`, `kv-avg`, `p-step`, …).
- **`inputsUsed`** — only the values that actually reach a formula, grouped
  Model / GPU / Workload / Engine, each carrying its originating `config.json`
  key and the symbol it feeds (`num_key_value_heads` → `H_kv` → `KV_seq`). A
  `config.json` has far more keys than the calculation reads; this is the subset
  that mattered.

Both are built inside `memory::evaluate` and `performance::evaluate_explained`
from the *same* locals the calculation used, so the math shown can never drift
from the math that ran. The strings are also deliberately restricted to glyphs a
monospace font renders unambiguously — `/` and `floor(…)` rather than `÷` and
`⌊…⌋`, which are near-indistinguishable from `+` and `[…]` at UI sizes and turn a
division into an apparent addition.

# Desktop UI (Phase 2)

A Tauri 2 + React/TypeScript shell in `ui/` that consumes `lib` as a path dependency
via one `#[tauri::command] analyze(...)`. It exposes the PRD §21.2 three-pane
layout: model input (paste / local file / HuggingFace URL), hardware + workload
controls, and the fit verdict with the §22.1 memory composition bar, evidence and
assumptions panels, and JSON save/load.

Every figure is explainable in place. Clicking a row expands the engine's
derivation for that number — formula, your inputs substituted, result — and the
"Input values used in these calculations" panel lists what the formulas actually
consumed. Jargon that has no number of its own (the verdict, the confidence
grade, the Level A–D analysis level, the memory-bar segments) carries a
hover/focus definition from `ui/src/glossary.ts`; anything *with* a number takes
its explanation from the backend instead, so the UI never restates the math.

```bash
cd ui
npm install            # one-time: React + Vite + Tauri toolchain
npm run tauri dev      # launch the desktop window (hot reload)
npm run tauri build    # release bundle (target/release/bundle/...)
npm run build          # type-check + Vite production bundle only
```

Verify without the GUI:
```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cd ui && npm test          # vitest: IPC payload shape, bar geometry, formatting
```

The frontend tests are not optional extras: the `analyze` IPC contract can only be
checked from the frontend side. A Rust-side test that writes its own payload proves
nothing about what `invoke()` actually sends — `ui/src/lib/invoke.test.ts` reads the
shape from the production `analyzeArgs()` instead. The same reasoning applies to
`ui/src/glossary.test.ts`: it asserts against the committed golden scenario that
the engine still emits every derivation id the result panel looks up. A renamed
id would otherwise drop a "show the math" expander silently — the number keeps
rendering, so nothing looks broken.

> The native window cannot be launched headlessly here; `cargo check` + `npm run
> build` prove the stack compiles, and the Rust `analyze_core` unit test pins the
> Laguna/B200/NVFP4 numbers. Tests, plans, and exact coverage boundaries are in
> `lib/tests/reference.rs` and the plan file under
> `~/Library/Application Support/poolside/plans/`.

The mathematical core is feature-gated and network-free; `cargo test` runs entirely offline.
