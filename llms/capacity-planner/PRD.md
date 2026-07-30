# PRD: Portable LLM Capacity & Performance Planner

**Working name:** LLM Capacity Planner
**Platforms:** macOS and Windows
**Primary user:** Solutions architects, platform engineers, AI infrastructure engineers
**Product type:** Local-first desktop application
**Status:** Initial product definition

---

## 1. Executive summary

LLM Capacity Planner is a small desktop application that answers:

> Can this model run on this GPU configuration, and what practical level of service should I expect?

A user supplies a Hugging Face model, local `config.json`, or pasted model configuration. The application analyzes the model architecture and compares it against one or more GPU configurations.

The application produces three distinct capacity answers:

1. **Memory capacity**

   * Does the model fit?
   * How much memory remains for KV cache?
   * How many active sequences fit at average and maximum context?

2. **Performance capacity**

   * What prefill and decode performance is theoretically possible?
   * What performance is likely under vLLM or Ollama?
   * How many simultaneously active requests can meet the selected latency target?

3. **Practical agent capacity**

   * How many continuously active agents can be supported?
   * How many intermittently active agents or human users could that represent?
   * What happens during bursts?

All results must carry an explicit confidence level. The application must never present an analytical tokens-per-second estimate as if it were a measured benchmark.

---

# 2. Problem statement

Sizing an LLM deployment currently requires manually combining:

* Model configuration
* Checkpoint tensor shapes
* Quantization format
* Model architecture
* KV-cache layout
* GPU memory
* GPU memory bandwidth
* Tensor-core capabilities
* GPU interconnect
* Inference-engine behavior
* Expected context and output lengths
* User or agent concurrency
* Latency requirements

Existing model-size calculators generally stop at:

> This model requires approximately X GB.

That is necessary but insufficient. A model may fit while still producing an unacceptable user experience. Conversely, a system that can hold only one maximum-length sequence may support many users whose normal contexts are much smaller and whose activity is intermittent.

The product should bridge the gap between **hardware fit calculations** and **real-world service planning**.

---

# 3. Goals

## 3.1 Primary goals

The application must allow a user to:

* Load a model from a Hugging Face URL.
* Paste a model’s `config.json`.
* select a local `config.json`.
* Optionally provide safetensors metadata, a checkpoint index, or a GGUF file.
* Select a checkpoint or hypothetical quantization format.
* Select one or more GPU types and quantities.
* Define average and maximum context lengths.
* Select a target model-step latency.
* Compare vLLM and Ollama.
* Determine whether the model fits.
* Estimate memory use and remaining KV-cache capacity.
* Estimate memory-limited active concurrency.
* Estimate performance-limited active concurrency.
* Translate active concurrency into agent and user capacity.
* Recommend an appropriate TP, DP, or EP topology.
* Explain every calculation and assumption.

## 3.2 Secondary goals

The application should:

* Work offline after hardware and engine data are installed.
* Save and compare scenarios.
* Export a result as JSON, CSV, PNG, or PDF.
* Generate suggested vLLM and Ollama launch parameters.
* Allow measured benchmark results to calibrate future estimates.
* Support private or gated Hugging Face repositories through an optional token.

## 3.3 Non-goals for the MVP

The MVP will not:

* Provision infrastructure.
* Launch production inference servers.
* Guarantee exact tokens per second without a benchmark.
* Execute arbitrary Hugging Face `trust_remote_code`.
* Download complete multi-hundred-gigabyte checkpoints merely to inspect them.
* Model CPU-offloaded inference as equivalent to GPU-resident inference.
* Estimate training or fine-tuning capacity.
* Calculate cloud cost unless a separate pricing module is later added.

---

# 4. Core terminology

The application must use precise terminology to avoid conflating users, agents, requests, and cached sequences.

| Term                        | Product definition                                                                              |
| --------------------------- | ----------------------------------------------------------------------------------------------- |
| **Logical user**            | A human or service account that may use the deployment                                          |
| **Logical agent**           | A persistent agent task, whether currently using the model or waiting on a tool                 |
| **Outstanding request**     | A request submitted but not yet complete                                                        |
| **Active request**          | A request currently in prefill or decode                                                        |
| **KV-resident sequence**    | A sequence whose processed tokens occupy GPU KV-cache memory                                    |
| **Memory ceiling**          | Maximum sequences that can physically reside in memory                                          |
| **SLO ceiling**             | Maximum active requests that meet the selected latency target                                   |
| **Comfortable concurrency** | The lower of the memory and SLO ceilings                                                        |
| **Logical-agent capacity**  | Estimated number of intermittent agents supported by comfortable concurrency                    |
| **Model step**              | One inference request, excluding external tool execution unless explicitly configured otherwise |

The top-level output should never simply say “supports 20 sessions.” It should instead say something like:

> Supports an estimated 12 simultaneously active requests at the average context, or approximately 40 intermittent coding agents under the selected workload profile.

---

# 5. Target users

## 5.1 Solutions architect

Needs a quick answer while designing or discussing infrastructure:

* Can model X run on two H200s?
* Does it need TP?
* Would two independent replicas be better?
* How many coding agents could it support?
* Is an RTX workstation viable for a pilot?

## 5.2 Platform engineer

Needs deeper details:

* Weight allocation per GPU
* KV-cache block capacity
* Runtime reserve
* Expected queueing
* Suggested vLLM arguments
* Prefix-cache assumptions
* Engine and quantization compatibility

## 5.3 Technical buyer

Needs comparison-oriented results:

* One RTX PRO 6000 versus two
* Two H100s versus one H200
* Memory capacity versus performance
* User-experience implications
* Headroom and failure tolerance

---

# 6. Primary user flow

## Step 1: Load model

The user selects one input method:

### Hugging Face URL

Example:

```text
https://huggingface.co/organization/model-name
```

The application retrieves, where available:

* `config.json`
* `generation_config.json`
* `tokenizer_config.json`
* `model.safetensors.index.json`
* Safetensors tensor metadata
* GGUF metadata
* Repository file sizes
* Model-card metadata
* Quantization metadata
* Revision or commit identifier

Hugging Face describes `config.json` as the model architecture blueprint, while the weights reside separately in safetensors or another checkpoint format. Its Hub API can expose repository file metadata and safetensors metadata without requiring the entire checkpoint to be downloaded.

### Paste configuration

The user pastes JSON into an editor with:

* JSON validation
* Syntax highlighting
* Recognized-field highlighting
* Missing-field warnings
* Manual override controls

### Local file

The user selects:

* `config.json`
* Optional safetensors index
* Optional one or more safetensors files
* Optional GGUF file
* Optional model directory

## Step 2: Confirm parsed architecture

The application displays:

* Architecture family
* Dense or MoE
* Total layers
* Full-attention layers
* Sliding/local-attention layers
* Hidden dimension
* Query heads
* KV heads
* Head dimension
* Expert count
* Active experts per token
* Maximum supported context
* Weight precision
* KV-cache precision
* Estimated or exact parameter count

Unknown or inferred values are visibly marked.

## Step 3: Define workload

The user selects a workload preset or custom values.

## Step 4: Select hardware

The user selects:

* GPU SKU
* Number of GPUs
* GPU topology
* Inference engine
* Candidate quantizations

## Step 5: Review results

The application displays:

* Fit verdict
* Memory breakdown
* Average-context concurrency
* Maximum-context concurrency
* Expected performance
* Recommended topology
* Confidence and assumptions
* Potential bottlenecks

---

# 7. Quick mode and advanced mode

The application should remain fast enough to use during a customer call.

## 7.1 Quick mode

Quick mode exposes only:

### Model

* Model source
* Quantization

### Workload

* Workload preset
* Average context
* Maximum context
* Target model-step latency

### Hardware

* GPU type
* GPU quantity
* Inference engine

Recommended workload presets:

| Preset           | Typical characteristics                                |
| ---------------- | ------------------------------------------------------ |
| Chat assistant   | Short prompts, moderate outputs, human think time      |
| Coding assistant | Medium context, medium outputs, intermittent requests  |
| Coding agent     | Long context, repeated tool loops, moderate duty cycle |
| Autonomous agent | Sustained loops, higher duty cycle, bursty subagents   |
| RAG service      | Shared prefixes, moderate input, short output          |
| Batch inference  | Sustained work, throughput prioritized over latency    |

Each preset supplies editable defaults for output length, request frequency, prefix reuse, duty cycle, and burst factor.

## 7.2 Advanced mode

Advanced mode exposes:

* Average input/context tokens
* p95 context tokens
* Maximum context tokens
* Average output tokens
* p95 output tokens
* Target time to first token
* Target total model-step latency
* Agent model-active duty cycle
* Requests per agent per minute
* Burst multiplier
* Prefix-cache hit rate
* KV-cache data type
* GPU-memory utilization
* Fixed runtime reserve
* Maximum batched tokens
* Maximum running sequences
* Chunked prefill
* Speculative decoding
* Draft-model memory
* Tensor-parallel size
* Data-parallel replicas
* Expert parallelism
* CPU offload
* Swap space
* Custom efficiency coefficients

---

# 8. Target latency definition

The proposed 5-, 10-, 20-, and 30-second values should be labeled:

> **Target model-step completion time**

This is the duration from request submission until the requested output is complete.

It consists of:

[
T_{step} =
T_{queue}+
T_{prefill}+
T_{decode}
]

The calculation is impossible without an expected output length. Therefore, workload presets must provide a default average output length.

For example:

* 5 seconds with 128 output tokens is very different from
* 5 seconds with 1,024 output tokens.

Advanced mode should separately expose:

* Target TTFT
* Target inter-token latency
* Target total step completion time

External tool execution should be excluded by default because GPU sizing cannot predict how long a compiler, API, browser, database, or test suite will take.

---

# 9. Hardware catalog

The application should maintain a versioned local hardware database.

Each GPU record should contain:

```text
Manufacturer
Product family
Exact SKU
Architecture
Memory capacity in marketed GB
Usable capacity in GiB
Memory bandwidth
BF16/FP16 throughput
FP8 throughput
FP4/NVFP4 throughput
PCIe generation and width
NVLink generation
Per-GPU NVLink bandwidth
MIG support
Supported quantization formats
Typical runtime reserve
Power consumption
Source and last-verified date
```

The application should use exact SKUs rather than ambiguous product families. For example:

* RTX PRO 6000 Blackwell Workstation Edition
* RTX PRO 6000 Blackwell Server Edition
* RTX 6000 Ada Generation
* H100 SXM 80 GB
* H200 SXM 141 GB
* B200 SXM 180 GB

These products differ materially. The RTX PRO 6000 Blackwell Workstation Edition has 96 GB and 1,792 GB/s bandwidth, while the server edition is listed at 96 GB and 1,597 GB/s. The RTX 6000 Ada has 48 GB and 960 GB/s.

The H200 SXM provides 141 GB, 4.8 TB/s memory bandwidth, and 900 GB/s NVLink. Current DGX B200 specifications expose 1,440 GB and 64 TB/s across eight B200 GPUs, corresponding to 180 GB and 8 TB/s per GPU; the system uses fifth-generation NVLink with 14.4 TB/s aggregate per-node NVLink bandwidth.

## Initial topology defaults

| GPU                    | Default topology    |
| ---------------------- | ------------------- |
| RTX 6000 Ada           | PCIe only           |
| RTX PRO 6000 Blackwell | PCIe only           |
| H100 SXM               | NVLink 4 / NVSwitch |
| H200 SXM               | NVLink 4 / NVSwitch |
| B200 SXM               | NVLink 5 / NVSwitch |

The user must be able to override topology. Two H100 PCIe cards are not equivalent to two H100 SXM GPUs on an HGX baseboard.

---

# 10. Model-analysis engine

## 10.1 Confidence hierarchy

The application should use the best available method in this order:

### Level A: Exact checkpoint inspection

Use actual tensor metadata to calculate:

* Tensor names
* Tensor dimensions
* Tensor data types
* Number of elements
* Quantization scales
* Total stored bytes
* Mixed-precision regions

This is the preferred method.

### Level B: Checkpoint index and repository sizes

Use:

* Safetensors shard index
* File sizes
* Quantization configuration
* Known format overhead

This provides a strong estimate but may not exactly equal loaded GPU memory.

### Level C: Architecture-derived calculation

Derive parameter counts from `config.json` and a known architecture adapter.

This is required when only the configuration is available.

### Level D: Generic approximation

Apply general transformer formulas and user-selected precision.

This should produce a low-confidence result with a prominent warning.

## 10.2 Architecture adapters

The parser should use adapters rather than one universal formula.

Initial adapters:

* Llama-like dense decoder
* Qwen-like dense decoder
* Mixtral-style MoE
* DeepSeek-style MoE
* Laguna custom hybrid MoE
* Generic decoder-only GQA/MQA/MHA
* Generic hybrid full/sliding attention

Later adapters:

* MLA
* Mamba and SSM hybrids
* Multimodal models
* Encoder-decoder models
* Recurrent or state-space architectures

Each adapter returns a normalized internal representation rather than allowing downstream calculations to depend on arbitrary model-specific field names.

## 10.3 Security requirement

The application must not execute arbitrary repository Python code.

A Hugging Face model may reference custom model code. The application may inspect that code as text, but automatic execution creates an unacceptable supply-chain risk.

For unsupported custom architectures, the application should:

* Inspect tensor names and shapes.
* Apply known pattern matching.
* Ask for manual overrides.
* Lower the confidence score.
* Allow a signed community architecture adapter in a future release.

---

# 11. Normalized model representation

All imported models should be converted into an internal structure resembling:

```typescript
interface NormalizedModel {
  identity: {
    repository?: string;
    revision?: string;
    architectureNames: string[];
  };

  modelType: "dense" | "moe" | "hybrid" | "unknown";

  dimensions: {
    vocabularySize?: number;
    hiddenSize: number;
    intermediateSize?: number;
    layerCount: number;
    attentionHeads?: number;
    kvHeads?: number;
    headDimension?: number;
  };

  attentionLayers: Array<{
    type: "full" | "sliding" | "local" | "mla" | "ssm";
    count: number;
    windowSize?: number;
  }>;

  moe?: {
    expertCount: number;
    activeExpertsPerToken: number;
    expertIntermediateSize: number;
    sharedExpertParameters?: number;
  };

  context: {
    nativeMaximum: number;
    checkpointMaximum?: number;
    ropeScaling?: Record<string, unknown>;
  };

  weights: {
    exactParameterCount?: number;
    estimatedParameterCount?: number;
    tensors?: TensorMetadata[];
    sourcePrecision?: string;
    quantization?: QuantizationMetadata;
  };
}
```

---

# 12. Weight-memory calculation

## 12.1 Exact path

Where tensor metadata is available:

[
W_{stored} =
\sum_i
\left(
N_i \times B_i
\right)
+
W_{scales}
+
W_{metadata}
]

Where:

* (N_i) is the number of elements in tensor (i)
* (B_i) is stored bytes per element
* (W_{scales}) includes quantization scales and zero points

Loaded GPU memory may differ because an inference engine may:

* Repack tensors
* Create kernel-specific layouts
* Dequantize unsupported layers
* Duplicate scales
* Pad dimensions
* Allocate communication buffers

The application should separately report:

* Checkpoint storage size
* Estimated loaded weight memory
* Engine-specific loaded memory

## 12.2 Hypothetical quantization

When the user selects a quantization that does not exist in the repository, the result must be labeled:

> Hypothetical quantization estimate

The engine applies the selected format only to compatible tensor categories.

Example categories:

* Attention projections
* Dense MLP
* Routed experts
* Shared experts
* Embeddings
* Output head
* Norms
* Routers
* Biases

This is necessary for mixed-precision models such as a checkpoint where expert weights use NVFP4 but attention, embeddings, routers, and shared experts remain BF16. vLLM’s mixed-precision model configuration supports different quantization algorithms on different layers, and NVFP4 itself includes per-group FP8 scales rather than costing exactly half a byte per parameter.

---

# 13. KV-cache calculation

For conventional MHA, GQA, or MQA attention:

[
KV_{sequence} =
2 \times
L \times
S \times
H_{KV} \times
D_{head} \times
B_{KV}
]

Where:

* 2 represents keys and values
* (L) is the number of cached attention layers
* (S) is context length
* (H_{KV}) is the number of KV heads
* (D_{head}) is head dimension
* (B_{KV}) is bytes per KV element

For hybrid full and sliding-window attention:

[
KV_{sequence} =
2 H_{KV} D_{head} B_{KV}
\left[
L_{full}S+
L_{sliding}\min(S,W)
\right]
]

Where (W) is the sliding-window size.

The calculator must also account for:

* KV block rounding
* Per-block metadata
* Tensor-parallel sharding
* Prefix-cache retention
* Draft-model KV cache
* Cross-attention cache
* Encoder cache
* MLA compressed cache
* Mamba or SSM recurrent state
* Hybrid cache-manager limitations

vLLM partitions KV cache into blocks, allocates those blocks on demand, supports FP8 KV cache, and includes specific cache management for hybrid attention models.

---

# 14. Runtime and activation memory

Runtime overhead should be divided into:

## Fixed per-GPU overhead

* CUDA context
* Loaded kernels
* Engine process
* CUDA graphs
* NCCL buffers
* Quantization metadata
* Allocator reserve
* Memory fragmentation
* Attention backend workspaces

## Per-scheduler-step overhead

* Batched hidden states
* Attention workspaces
* MoE routing buffers
* Logits
* Sampling buffers
* Chunked-prefill buffers
* Temporary quantization buffers

The estimate should use:

[
M_{runtime} =
M_{fixed}
+
M_{token} \times N_{scheduledTokens}
+
M_{sequence} \times N_{runningSequences}
]

The coefficients must be engine-, architecture-, and hardware-specific.

The UI should allow:

* Conservative
* Balanced
* Aggressive

memory profiles.

Example behavior:

| Profile      | Purpose                             |
| ------------ | ----------------------------------- |
| Conservative | Procurement and production planning |
| Balanced     | Typical deployment estimate         |
| Aggressive   | Maximum technical fit               |

---

# 15. Memory-fit calculation

For each GPU rank:

[
M_{available} =
M_{physical} \times U
]

[
M_{freeForKV} =
M_{available}
-------------

## M_{weightsPerRank}

## M_{runtime}

## M_{draft}

M_{communication}
]

The memory-limited sequence count is:

[
C_{memory} =
\left\lfloor
\frac{M_{freeForKV}}
{KV_{sequence}}
\right\rfloor
]

The calculation must be performed for at least:

* Average context
* p95 context
* Maximum context

The results should not assume every active request has the same context. Advanced mode should support a weighted context distribution and calculate:

[
\sum_i KV(S_i) \leq M_{freeForKV}
]

A Monte Carlo simulation can model mixed real-world request sizes in a later version.

---

# 16. Performance-estimation engine

## 16.1 Required outputs

For each scenario, estimate:

* Prefill tokens per second
* Decode tokens per second for one request
* Aggregate decode tokens per second
* Time to first token
* Time per output token
* Total model-step time
* Queue delay at selected concurrency
* Maximum concurrency meeting the latency target

## 16.2 Analytical baseline

The initial model should use a roofline calculation:

[
TPS_{decode} \leq
\min
\left(
\frac{BW_{effective}}
{BytesPerOutputToken},
\frac{Compute_{effective}}
{FLOPsPerOutputToken}
\right)
]

For dense models:

[
BytesPerOutputToken}
\approx
ActiveWeightBytes+
KVReadBytes+
TemporaryTraffic
]

For MoE models, active weight traffic is based on selected experts per token rather than all stored experts.

Prefill must be modeled separately from decode:

* Dense projection work scales approximately with token count.
* Full attention includes sequence-length-dependent attention work.
* Sliding attention depends on its window.
* Prefix-cache hits may avoid recomputing a shared prefix.

vLLM’s automatic prefix caching reuses KV blocks when requests share an identical prefix, reducing repeated prompt computation without changing model outputs.

## 16.3 Efficiency factors

Theoretical peak bandwidth and FLOPs cannot be used directly. Each result should apply empirically derived efficiency factors:

```text
Effective bandwidth utilization
Effective tensor-core utilization
MoE routing efficiency
Attention-kernel efficiency
TP collective efficiency
Scheduler and sampling overhead
```

Initial estimates may use broad ranges, such as:

* Pessimistic
* Expected
* Optimistic

The product should display a range rather than false precision.

## 16.4 Engine profiles

### vLLM profile

The vLLM profile should account for:

* Paged KV cache
* Chunked prefill
* Continuous batching
* Prefix caching
* FP8 KV cache
* CUDA graph memory
* Tensor parallelism
* Data parallelism
* Expert parallelism
* Maximum batched tokens
* Scheduler behavior

vLLM exposes TTFT, inter-token latency, queue time, running requests, waiting requests, prompt-token throughput, generation throughput, and cache utilization. It also provides a serving benchmark command suitable for calibrating the calculator.

### Ollama profile

The Ollama profile should account for:

* GGUF quantization
* Configured context length
* Parallel request count
* Loaded-model count
* GPU versus CPU placement
* Model queueing
* CPU offload
* Engine-supported architectures

Ollama states that required memory for a model scales with parallel request count multiplied by configured context length. When memory is insufficient for another model or request, work may queue until capacity becomes available.

Ollama also chooses default context lengths based on available VRAM, while allowing context length to be changed explicitly.

The application must not assume that a checkpoint supported by vLLM is automatically loadable by Ollama. Engine compatibility is a separate result from memory fit.

## 16.5 Performance confidence levels

| Grade           | Meaning                                                                                       |
| --------------- | --------------------------------------------------------------------------------------------- |
| **Measured**    | Imported or locally run benchmark for the exact model, engine, quantization, GPU and topology |
| **Calibrated**  | Benchmark exists for a closely related model or hardware configuration                        |
| **Analytical**  | Calculated from model architecture and hardware roofline                                      |
| **Speculative** | Missing architectural or engine-specific information                                          |

The UI should show:

```text
Expected decode: 85–115 tok/s
Confidence: Analytical
Primary uncertainty: NVFP4 MoE kernel efficiency
```

It should not show:

```text
Expected decode: 103.42 tok/s
```

unless that value came from a measured benchmark.

---

# 17. Benchmark calibration

Benchmark calibration is essential for making tokens-per-second predictions credible.

## MVP behavior

The application generates:

* A vLLM benchmark command
* An Ollama benchmark script
* A standardized prompt-length/output-length matrix

The user runs it on the target system and imports the resulting JSON.

## Later behavior

The application may connect to an existing inference endpoint and run a controlled benchmark after explicit user authorization.

Recommended benchmark matrix:

| Test              |            Input | Output | Concurrency |
| ----------------- | ---------------: | -----: | ----------: |
| Short interactive |               2K |    256 |  1, 2, 4, 8 |
| Coding            |              16K |    512 |  1, 2, 4, 8 |
| Long agent        |              64K |    512 |     1, 2, 4 |
| Extreme context   | Selected maximum |    128 |           1 |
| Decode-heavy      |               1K |     2K |  1, 2, 4, 8 |
| Prefill-heavy     |         32K–256K |     32 |     1, 2, 4 |

Imported calibration records should be keyed by:

```text
Model revision
Quantization
Inference engine and version
GPU SKU
GPU count
TP/DP/EP topology
Attention backend
KV data type
Driver version
CUDA version
Benchmark date
```

---

# 18. Concurrency model

The application should provide three concurrency values.

## 18.1 Memory concurrency

How many active sequences physically fit:

[
C_{memory}
]

## 18.2 SLO concurrency

How many requests can run before the selected latency objective is violated:

[
C_{SLO} =
\max C
\quad\text{such that}\quad
T_{step,p95}(C) \leq T_{target}
]

## 18.3 Comfortable active concurrency

[
C_{comfortable} =
\min(C_{memory}, C_{SLO})
]

This is the primary highlighted concurrency number.

---

# 19. Translating active concurrency into agents and users

Agent sessions ebb and flow. An agent may:

* Generate model output
* Execute a tool
* Wait for a network call
* Compile code
* Run tests
* Wait for a human

The application should use an **inference duty cycle**:

[
D =
\frac{\text{time actively requiring inference}}
{\text{total agent elapsed time}}
]

A first approximation of logical-agent capacity is:

[
A_{logical} =
\frac{C_{comfortable}}{D \times B}
]

Where (B) is a burst-safety factor greater than or equal to 1.

Example:

```text
Comfortable active concurrency: 8
Model-active duty cycle: 25%
Burst factor: 1.5
Estimated logical agents: 8 / (0.25 × 1.5) ≈ 21
```

The output must explain that this does not guarantee all 21 agents can simultaneously demand inference without queueing.

## Human-user model

For human users, the application can use Little’s Law:

[
L = \lambda W
]

Where:

* (L) is average outstanding concurrency
* (\lambda) is requests per second
* (W) is average request duration

Inputs:

* Number of users
* Requests per user per hour
* Average request duration
* Peak multiplier

Output:

* Expected average concurrency
* Expected peak concurrency
* Recommended replica count

The application should therefore distinguish:

* **Simultaneously active agents**
* **Logical intermittent agents**
* **Estimated human users**
* **Total registered users**

---

# 20. Parallelism recommendation engine

The application should evaluate:

* Single-GPU deployment
* Tensor parallelism
* Independent data-parallel replicas
* TP × DP
* Expert parallelism for MoE
* Pipeline parallelism where necessary
* Context parallelism in a later release

vLLM supports tensor, data, and expert parallel deployment, including sharding MoE experts separately from attention layers.

## Recommendation rules

### Rule 1: Prefer one GPU when practical

When the model, runtime, and target KV capacity fit comfortably on one GPU:

* Recommend TP=1.
* Scale throughput using independent replicas.

### Rule 2: Use the smallest TP that provides adequate fit

When the model cannot fit on one GPU:

* Enumerate TP sizes.
* Reject layouts that violate head, KV-head, expert, or kernel divisibility requirements.
* Select the smallest TP that leaves the required KV headroom.

### Rule 3: Penalize TP over PCIe

For RTX configurations:

* Apply a larger communication penalty.
* Prefer independent replicas when the model fits on one card.
* Recommend TP only for model fit, pooled KV capacity, or a proven benchmark advantage.

### Rule 4: Favor TP on NVLink when the model does not fit

For H100, H200, and B200 NVLink systems:

* Apply topology-specific collective bandwidth.
* Evaluate whether TP improves single-request latency.
* Compare one TP replica against multiple smaller replicas.

### Rule 5: Evaluate EP for large MoE models

For MoE models:

* Verify expert count and placement.
* Estimate all-to-all communication.
* Compare TP and EP.
* Prefer a hybrid DP-attention/EP-expert topology only where benchmark or calibrated data supports it.

## Recommendation output

Example:

```text
Recommended topology: 2 independent replicas, TP=1 per GPU

Why:
• The model fits on one GPU with 18 GiB KV headroom.
• Two replicas provide higher aggregate throughput.
• TP=2 would add PCIe communication to every layer.
• TP=2 provides more capacity for a single exceptionally long request,
  but lower expected team throughput.
```

The output should also provide the alternative:

```text
Alternative: TP=2
Best when: one request requires more KV memory than a single GPU provides.
```

---

# 21. Visual design

## 21.1 Overall style

* Dark mode by default
* Dense but readable
* Minimal decorative UI
* High information-to-space ratio
* Technical values visible without opening multiple dialogs
* Tooltips for every formula and assumption
* Color must not be the sole indicator of status

Suggested visual language:

* Green: comfortable
* Amber: fits with limitations
* Red: does not fit or misses SLO
* Blue: measured data
* Purple: calculated estimate
* Gray: unknown or unsupported

## 21.2 Main layout

```text
┌──────────────────────────────────────────────────────────────────┐
│ LLM Capacity Planner                              Save | Export   │
├───────────────────────┬──────────────────────────────────────────┤
│ MODEL                 │ FIT VERDICT                              │
│ Laguna-S-2.1          │ ✓ Fits on 1× RTX PRO 6000 NVFP4          │
│ MoE / Hybrid Attn     │ Confidence: High memory / Medium perf.   │
│ 117.6B parameters     │                                          │
├───────────────────────┼──────────────────────────────────────────┤
│ WORKLOAD              │ MEMORY PER GPU                           │
│ Avg context: 32K      │ [Weights][Runtime][KV][Free]             │
│ Max context: 256K     │                                          │
│ Output: 512           │                                          │
│ Step target: 10 sec   │                                          │
├───────────────────────┼──────────────────────────────────────────┤
│ HARDWARE              │ CONCURRENCY                              │
│ RTX PRO 6000 × 1      │ Average context:  ███████  7 comfortable │
│ PCIe 5                │ Maximum context:  █        1 comfortable │
│ vLLM / NVFP4          │ Memory ceiling vs SLO ceiling            │
├───────────────────────┼──────────────────────────────────────────┤
│ TOPOLOGY              │ PERFORMANCE                              │
│ Recommended: TP=1     │ TTFT and tok/s by active request count   │
│ Add GPUs as replicas  │ [interactive line chart]                 │
└───────────────────────┴──────────────────────────────────────────┘
```

---

# 22. Required charts

## 22.1 Memory composition chart

A stacked horizontal bar for each GPU:

```text
Weights | Runtime | KV at selected concurrency | Reserved | Free
```

Toggles:

* Average context
* p95 context
* Maximum context
* One active request
* Comfortable concurrency
* Maximum memory concurrency

## 22.2 Concurrency comparison chart

Grouped bars:

| Scenario        | Memory ceiling | SLO ceiling | Comfortable |
| --------------- | -------------: | ----------: | ----------: |
| Average context |              X |           Y |    min(X,Y) |
| p95 context     |              X |           Y |    min(X,Y) |
| Maximum context |              X |           Y |    min(X,Y) |

## 22.3 User-experience curve

X-axis:

* Simultaneously active requests

Y-series:

* Time to first token
* Per-request tokens per second
* Total model-step time
* Queue time

A vertical marker shows the recommended concurrency.

## 22.4 Hardware comparison chart

For selected GPU configurations:

* Fits or does not fit
* Comfortable active agents
* Logical-agent estimate
* Aggregate throughput
* Per-user output rate
* Maximum supported context
* Suggested topology

## 22.5 Context sensitivity chart

X-axis:

* Context length

Y-axis:

* KV memory per request
* Maximum memory concurrency

This chart makes the cost of long context immediately visible.

## 22.6 Assumption and confidence panel

Every result must provide:

* Inputs used
* Fields inferred
* Unsupported features
* Formula version
* Data-source revision
* Hardware-data revision
* Confidence grade
* Largest uncertainty

Apache ECharts is a suitable charting library because it supports dark themes and a broad range of composable chart types.

---

# 23. Proposed technical architecture

## Desktop shell

**Tauri 2**

* Windows and macOS support
* React or another web frontend
* Rust backend
* Native file access
* Local HTTP requests
* Smaller footprint than a full Chromium-bundled desktop runtime
* Clear separation between UI and trusted calculation logic

Tauri supports a shared web frontend with Rust application logic across Windows and macOS.

## Frontend

* React
* TypeScript
* Zustand or Redux Toolkit
* Apache ECharts
* Tailwind CSS or a small custom design system
* Monaco editor for pasted JSON

## Calculation core

Prefer Rust for:

* JSON validation
* Safetensors header parsing
* GGUF metadata parsing
* Large integer calculations
* Formula engine
* Local file processing
* Scenario simulation

Expose a stable typed API to the frontend through Tauri commands.

## Persistence

Use SQLite for:

* Saved models
* Saved hardware configurations
* Scenario history
* Benchmark calibrations
* Hardware catalog
* Formula versions
* Data-source provenance

SQLite is self-contained, serverless, and stores a complete database in a local file, making it appropriate for a portable local-first application.

## Secrets

Store Hugging Face tokens in:

* Windows Credential Manager
* macOS Keychain

Do not store tokens in SQLite or application logs.

---

# 24. Internal service modules

```text
Model Source Service
 ├── Hugging Face URL parser
 ├── Hub metadata client
 ├── Local file loader
 └── JSON paste parser

Model Normalizer
 ├── Architecture detection
 ├── Tensor inventory
 ├── Quantization detection
 └── Confidence scorer

Capacity Engine
 ├── Weight calculator
 ├── KV calculator
 ├── Runtime-memory model
 ├── Fit evaluator
 └── Context distribution simulator

Performance Engine
 ├── FLOP estimator
 ├── Bandwidth roofline
 ├── Prefill estimator
 ├── Decode estimator
 ├── Queue/concurrency model
 └── Benchmark calibration

Topology Optimizer
 ├── TP candidate generator
 ├── DP candidate generator
 ├── EP candidate generator
 ├── Interconnect penalty
 └── Recommendation scorer

Presentation Layer
 ├── Charts
 ├── Explanations
 ├── Comparison
 └── Export
```

---

# 25. Scenario-result schema

Each calculated result should preserve its assumptions:

```typescript
interface ScenarioResult {
  verdict: "comfortable" | "constrained" | "does_not_fit" | "unsupported";

  memory: {
    weightGiBPerGpu: number;
    runtimeGiBPerGpu: number;
    kvGiBPerAverageSequence: number;
    kvGiBPerMaximumSequence: number;
    freeGiBPerGpu: number;
    memoryConcurrencyAverage: number;
    memoryConcurrencyMaximum: number;
  };

  performance: {
    prefillTokensPerSecond?: Range;
    decodeTokensPerSecondPerRequest?: Range;
    aggregateDecodeTokensPerSecond?: Range;
    estimatedTTFT?: Range;
    estimatedStepLatency?: Range;
    sloConcurrency?: number;
  };

  practicalCapacity: {
    comfortableActiveRequests: number;
    intermittentAgents?: Range;
    humanUsers?: Range;
  };

  topology: {
    tensorParallel: number;
    dataParallel: number;
    expertParallel: boolean;
    explanation: string[];
    alternatives: TopologyOption[];
  };

  confidence: {
    memory: ConfidenceGrade;
    performance: ConfidenceGrade;
    concurrency: ConfidenceGrade;
    reasons: string[];
  };

  evidence: EvidenceRecord[];
  assumptions: AssumptionRecord[];
  warnings: string[];
}
```

---

# 26. Compatibility matrix

The product must maintain an engine-compatibility matrix containing:

* Model architecture
* Checkpoint format
* Quantization format
* GPU architecture
* Engine
* Minimum engine version
* Supported KV-cache formats
* Supported parallelism strategies
* Known limitations

A model may:

* Fit in memory but be unsupported by the engine.
* Be supported only in BF16 but not its selected quantization.
* Load successfully but lack an optimized kernel.
* Run on a GPU but fall back to a much slower implementation.

These states should appear separately:

```text
Memory fit: Yes
Engine support: Experimental
Optimized kernel: Unknown
Performance confidence: Low
```

---

# 27. Exported recommendation

The exported report should include:

## Executive result

```text
The selected model fits on this configuration.

Recommended topology:
2 independent vLLM replicas, one per RTX PRO 6000.

Expected use:
• Average-context comfortable concurrency: 6–10 active requests
• Maximum-context comfortable concurrency: 1 request per replica
• Estimated intermittent coding agents: 20–35
• Performance confidence: Analytical

Primary constraints:
• Decode memory bandwidth
• Large-context KV usage
• PCIe tensor-parallel communication
```

## Technical appendix

* Parsed architecture
* Exact formulas
* Weight categories
* KV calculation
* Runtime reserve
* Hardware specifications
* Quantization assumptions
* Performance coefficients
* Engine settings
* Suggested benchmark
* Confidence explanation

---

# 28. Suggested engine configuration output

## vLLM

Generate a proposed configuration containing values such as:

```text
tensor-parallel-size
data-parallel-size
enable-expert-parallel
gpu-memory-utilization
max-model-len
kv-cache-dtype
max-num-seqs
max-num-batched-tokens
enable-prefix-caching
enable-chunked-prefill
quantization
```

The configuration must be labeled as a recommendation and validated against the selected vLLM version.

## Ollama

Generate proposed values such as:

```text
OLLAMA_CONTEXT_LENGTH
OLLAMA_NUM_PARALLEL
OLLAMA_MAX_LOADED_MODELS
OLLAMA_MAX_QUEUE
```

Ollama’s documentation explicitly ties parallel request count and configured context length to required memory, so these values must be derived together rather than independently.

---

# 29. MVP scope

## Supported model structures

* Decoder-only transformers
* Dense MLP models
* Conventional MoE models
* MHA, GQA, and MQA
* Mixed full and sliding-window attention
* Laguna architecture adapter
* Untied or tied embeddings

## Supported checkpoint estimates

* FP32
* FP16
* BF16
* FP8
* NVFP4
* Generic INT8
* Generic INT4
* Existing GGUF file size

## Supported hardware

* RTX 6000 Ada
* RTX PRO 6000 Blackwell Workstation
* H100 SXM 80 GB
* H200 SXM 141 GB
* B200 SXM 180 GB
* User-defined GPU

## Supported topologies

* One GPU
* Multiple PCIe GPUs
* NVLink 4
* NVLink 5
* TP
* DP
* Basic EP recommendation

## Supported engines

* vLLM
* Ollama
* Generic inference engine

---

# 30. Deferred capabilities

## Version 1.1

* Exact GGUF tensor parsing
* AWQ
* GPTQ
* Marlin
* Multiple GPUs with mixed SKUs
* Prefix-sharing workload simulation
* Speculative decoding
* Benchmark import

## Version 1.2

* Live endpoint benchmark
* Cost per token
* Cloud GPU pricing
* Multi-node InfiniBand
* Kubernetes replica planning
* High-availability capacity
* Queue simulation
* p95 and p99 traffic simulations

## Version 2

* MLA
* Mamba and state-space models
* Multimodal cache calculations
* Disaggregated prefill and decode
* Context parallelism
* Remote fleet inventory
* Local GPU detection
* Public benchmark database
* Shareable scenario links
* Enterprise policy and approved-hardware catalogs

---

# 31. Recommended development phases

## Phase 1: Formula prototype

Build a command-line or library prototype that can:

* Parse `config.json`
* Normalize Laguna, Llama, and Mixtral
* Calculate parameter counts
* Calculate weight memory
* Calculate hybrid KV cache
* Evaluate one or more GPUs
* Return structured JSON

This isolates the difficult calculation work before UI development.

## Phase 2: Desktop MVP

Add:

* Tauri shell
* Model import
* Hardware selection
* Workload inputs
* Memory chart
* Fit verdict
* Average/max-context concurrency
* Formula explanations
* Scenario save/load

## Phase 3: Performance model

Add:

* Decode roofline
* Prefill estimate
* SLO-based concurrency
* vLLM/Ollama profiles
* TP-versus-DP scoring
* Confidence ranges

## Phase 4: Calibration

Add:

* Benchmark command generation
* Benchmark JSON import
* Calibration database
* Measured-versus-estimated charts

## Phase 5: Fleet planning

Add:

* User counts
* Requests per user
* Agent duty cycles
* Burst modeling
* Replica count
* N+1 capacity
* Department-scale projections

---

# 32. MVP acceptance criteria

The MVP is complete when:

1. A Hugging Face URL can be parsed into a normalized model profile.
2. A pasted or local `config.json` produces the same normalized result.
3. Laguna-S-2.1 is correctly identified as a hybrid MoE architecture.
4. The application recognizes full versus sliding-window attention.
5. The application calculates BF16, FP8, and NVFP4 weight scenarios.
6. The application calculates KV memory at average and maximum context.
7. The result distinguishes exact checkpoint size from hypothetical quantization.
8. A GPU configuration can contain one or more GPUs and a topology.
9. The application reports model fit and remaining KV capacity.
10. The application shows memory and SLO concurrency separately.
11. The application recommends TP or independent replicas and explains why.
12. Performance estimates are shown as ranges with confidence grades.
13. Unsupported engine/model combinations are explicitly identified.
14. No remote Python code is executed.
15. Every result includes its formulas, assumptions, source revision, and confidence.

---

# 33. Accuracy targets

## Deterministic calculations

For supported architectures:

* Parameter count: within 0.1% when complete tensor metadata exists
* Stored checkpoint bytes: within 1%
* Analytical KV cache: exact before engine block rounding
* Rounded KV cache: within one allocation block
* GPU memory unit conversion: exact

## Runtime estimates

Before calibration:

* Weight-load estimate target: within 5–10%
* Total-memory estimate target: within 10–15%
* Tokens-per-second result: displayed as a broad range
* SLO concurrency: explicitly marked analytical

After exact-system calibration:

* Decode throughput target: within 10%
* TTFT target: within 15%
* Maximum SLO concurrency: within one active request for small systems

---

# 34. Product risks

## Risk: `config.json` is insufficient

Mitigation:

* Prefer safetensors metadata.
* Support architecture adapters.
* Display missing data.
* Require manual overrides where needed.

## Risk: false tokens-per-second precision

Mitigation:

* Use ranges.
* Use confidence grades.
* Separate analytical from measured results.
* Provide benchmark calibration.

## Risk: engine behavior changes

Mitigation:

* Version engine profiles.
* Store the selected engine version in every scenario.
* Keep formulas and compatibility data independently updateable.

## Risk: hardware naming ambiguity

Mitigation:

* Use exact GPU SKUs.
* Store memory, bandwidth, and topology explicitly.
* Never infer NVLink solely from GPU family.

## Risk: custom model architectures

Mitigation:

* Never execute remote code.
* Build signed architecture adapters.
* Fall back to tensor inspection and manual overrides.

## Risk: “user count” produces misleading sizing

Mitigation:

* Require or infer request rate, duty cycle, output length, and burst factor.
* Show active requests separately from logical agents and registered users.

---

# 35. Recommended product principles

1. **Fit is not performance.**
2. **Maximum context is not average context.**
3. **Users are not concurrent requests.**
4. **Saved sessions do not necessarily occupy GPU memory.**
5. **A model that loads is not necessarily supported efficiently.**
6. **Theoretical throughput is not measured throughput.**
7. **Topology matters as much as GPU count.**
8. **Every estimate needs provenance and confidence.**
9. **Prefer ranges over false precision.**
10. **Make the result explainable enough for an architecture review.**

---

# 36. Most useful MVP result

The first release should optimize for producing this answer within approximately one minute of user interaction:

```text
MODEL
Laguna-S-2.1-NVFP4

HARDWARE
2× RTX PRO 6000 Blackwell, PCIe

FIT
Yes

RECOMMENDED TOPOLOGY
2 independent replicas, TP=1

WHY
The model fits on one GPU.
Independent replicas avoid PCIe tensor-parallel overhead.
TP=2 is available when a single request requires additional KV capacity.

MEMORY CAPACITY
Average context:
X active sequences per replica

Maximum context:
Y active sequences per replica

EXPECTED EXPERIENCE
Comfortable active concurrency:
Z requests

Estimated intermittent coding agents:
A–B agents

PERFORMANCE
Expected decode:
C–D tok/s per replica

Confidence:
High for memory
Medium-low for performance

NEXT VALIDATION
Run the generated vLLM benchmark using the selected context and output profile.
```

That result is simple enough for a customer conversation while preserving a detailed technical explanation underneath.

