import type React from "react";
import { useRef, useState } from "react";
import { MemoryBar } from "./components/MemoryBar";
import { Figure, Term } from "./components/Explain";
import type { BindingConstraint } from "./types";

/// Which ceiling produced the comfortable-requests number. Without it the value
/// duplicates whichever row won and says nothing about what to change.
/// Request counts are per replica; the cluster total only differs when more
/// than one replica is deployed, so the qualifier appears only when it matters.
function concurrency(perReplica: number, total: number): string {
  return perReplica === total
    ? `${total}`
    : `${total} total · ${perReplica} per replica`;
}

const BINDING_LABEL: Record<BindingConstraint, string> = {
  memory_at_maximum_context: "limited by KV memory at maximum context",
  memory_at_average_context: "limited by KV memory at average context",
  slo_latency: "limited by the SLO latency target",
};
import { InputsUsed } from "./components/InputsUsed";
import { indexDerivations, levelKey } from "./glossary";
import { useStore, GPU_SKUS } from "./store";
import type { MemoryProfile, Precision, Range, ScenarioResult, Verdict } from "./types";
import { analyze, fetchConfig, fetchIndex } from "./lib/invoke";
import "./App.css";

const PRECISIONS: Precision[] = ["fp16", "bf16", "fp8", "nvfp4", "int8", "int4", "fp32"];

function verdictClass(v: Verdict): string {
  switch (v) {
    case "comfortable":
      return "verdict-ok";
    case "constrained":
      return "verdict-warn";
    case "does_not_fit":
    case "unsupported":
      return "verdict-bad";
    default:
      return "";
  }
}

function NumberInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        type="number"
        min={1}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </label>
  );
}


/// Format one endpoint with enough precision to stay informative at any
/// magnitude. Fixed 1-decimal formatting rendered sub-second step latencies
/// (~0.001 s) as a useless "0.0–0.0".
function formatMagnitude(v: number): string {
  const abs = Math.abs(v);
  if (abs >= 100) return Math.round(v).toLocaleString();
  if (abs >= 10) return v.toFixed(1);
  if (abs >= 1) return v.toFixed(2);
  if (abs >= 0.01) return v.toFixed(3);
  return v.toPrecision(2);
}

/// Split/join rather than `replace`, which substitutes only the first match and
/// left the one multi-underscore verdict rendering as "does not_fit".
/// (`replaceAll` would need an ES2021 lib target.)
export function formatVerdict(v: Verdict): string {
  return v.split("_").join(" ");
}

export function formatRange(r: Range | null): string {
  if (!r) return "—";
  // Sub-second durations read far better in milliseconds.
  if (r.unit === "seconds" && Math.abs(r.max) < 1) {
    return `${formatMagnitude(r.min * 1000)}–${formatMagnitude(r.max * 1000)} ms`;
  }
  return `${formatMagnitude(r.min)}–${formatMagnitude(r.max)} ${r.unit}`;
}

export default function App() {
  const {
    inputs,
    setInputs,
    result,
    setResult,
    error,
    setError,
    loading,
    setLoading,
  } = useStore();
  const [url, setUrl] = useState("");

  const handleFetch = async () => {
    if (!url.trim()) return;
    setLoading(true);
    try {
      const cfg = await fetchConfig(url);
      // The index is what makes the weight total exact rather than derived, so
      // it is fetched with the config rather than as a separate opt-in. A repo
      // without one is normal and must not fail the config fetch.
      const idx = await fetchIndex(url).catch(() => null);
      setInputs({ configJson: cfg, indexJson: idx });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = async () => {
    setLoading(true);
    try {
      const r: ScenarioResult = await analyze(inputs);
      setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleCopyJson = async () => {
    if (!result) return;
    await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
  };

  const fileRef = useRef<HTMLInputElement>(null);
  const configFileRef = useRef<HTMLInputElement>(null);

  const handleSave = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = "scenario.json";
    a.click();
    URL.revokeObjectURL(href);
  };

  const handleLoad = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const parsed = JSON.parse(
          (ev.target?.result as string) ?? "",
        ) as ScenarioResult;
        setResult(parsed);
        setError(null);
      } catch (err) {
        setError(String(err));
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  // Accepts config.json and model.safetensors.index.json together — both live in
  // the same model directory, and the index is what turns a derived weight total
  // into a measured one. Files are told apart by shape rather than by filename,
  // since a downloaded copy is often renamed.
  const handleLoadConfig = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    e.target.value = "";
    if (files.length === 0) return;

    let config: string | null = null;
    let index: string | null = null;
    for (const file of files) {
      const text = await file.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        setError(`${file.name} is not valid JSON`);
        return;
      }
      const obj = parsed as Record<string, unknown>;
      if (obj?.weight_map || obj?.metadata) index = text;
      else config = text;
    }

    // Always set both. Leaving a previously fetched index in place while the
    // config changes underneath it would size one checkpoint with another's
    // byte total.
    setInputs({ configJson: config ?? inputs.configJson, indexJson: index });
    setError(null);
  };

  const hasModel = !!inputs.configJson.trim();

  return (
    <main className="app">
      <header className="header">
        <h1>LLM Capacity Planner</h1>
        <div className="header-actions">
          <span className="provenance">v{result?.provenance.formulaVersion ?? "—"}</span>
          <input
            type="file"
            ref={fileRef}
            accept="application/json,.json"
            onChange={handleLoad}
            style={{ display: "none" }}
          />
          {/* Always enabled: loading a saved scenario is exactly what you do
              when you have no result yet. */}
          <button onClick={() => fileRef.current?.click()}>Load</button>
          <button onClick={handleSave} disabled={!result}>
            Save
          </button>
        </div>
      </header>

      <div className="grid">
        {/* Left column: inputs */}
        <section className="panel inputs">
          <fieldset>
            <legend>Model</legend>
            <textarea
              placeholder="Paste model config.json here"
              value={inputs.configJson}
              onChange={(e) =>
                // Clear any index fetched for a previous model: it describes a
                // checkpoint that is no longer the one in the box.
                setInputs({ configJson: e.target.value, indexJson: null })
              }
              rows={8}
            />
            <div className="row">
              <input
                type="file"
                ref={configFileRef}
                accept=".json,application/json"
                multiple
                onChange={handleLoadConfig}
                style={{ display: "none" }}
              />
              <button
                type="button"
                onClick={() => configFileRef.current?.click()}
                title="Select config.json, and model.safetensors.index.json too for an exact weight total"
              >
                Choose config.json…
              </button>
              {inputs.indexJson && (
                <span className="provenance">index loaded — exact weights</span>
              )}
              <span className="hint">or paste above</span>
            </div>
            <div className="row url-row">
              <input
                type="url"
                placeholder="https://huggingface.co/org/model"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
              <button onClick={handleFetch} disabled={loading || !url.trim()}>
                {loading ? "Loading…" : "Fetch from HF"}
              </button>
            </div>
          </fieldset>

          <fieldset>
            <legend>Hardware</legend>
            <div className="field">
              <span>GPU SKU</span>
              <select value={inputs.gpu} onChange={(e) => setInputs({ gpu: e.target.value })}>
                {GPU_SKUS.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <NumberInput
              label="GPU count"
              value={inputs.count}
              onChange={(v) => setInputs({ count: Math.max(1, v) })}
            />
            <NumberInput
              label="Tensor parallel (TP)"
              value={inputs.tensorParallel}
              onChange={(v) => setInputs({ tensorParallel: Math.max(1, v) })}
            />
            {/* Replicas are a deployment choice, not a quotient: 8 GPUs at TP=4
                can be 2 copies or 1 copy with 4 cards spare. Blank = fill the
                machine, so the common case needs no input. */}
            <NumberInput
              label="Replicas"
              value={inputs.replicas ?? Math.max(1, Math.floor(inputs.count / inputs.tensorParallel))}
              onChange={(v) => setInputs({ replicas: Math.max(1, v) })}
            />
            <div className="label-sm">
              {inputs.replicas === null
                ? `filling the machine — ${Math.max(1, Math.floor(inputs.count / inputs.tensorParallel))} × TP ${inputs.tensorParallel}`
                : `${inputs.replicas} × TP ${inputs.tensorParallel} = ${inputs.replicas * inputs.tensorParallel} of ${inputs.count} GPUs`}
            </div>
          </fieldset>

          <fieldset>
            <legend>Workload</legend>
            <NumberInput
              label="Average context (tokens)"
              value={inputs.avgContextTokens}
              onChange={(v) => setInputs({ avgContextTokens: v })}
            />
            <NumberInput
              label="Maximum context (tokens)"
              value={inputs.maxContextTokens}
              onChange={(v) => setInputs({ maxContextTokens: v })}
            />
            <NumberInput
              label="Avg output tokens"
              value={inputs.avgOutputTokens}
              onChange={(v) => setInputs({ avgOutputTokens: Math.max(1, v) })}
            />
            <NumberInput
              label="SLO target (seconds)"
              value={inputs.sloTargetSeconds}
              onChange={(v) => setInputs({ sloTargetSeconds: Math.max(0.1, v) })}
            />
            {/* Engine scheduler settings. These are not cosmetic: activation
                memory scales with the widest step, and max_num_seqs both
                reserves per-sequence buffers and caps concurrency (PRD §14). */}
            <NumberInput
              label="max_num_batched_tokens"
              value={inputs.maxNumBatchedTokens}
              onChange={(v) => setInputs({ maxNumBatchedTokens: Math.max(1, v) })}
            />
            <NumberInput
              label="max_num_seqs"
              value={inputs.maxNumSeqs}
              onChange={(v) => setInputs({ maxNumSeqs: Math.max(1, v) })}
            />
            <div className="field">
              <span>Memory profile</span>
              <select
                value={inputs.memoryProfile}
                onChange={(e) =>
                  setInputs({ memoryProfile: e.target.value as MemoryProfile })
                }
              >
                <option value="conservative">
                  Conservative — procurement and production planning
                </option>
                <option value="balanced">Balanced — typical deployment</option>
                <option value="aggressive">
                  Aggressive — maximum technical fit
                </option>
              </select>
            </div>
            {/* Unchecked, weights are sized from the checkpoint's own
                `quantization_config` — including the tensors it left at full
                precision. The selector below is a what-if that replaces that,
                so it is disabled until the override is explicitly requested. */}
            <label className="field check">
              <input
                type="checkbox"
                checked={inputs.isHypotheticalWeight}
                onChange={(e) => setInputs({ isHypotheticalWeight: e.target.checked })}
              />
              <span>Override checkpoint precision (what-if)</span>
            </label>
            <div className="field">
              <span>Weight precision</span>
              <select
                value={inputs.weightPrecision}
                disabled={!inputs.isHypotheticalWeight}
                onChange={(e) => setInputs({ weightPrecision: e.target.value as Precision })}
              >
                {PRECISIONS.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
            {!inputs.isHypotheticalWeight && (
              <p className="hint">
                Weights are sized from the checkpoint's own quantization_config.
              </p>
            )}
            <div className="field">
              <span>KV-cache precision</span>
              <select
                value={inputs.kvPrecision}
                onChange={(e) => setInputs({ kvPrecision: e.target.value as Precision })}
              >
                {PRECISIONS.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
          </fieldset>

          <button className="primary" onClick={handleAnalyze} disabled={loading || !hasModel}>
            {loading ? "Calculating…" : "Analyze"}
          </button>
        </section>

        {/* Right column: results */}
        <section className="panel results">
          {error ? (
            <div className="warning">{error}</div>
          ) : !result ? (
            <div className="placeholder">
              Load a model (paste or fetch from HuggingFace) and click Analyze.
            </div>
          ) : (
            <ResultView r={result} onCopyJson={handleCopyJson} />
          )}
        </section>
      </div>
    </main>
  );
}

function ResultView({ r, onCopyJson }: { r: ScenarioResult; onCopyJson: () => void }) {
  const m = r.memory;
  // Saved scenarios written before derivations existed have no such field, so
  // every lookup below must tolerate a miss rather than assume one is present.
  const dv = indexDerivations(r.derivations ?? []);
  return (
    <>
      <div className={`verdict ${verdictClass(r.verdict)}`}>
        <Term termKey={r.verdict}>
          <span className="verdict-badge">{formatVerdict(r.verdict)}</span>
        </Term>
        <span className="confidence">
          <Term termKey={r.confidence.memory}>{r.confidence.memory}</Term>
          {" · "}
          <Term termKey={levelKey(r.confidence.analyzeLevel)}>
            Level {r.confidence.analyzeLevel.toUpperCase()}
          </Term>
        </span>
      </div>

      <div className="label-sm">{m.checkpointPrecisionLabel}</div>

      {/* The headline capacity numbers lead; the memory breakdown that produces
          them follows. Each row expands to the formula that derived it. */}
      <div className="figures headline">
        <Figure
          label={`Comfortable active requests — ${BINDING_LABEL[r.practicalCapacity.bindingConstraint]}`}
          value={r.practicalCapacity.comfortableActiveRequests}
          derivation={dv["c-comfortable"]}
        />
        {/* "Memory ceiling" named the mechanism, not the quantity. These are
            request counts, and with >1 replica the per-replica and cluster
            figures differ — showing only one invited exactly that confusion. */}
        <Figure
          label="Concurrent requests @ avg context"
          value={concurrency(m.memoryConcurrencyAverage, m.memoryConcurrencyAverageTotal)}
          derivation={dv["c-mem-avg"]}
        />
        <Figure
          label="Concurrent requests @ max context"
          value={concurrency(m.memoryConcurrencyMaximum, m.memoryConcurrencyMaximumTotal)}
          derivation={dv["c-mem-max"]}
        />
      </div>

      <div className="figures">
        <Figure
          label="Deployment"
          value={`${r.topology.dataParallel} replica(s) x TP ${r.topology.tensorParallel} = ${r.topology.gpusInUse} GPU(s)${
            r.topology.gpusIdle > 0 ? ` (${r.topology.gpusIdle} idle)` : ""
          }`}
        />
        {/* The per-GPU slice alone reads as though the other cards were ignored.
            Within a TP group the KV pool is shared, so the cluster figure is the
            one that matches how people reason about the box. */}
        <Figure
          label="KV pool across GPUs in use"
          value={`${m.freeGiBAcrossGpusInUse.toFixed(2)} GiB`}
        />
        <Figure
          label="KV per sequence @ max ctx (whole TP group)"
          value={`${m.kvGiBPerMaximumSequenceAllRanks.toFixed(3)} GiB`}
        />
      </div>

      <h3 className="section-head">Memory per GPU</h3>
      <MemoryBar m={m} derivations={dv} />

      {r.performance.sloConcurrency === null ? (
        // Unpopulated performance is a real state (e.g. weights do not fit), and
        // the note explains why — silently omitting the section hid the reason.
        <div className="stub-note">{r.performance.note}</div>
      ) : (
        <div className="perf">
          <h3 className="section-head">Performance</h3>
          <div className="figures">
            <Figure
              label="Decode (per request)"
              value={formatRange(r.performance.decodeTokensPerSecondPerRequest)}
              derivation={dv["p-decode"]}
            />
            <Figure
              label="Prefill"
              value={formatRange(r.performance.prefillTokensPerSecond)}
              derivation={dv["p-prefill"]}
            />
            <Figure
              label="Aggregate decode"
              value={formatRange(r.performance.aggregateDecodeTokensPerSecond)}
              derivation={dv["p-aggregate"]}
            />
            <Figure
              label="SLO concurrency"
              value={r.performance.sloConcurrency}
              derivation={dv["p-slo"]}
            />
            {/* Units come from formatRange (it switches to ms below 1 s), so the
                label must not hardcode one. */}
            <Figure
              label="Step latency"
              value={formatRange(r.performance.estimatedStepLatency)}
              derivation={dv["p-step"]}
            />
            <Figure
              label="TTFT"
              value={formatRange(r.performance.estimatedTTFT)}
              derivation={dv["p-ttft"]}
            />
            <Figure
              label="FLOPs per token"
              value={dv["p-flops-token"]?.result ?? "—"}
              derivation={dv["p-flops-token"]}
            />
          </div>
        </div>
      )}

      <InputsUsed facts={r.inputsUsed ?? []} />

      {!!r.warnings.length && (
        <ul className="warnings">
          {r.warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}

      <div className="evidence">
        <h3>Evidence</h3>
        <ul>
          {r.evidence.map((e, i) => (
            <li key={i}>
              <b>{e.what}:</b> {e.value} <i>({e.source})</i>
            </li>
          ))}
        </ul>
        <h3>Assumptions</h3>
        <ul>
          {r.assumptions.map((a) => (
            <li key={a.id}>{a.description}</li>
          ))}
        </ul>
        <button onClick={onCopyJson}>Copy result JSON</button>
      </div>
    </>
  );
}
