import type React from "react";
import { useRef, useState } from "react";
import { MemoryBar } from "./components/MemoryBar";
import { useStore, GPU_SKUS } from "./store";
import type { Precision, ScenarioResult, Verdict } from "./types";
import { analyze, fetchConfig } from "./lib/invoke";
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

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
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
      setInputs({ configJson: cfg });
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

  const handleLoadConfig = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setInputs({ configJson: (ev.target?.result as string) ?? "" });
      setError(null);
    };
    reader.readAsText(file);
    e.target.value = "";
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
          <button onClick={() => fileRef.current?.click()} disabled={!result}>
            Load
          </button>
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
              onChange={(e) => setInputs({ configJson: e.target.value })}
              rows={8}
            />
            <div className="row">
              <input
                type="file"
                ref={configFileRef}
                accept=".json,application/json"
                onChange={handleLoadConfig}
                style={{ display: "none" }}
              />
              <button
                type="button"
                onClick={() => configFileRef.current?.click()}
              >
                Choose config.json…
              </button>
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
            <label className="field check">
              <input
                type="checkbox"
                checked={inputs.isHypotheticalWeight}
                onChange={(e) => setInputs({ isHypotheticalWeight: e.target.checked })}
              />
              <span>Hypothetical quantization</span>
            </label>
            <div className="field">
              <span>Weight precision</span>
              <select
                value={inputs.weightPrecision}
                onChange={(e) => setInputs({ weightPrecision: e.target.value as Precision })}
              >
                {PRECISIONS.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
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
  return (
    <>
      <div className={`verdict ${verdictClass(r.verdict)}`}>
        <span className="verdict-badge">{r.verdict.replace("_", " ")}</span>
        <span className="confidence">
          {r.confidence.memory} · Level {r.confidence.analyzeLevel.toUpperCase()}
        </span>
      </div>

      <div className="label-sm">{m.checkpointPrecisionLabel}</div>

      <MemoryBar m={m} />

      <div className="stats">
        <Stat label="Comfortable active (avg ctx)" value={m.memoryConcurrencyAverage} />
        <Stat label="Comfortable active (max ctx)" value={m.memoryConcurrencyMaximum} />
      </div>

      <div className="stub-note">
        Performance, SLO concurrency, and topology recommendation are Phase 3
        defers (shown as null). See the evidence/assumptions panels for provenance.
      </div>

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
