import type { Derivation, MemoryResult } from "../types";
import { Figure, Term } from "./Explain";

// Stacked memory composition bar (PRD §22.1):
//   Weights | Runtime reserve | KV @ concurrency | Free (KV headroom)
// The slices always sum to the usable, utilization-capped GPU memory.

interface Segment {
  label: string;
  value: number;
  color: string;
  /** Glossary key for the hover definition of this slice. */
  termKey: string;
}

/// The memory chain in dependency order, keyed to the derivations the engine
/// emits. Rendering one row per step (rather than the old single run-on grey
/// line) is what makes each step's math individually inspectable.
const MEMORY_CHAIN = [
  "m-physical",
  "m-available",
  "m-checkpoint",
  "m-weights",
  "m-runtime",
  "m-free",
  "kv-avg",
  "kv-max",
] as const;

/// Build a hard-stopped stacked bar from segment *widths*.
///
/// CSS gradient stops are absolute positions along the bar, not widths, and a
/// stop may not sit before its predecessor (the browser clamps it). Feeding
/// widths in directly therefore both smears each boundary into a blend and
/// silently reorders the slices: with weights 43% and KV 56%, KV collapsed to a
/// thin band while a 0.3% "free" slice rendered as ~44% of the bar.
///
/// Each segment emits two stops at its cumulative start and end, which produces
/// a flat block per segment and preserves the widths as given.
/// Takes only the two fields it needs, not a full `Segment`: the label and
/// glossary key are legend concerns and have no bearing on the gradient.
export function stackGradient(
  segments: Pick<Segment, "value" | "color">[],
  pct: (v: number) => number,
): string {
  const stops: string[] = [];
  let cursor = 0;
  for (const s of segments) {
    const width = pct(s.value);
    stops.push(`${s.color} ${cursor}%`, `${s.color} ${cursor + width}%`);
    cursor += width;
  }
  return `linear-gradient(to right, ${stops.join(", ")})`;
}

export function MemoryBar({
  m,
  derivations,
}: {
  m: MemoryResult;
  derivations: Record<string, Derivation>;
}) {
  // Derived from the result rather than re-applying the backend's default
  // utilization here: the lib computes freeForKV = available − weights − runtime,
  // so these three sum back to whatever utilization it actually used. Hardcoding
  // 0.9 drifts the moment utilization becomes user-overridable.
  const available = m.weightGiBPerGpu + m.runtimeGiBPerGpu + m.freeGiBPerGpu;
  const kvAtConcurrency = m.memoryConcurrencyAverage * m.kvGiBPerAverageSequence;
  const freeRemaining = Math.max(0, m.freeGiBPerGpu - kvAtConcurrency);

  const segments: Segment[] = [
    // purple = calculated
    { label: "Weights", value: m.weightGiBPerGpu, color: "#7c3aed", termKey: "weights" },
    { label: "Runtime", value: m.runtimeGiBPerGpu, color: "#6b7280", termKey: "runtime" }, // gray
    {
      label: "KV @ avg ctx",
      value: kvAtConcurrency,
      color: "#3b82f6", // blue
      termKey: "kv-at-concurrency",
    },
    {
      label: "Free (KV headroom)",
      value: freeRemaining,
      color: "#22c55e", // green
      termKey: "free-headroom",
    },
  ];

  // Base the bar on the larger of usable memory and the loaded weights so an
  // over-capacity (does-not-fit) model renders as an overflowing bar rather
  // than a broken percentage.
  const barTotal = Math.max(
    available,
    m.weightGiBPerGpu + m.runtimeGiBPerGpu + kvAtConcurrency,
  );
  const pct = (v: number) => (barTotal > 0 ? (v / barTotal) * 100 : 0);

  return (
    <div className="memory-bar">
      <div className="bar-stack" style={{ background: stackGradient(segments, pct) }} />
      <div className="bar-legend">
        {segments.map((s) => (
          <span key={s.label} className="legend-item">
            <i style={{ background: s.color }} />
            <Term termKey={s.termKey}>{s.label}</Term>
            <b>{s.value.toFixed(2)} GiB</b>
          </span>
        ))}
      </div>
      <div className="figures">
        {MEMORY_CHAIN.map((id) => {
          const dv = derivations[id];
          // The engine's own formatted result is used as the displayed value so
          // the row and its derivation can never disagree about the number.
          return dv ? (
            <Figure key={id} label={dv.label} value={dv.result} derivation={dv} />
          ) : null;
        })}
      </div>
    </div>
  );
}
