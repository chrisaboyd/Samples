import type { MemoryResult } from "../types";

// Stacked memory composition bar (PRD §22.1):
//   Weights | Runtime reserve | KV @ concurrency | Free (KV headroom)
// The slices always sum to the usable, utilization-capped GPU memory.

interface Segment {
  label: string;
  value: number;
  color: string;
}

export function MemoryBar({ m }: { m: MemoryResult }) {
  const available = m.physicalGiBPerGpu * 0.9; // matches the lib's default utilization
  const kvAtConcurrency = m.memoryConcurrencyAverage * m.kvGiBPerAverageSequence;
  const freeRemaining = Math.max(0, m.freeGiBPerGpu - kvAtConcurrency);

  const segments: Segment[] = [
    { label: "Weights", value: m.weightGiBPerGpu, color: "#7c3aed" }, // purple = calculated
    { label: "Runtime", value: m.runtimeGiBPerGpu, color: "#6b7280" }, // gray
    { label: "KV @ avg ctx", value: kvAtConcurrency, color: "#3b82f6" }, // blue
    { label: "Free (KV headroom)", value: freeRemaining, color: "#22c55e" }, // green
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
      <div
        className="bar-stack"
        style={{
          background: `linear-gradient(to right, ${segments
            .map((s) => `${s.color} ${pct(s.value)}%`)
            .join(", ")})`,
        }}
      />
      <div className="bar-legend">
        {segments.map((s) => (
          <span key={s.label} className="legend-item">
            <i style={{ background: s.color }} />
            <span>{s.label}</span>
            <b>{s.value.toFixed(2)} GiB</b>
          </span>
        ))}
      </div>
      <div className="bar-foot">
        Physical {m.physicalGiBPerGpu.toFixed(1)} GiB · KV/seq @ avg ctx{" "}
        <b>{m.kvGiBPerAverageSequence.toFixed(3)} GiB</b> · KV/seq @ max ctx{" "}
        <b>{m.kvGiBPerMaximumSequence.toFixed(2)} GiB</b>
      </div>
    </div>
  );
}
