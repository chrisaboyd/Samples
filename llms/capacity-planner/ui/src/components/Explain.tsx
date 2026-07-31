import { useId, useState } from "react";
import { lookup } from "../glossary";
import type { Derivation } from "../types";

/// A term with a definition, revealed on hover or keyboard focus.
///
/// `tabIndex` (not just `:hover`) so the definition is reachable without a
/// pointer; the dotted underline is what signals there is something to reveal.
export function Term({ termKey, children }: { termKey: string; children: React.ReactNode }) {
  const entry = lookup(termKey);
  const id = useId();
  if (!entry) return <>{children}</>;
  return (
    <span className="term" tabIndex={0} aria-describedby={id}>
      {children}
      <span className="tip" role="tooltip" id={id}>
        <b>{entry.title}</b>
        {entry.definition}
      </span>
    </span>
  );
}

/// One labelled figure with its derivation available in place.
///
/// Click-to-expand rather than hover: the substitution runs to several lines and
/// is meant to be read and compared against a neighbouring figure, which a
/// tooltip that vanishes on pointer-out cannot support.
export function Figure({
  label,
  value,
  derivation,
  termKey,
}: {
  label: string;
  value: number | string;
  derivation?: Derivation;
  termKey?: string;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const labelNode = termKey ? <Term termKey={termKey}>{label}</Term> : label;

  if (!derivation) {
    return (
      <div className="figure">
        <span className="figure-label">{labelNode}</span>
        <b className="figure-value">{value}</b>
      </div>
    );
  }

  return (
    <div className={`figure ${open ? "open" : ""}`}>
      <button
        type="button"
        className="figure-row"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-controls={id}
      >
        <span className="figure-label">{labelNode}</span>
        <b className="figure-value">{value}</b>
        <span className="chev" aria-hidden="true">
          {open ? "▾" : "▸"}
        </span>
      </button>
      {open && (
        <div className="derivation" id={id}>
          <p className="derivation-meaning">{derivation.meaning}</p>
          <div className="derivation-block">
            <span className="derivation-tag">formula</span>
            <pre>{derivation.formula}</pre>
          </div>
          <div className="derivation-block">
            <span className="derivation-tag">with your inputs</span>
            <pre>{derivation.substitution}</pre>
          </div>
          <div className="derivation-block">
            <span className="derivation-tag">result</span>
            <pre className="derivation-result">{derivation.result}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
