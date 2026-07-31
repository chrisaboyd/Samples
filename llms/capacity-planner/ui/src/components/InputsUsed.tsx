import { useState } from "react";
import type { InputFact } from "../types";

/// The subset of config.json / GPU catalog / workload settings that actually
/// reaches a formula.
///
/// A config.json carries far more keys than the calculation reads, so listing
/// only the consumed ones — with the originating key and the symbol each feeds —
/// answers "what did it actually use?" without dumping the whole file back.
export function InputsUsed({ facts }: { facts: InputFact[] }) {
  const [open, setOpen] = useState(false);
  if (!facts?.length) return null;

  // Preserve the engine's ordering within each group rather than sorting: it
  // emits them in the order the formulas consume them.
  const groups: string[] = [];
  for (const f of facts) if (!groups.includes(f.group)) groups.push(f.group);

  return (
    <section className="inputs-used">
      <button
        type="button"
        className="section-toggle"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
      >
        <span className="chev" aria-hidden="true">
          {open ? "▾" : "▸"}
        </span>
        Input values used in these calculations
        <span className="hint">
          {facts.length} of the config, hardware, and workload settings
        </span>
      </button>
      {open && (
        <div className="inputs-body">
          {groups.map((g) => (
            <div key={g} className="input-group">
              <h4>{g}</h4>
              <table>
                <tbody>
                  {facts
                    .filter((f) => f.group === g)
                    .map((f, i) => (
                      <tr key={`${f.name}-${i}`}>
                        <td className="fact-name">
                          {f.name}
                          {f.key && <code>{f.key}</code>}
                        </td>
                        <td className="fact-value">{f.value}</td>
                        <td className="fact-used">{f.usedFor}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
