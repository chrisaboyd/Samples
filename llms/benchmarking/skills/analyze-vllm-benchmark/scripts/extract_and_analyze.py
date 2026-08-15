#!/usr/bin/env python3
"""Read a vLLM benchmark Job/log and produce normalized JSON and Markdown."""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


SELECTOR = "app.kubernetes.io/name=vllm-behavior-benchmark"
EXPECTED_TESTS = [f"T{i:02d}" for i in range(1, 11)]


def run_command(command: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(command, env=env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed: {result.stderr.strip()}")
    return result.stdout


def choose_job(kubeconfig: str, namespace: str, requested: str | None) -> tuple[str, str]:
    env = {**os.environ, "KUBECONFIG": os.path.expanduser(kubeconfig)}
    if requested:
        raw = run_command(["kubectl", "-n", namespace, "get", "job", requested, "-o", "json"], env)
        job = json.loads(raw)
    else:
        raw = run_command(["kubectl", "-n", namespace, "get", "jobs", "-l", SELECTOR, "-o", "json"], env)
        items = json.loads(raw).get("items", [])
        successful = [item for item in items if item.get("status", {}).get("succeeded", 0) > 0]
        candidates = successful or items
        if not candidates:
            raise RuntimeError(f"no benchmark Jobs found in namespace {namespace!r}")
        job = max(candidates, key=lambda item: item["metadata"].get("creationTimestamp", ""))
    name = job["metadata"]["name"]
    logs = run_command(["kubectl", "-n", namespace, "logs", f"job/{name}"], env)
    return name, logs


def parse_report(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        raise RuntimeError("benchmark result is empty")
    try:
        value = json.loads(stripped)
        if "final_report" in value:
            return value["final_report"]
        if "tests" in value:
            return value
    except json.JSONDecodeError:
        pass

    report: dict[str, Any] = {"tests": []}
    for line in stripped.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "final_report" in item:
            return item["final_report"]
        if item.get("id") in EXPECTED_TESTS:
            report["tests"].append(item)
        elif "schema_version" in item and "id" not in item:
            report.update(item)
    if not report["tests"]:
        raise RuntimeError("no T01-T10 results or final_report found in input")
    report["tests"].sort(key=lambda item: item["id"])
    return report


def finite(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def normalize_nonfinite(item: Any) -> Any:
    if isinstance(item, float) and not math.isfinite(item):
        return None
    if isinstance(item, dict):
        return {key: normalize_nonfinite(value) for key, value in item.items()}
    if isinstance(item, list):
        return [normalize_nonfinite(value) for value in item]
    return item


def value(test: dict[str, Any], section: str, name: str) -> float | None:
    return finite(test.get(section, {}).get(name))


def total_tps(test: dict[str, Any]) -> float | None:
    prompt = value(test, "summary", "prompt_tokens_per_second")
    generation = value(test, "summary", "generation_tokens_per_second")
    return prompt + generation if prompt is not None and generation is not None else None


def check(name: str, condition: bool | None, evidence: str) -> dict[str, str]:
    status = "PASS" if condition is True else "FAIL" if condition is False else "NOT OBSERVED"
    return {"name": name, "status": status, "evidence": evidence}


def fnum(number: float | None, digits: int = 3) -> str:
    return "n/a" if number is None else f"{number:.{digits}f}"


def analyze(report: dict[str, Any]) -> dict[str, Any]:
    tests = {test["id"]: test for test in report.get("tests", []) if test.get("id")}
    missing = [test_id for test_id in EXPECTED_TESTS if test_id not in tests]
    errors = sum(int(test.get("summary", {}).get("errors", 0)) for test in tests.values())
    mismatches = sum(len(test.get("token_mismatches", [])) for test in tests.values())
    checks = [
        check("Complete T01-T10 suite", not missing, "missing: " + (", ".join(missing) or "none")),
        check("All requests succeeded", errors == 0, f"request errors: {errors}"),
        check("Exact prompt-token budgets", mismatches == 0, f"token mismatches: {mismatches}"),
    ]
    if missing:
        return {"checks": checks, "missing_tests": missing, "classification": {}}

    t03, t05, t06, t07 = (tests[key] for key in ("T03", "T05", "T06", "T07"))
    t08, t09, t10 = (tests[key] for key in ("T08", "T09", "T10"))
    tps03, tps05, tps06, tps07 = map(total_tps, (t03, t05, t06, t07))
    ttft03, ttft05, ttft06, ttft07 = (
        value(test, "summary", "p95_ttft_seconds") for test in (t03, t05, t06, t07)
    )
    waiting05, waiting06, waiting07 = (
        value(test, "prometheus", "max_requests_waiting") for test in (t05, t06, t07)
    )
    preempt05 = value(t05, "prometheus", "preemptions")
    checks.extend([
        check("T05 batching payoff", tps05 > tps03 if None not in (tps05, tps03) else None,
              f"T05 {fnum(tps05, 1)} vs T03 {fnum(tps03, 1)} total tokens/s"),
        check("T05 controlled TTFT", ttft05 <= 2 * ttft03 if None not in (ttft05, ttft03) else None,
              f"T05 {fnum(ttft05)}s vs T03 {fnum(ttft03)}s"),
        check("T05 no queue", waiting05 == 0 if waiting05 is not None else None,
              f"max waiting {fnum(waiting05, 0)}"),
        check("T05 no preemptions", preempt05 == 0 if preempt05 is not None else None,
              f"preemptions {fnum(preempt05, 0)}"),
        check("T06 queue appears", waiting06 > 0 if waiting06 is not None else None,
              f"max waiting {fnum(waiting06, 0)}"),
        check("T06 throughput flattens", tps06 <= tps05 if None not in (tps06, tps05) else None,
              f"T06 {fnum(tps06, 1)} vs T05 {fnum(tps05, 1)} total tokens/s"),
        check("T07 no throughput gain", tps07 <= tps06 if None not in (tps07, tps06) else None,
              f"T07 {fnum(tps07, 1)} vs T06 {fnum(tps06, 1)} total tokens/s"),
        check("T07 TTFT worsens", ttft07 > ttft06 if None not in (ttft07, ttft06) else None,
              f"T07 {fnum(ttft07)}s vs T06 {fnum(ttft06)}s"),
        check("T07 queue does not improve", waiting07 >= waiting06 if None not in (waiting07, waiting06) else None,
              f"T07 {fnum(waiting07, 0)} vs T06 {fnum(waiting06, 0)} waiting"),
    ])

    hot_ttft, mixed_ttft, cold_ttft = (
        value(test, "summary", "p95_ttft_seconds") for test in (t08, t09, t10)
    )
    hot_hits, mixed_hits, cold_hits = (
        value(test, "prometheus", "prefix_cache_hit_ratio") for test in (t08, t09, t10)
    )
    checks.extend([
        check("Prefix-cache TTFT ordering",
              hot_ttft < mixed_ttft < cold_ttft if None not in (hot_ttft, mixed_ttft, cold_ttft) else None,
              f"hot {fnum(hot_ttft)}s, mixed {fnum(mixed_ttft)}s, cold {fnum(cold_ttft)}s"),
        check("Prefix-cache hit ordering",
              hot_hits > mixed_hits > cold_hits if None not in (hot_hits, mixed_hits, cold_hits) else None,
              f"hot {fnum(hot_hits)}, mixed {fnum(mixed_hits)}, cold {fnum(cold_hits)}"),
    ])

    healthy = (tps05 > tps03 and ttft05 <= 2 * ttft03 and waiting05 == 0 and preempt05 == 0
               if None not in (tps05, tps03, ttft05, ttft03, waiting05, preempt05) else None)
    saturated = (waiting06 > 0 and ttft06 > ttft05 and tps06 <= tps05
                 if None not in (waiting06, ttft06, ttft05, tps06, tps05) else None)
    overloaded = (tps07 <= tps06 and ttft07 > ttft06 and waiting07 >= waiting06
                  if None not in (tps07, tps06, ttft07, ttft06, waiting07, waiting06) else None)
    return {
        "checks": checks,
        "missing_tests": missing,
        "classification": {
            "T05_healthy": "yes" if healthy else "no" if healthy is False else "not observed",
            "T06_saturated": "yes" if saturated else "no" if saturated is False else "not observed",
            "T07_overloaded": "yes" if overloaded else "no" if overloaded is False else "not observed",
        },
    }


def markdown(report: dict[str, Any], analysis: dict[str, Any], source: str) -> str:
    tests = {test["id"]: test for test in report.get("tests", []) if test.get("id")}
    lines = [
        "# vLLM benchmark analysis", "", f"- Source: `{source}`",
        f"- Run started: {report.get('started_at', 'unknown')}",
        f"- Model: `{report.get('model', 'unknown')}`",
        f"- Token budget: {report.get('token_budget', 'unknown')}",
        f"- Theoretical concurrency: {report.get('theoretical_concurrency', 'unknown')}", "",
        "## Test curve", "",
        "| Test | Shape | Cache | Concurrency | Total tokens/s | p95 TTFT | Max waiting | KV max |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for test_id in EXPECTED_TESTS:
        if test_id not in tests:
            continue
        test = tests[test_id]
        lines.append(
            f"| {test_id} | {test.get('shape', {}).get('ratio', '?')} | {test.get('cache', '?')} | "
            f"{test.get('concurrency', '?')} | {fnum(total_tps(test), 1)} | "
            f"{fnum(value(test, 'summary', 'p95_ttft_seconds'))}s | "
            f"{fnum(value(test, 'prometheus', 'max_requests_waiting'), 0)} | "
            f"{fnum(value(test, 'prometheus', 'max_kv_cache_usage'))} |"
        )
    lines.extend(["", "## Relationship checks", "", "| Status | Expectation | Evidence |", "|---|---|---|"])
    for item in analysis["checks"]:
        lines.append(f"| {item['status']} | {item['name']} | {item['evidence']} |")
    lines.extend(["", "## Operational classification", ""])
    for name, result in analysis.get("classification", {}).items():
        lines.append(f"- {name.replace('_', ' ')}: **{result}**")
    lines.extend([
        "", "## Analyst notes", "",
        "Treat `NOT OBSERVED` as missing evidence, not success. Review normalized JSON and raw logs before attributing failures to the model or hardware; short Prometheus windows and unrelated traffic can distort server-side metrics.", ""
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", help="Saved results JSON or JSONL")
    source.add_argument("--job", help="Specific Kubernetes Job name")
    parser.add_argument("--kubeconfig", default=os.getenv("KUBECONFIG", "~/.kube/contexts/boyd-ref"))
    parser.add_argument("--namespace", default="poolside-models")
    parser.add_argument("--output-dir", default="./results")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if args.input:
        input_path = Path(args.input).expanduser().resolve()
        raw, source_name, stem = input_path.read_text(), str(input_path), input_path.stem
    else:
        job_name, raw = choose_job(args.kubeconfig, args.namespace, args.job)
        source_name, stem = f"job/{job_name} in {args.namespace}", job_name
        (output_dir / f"{stem}-raw.jsonl").write_text(raw)

    report = normalize_nonfinite(parse_report(raw))
    analysis = analyze(report)
    normalized_path = output_dir / f"{stem}-normalized.json"
    analysis_path = output_dir / f"{stem}-analysis.md"
    normalized_path.write_text(json.dumps({"source": source_name, "report": report, "analysis": analysis}, indent=2, allow_nan=False) + "\n")
    analysis_path.write_text(markdown(report, analysis, source_name))
    print(json.dumps({"source": source_name, "normalized_json": str(normalized_path), "analysis_markdown": str(analysis_path)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
