#!/usr/bin/env python3
"""Read a vLLM benchmark Job/log and produce normalized JSON, Markdown, and charts."""

from __future__ import annotations

import argparse
import html
import json
import math
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

SELECTOR = "app.kubernetes.io/name=vllm-behavior-benchmark"
EXPECTED_TESTS = [f"T{i:02d}" for i in range(1, 11)]

# What each test is for, in plain terms. Shape, cache state and concurrency come
# from the run itself; this supplies the intent.
TEST_PURPOSE = {
    "T01": "Latency floor for a prompt-dominated request. Nothing else is running.",
    "T02": "Latency floor when the prompt is large but the reply is meaningful.",
    "T03": "Latency floor for equal input and output. This is the reference the whole "
           "concurrency curve is measured against.",
    "T04": "Latency floor for a short prompt and a long reply.",
    "T05": "First loaded point on the concurrency curve.",
    "T06": "Higher load on the same shape.",
    "T07": "Highest load on the same shape, chosen to push past the useful limit.",
    "T08": "Best case for prompt reuse: every request shares a large identical opening.",
    "T09": "Half the requests share that opening, half are unique.",
    "T10": "No request shares anything. The comparison point for the two above.",
}
SWEEP_PURPOSE = ("Extra point on the concurrency curve, so the shape of the curve is "
                 "visible rather than inferred from four readings.")

SHAPE_MEANING = {
    "15:1": "Agentic coding and RAG: a large context of files, diffs or documents, then a small "
            "patch or tool call.",
    "5:1": "Chat with history, or a summarize-this request: long prompt, reply worth reading.",
    "1:1": "Rewrites, translation and refactors, where the reply tracks the length of the input.",
    "1:5": "Short prompt, long generation: scaffolding from a spec, drafting from an outline, or "
           "a reasoning model working through an answer.",
}

STATE_MEANING = [
    ("linear", "Scaling efficiency 0.75 or better. Each added session buys at least 75% of what "
               "the first session delivered."),
    ("sub-linear", "Scaling efficiency 0.30 to 0.75. Still buying real throughput per session, "
                   "but the server is now sharing capacity."),
    ("flat", "Scaling efficiency below 0.30. Added sessions mostly wait on each other; total "
             "throughput still creeps up but each session pays for it in latency."),
    ("capped", "Within 2% of the best throughput observed, and so was the level below it. "
                "Additional concurrency changes "
               "throughput by nothing measurable and only adds latency."),
    ("degraded", "Throughput fell below a lower concurrency, or the scheduler preempted "
                 "sequences, or latency grew faster than the load did."),
]

STATE_ONE_LINER = {
    "linear": "Adding users improves throughput 0.76 to 1.0 relative to the previous level.",
    "sub-linear": "Adding users improves throughput 0.30 to 0.75 relative to the previous level.",
    "flat": "Gains fall below 0.30, and concurrency starts trading throughput for latency.",
    "capped": "No throughput left to gain at this level; added users only add latency.",
    "degraded": "Worse than earlier levels: timeouts, cache eviction, dropped requests.",
}

GLOSSARY = [
    ("Prefill", "Processing the prompt. The whole prompt goes through the model at once, "
                "so it is fast per token."),
    ("Decode", "Generating the reply. One token per pass through the model, so it is slow "
               "per token."),
    ("TTFT", "Time to first token. How long a user waits before anything appears."),
    ("ITL", "Inter-token latency. The gap between output tokens once generation starts, "
            "which is how fast the reply streams."),
    ("Steady window", "The stretch of each test where every worker was busy. Ramp-up and "
                      "drain are excluded so the numbers reflect sustained load."),
    ("Scaling efficiency", "X(N) divided by N times X(1): the share of ideal linear scaling "
                           "still being achieved at concurrency N. 1.00 is perfect, 0.10 means "
                           "ninety percent of the theoretical gain is lost to contention."),
    ("Tuned setting", "Where the two straight lines through this run's own curve cross: the "
                      "linear-scaling line from the origin, and the flat line at maximum "
                      "throughput. Below it the GPU idles between requests; above it throughput "
                      "gains cost progressively more latency."),
    ("Latency multiple", "End-to-end p95 at concurrency N divided by end-to-end p95 at "
                         "concurrency 1. What a user pays for the extra throughput."),
]

# Validated categorical slots 1-3 from the reference palette (all-pairs, both modes).
SERIES = ("--series-1", "--series-2", "--series-3")


# --------------------------------------------------------------------------- io


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
        if isinstance(item.get("id"), str) and item["id"][0] in "TS":
            report["tests"].append(item)
        elif "schema_version" in item and "id" not in item:
            report.update(item)
    if not report["tests"]:
        raise RuntimeError("no test results or final_report found in input")
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


def backfill(report: dict[str, Any]) -> dict[str, Any]:
    """Derive fields that schema_version 1 runs did not record."""
    for test in report.get("tests", []):
        prometheus = test.get("prometheus") or {}
        if prometheus.get("cached_token_ratio") is None:
            queries = finite(prometheus.get("prefix_cache_queries"))
            cached = finite(prometheus.get("prompt_tokens_cached"))
            if queries and cached is not None:
                prometheus["cached_token_ratio"] = cached / queries
        summary = test.setdefault("summary", {})
        summary.setdefault("window_seconds", summary.get("elapsed_seconds"))
        if summary.get("prefill_share") is not None:
            continue
        pairs = [
            (r["ttft_seconds"], r["e2e_seconds"]) for r in test.get("requests", [])
            if not r.get("error") and r.get("ttft_seconds") is not None
        ]
        if not pairs:
            continue
        prefill = sum(t for t, _ in pairs) / len(pairs)
        decode = sum(e - t for t, e in pairs) / len(pairs)
        summary["mean_prefill_seconds"] = prefill
        summary["mean_decode_seconds"] = decode
        summary["prefill_share"] = prefill / (prefill + decode) if prefill + decode else None
    return report


# ---------------------------------------------------------------------- access


def value(test: dict[str, Any], section: str, name: str) -> float | None:
    return finite((test.get(section) or {}).get(name))


def prompt_tps(test: dict[str, Any]) -> float | None:
    return value(test, "summary", "prompt_tokens_per_second")


def generation_tps(test: dict[str, Any]) -> float | None:
    return value(test, "summary", "generation_tokens_per_second")


def total_tps(test: dict[str, Any]) -> float | None:
    """Only meaningful within one shape. Never compare across shapes."""
    prompt, generation = prompt_tps(test), generation_tps(test)
    return prompt + generation if None not in (prompt, generation) else None


def check(name: str, condition: bool | None, evidence: str) -> dict[str, str]:
    status = "PASS" if condition is True else "FAIL" if condition is False else "NOT OBSERVED"
    return {"name": name, "status": status, "evidence": evidence}


def fnum(number: float | None, digits: int = 3) -> str:
    return "n/a" if number is None else f"{number:.{digits}f}"


def ordered(*values: float | None) -> bool | None:
    if any(v is None for v in values):
        return None
    return all(a > b for a, b in zip(values, values[1:]))


# -------------------------------------------------------------------- analysis


MIN_CURVE_SAMPLES = 2   # one request is an observation, not a percentile


def on_curve(test: dict[str, Any], curve_shape: str) -> bool:
    """Curve membership, from the runner's own flag where the report carries it.

    Runs before BENCH_CURVE_SHAPE existed have no flag, so fall back to the
    shape those runs always used for the curve.
    """
    if "curve" in test:
        return bool(test["curve"])
    return (test.get("shape", {}).get("ratio") == curve_shape
            and test.get("cache") == "cold")


def curve_points(tests: dict[str, Any], curve_shape: str = "1:1") -> list[dict[str, Any]]:
    """Curve-shape cold tests ordered by concurrency, including sweep points.

    A test that completed fewer than MIN_CURVE_SAMPLES requests is dropped. Its
    p95 is a single observation, and left in place it lands on the curve as a
    throughput collapse that never happened.
    """
    points = [
        test for test in tests.values()
        if on_curve(test, curve_shape)
        and (value(test, "summary", "successes") or 0) >= MIN_CURVE_SAMPLES
    ]
    return sorted(points, key=lambda test: test.get("concurrency", 0))


def undersampled_curve_tests(tests: dict[str, Any], curve_shape: str = "1:1") -> list[str]:
    return sorted(
        str(test.get("id")) for test in tests.values()
        if on_curve(test, curve_shape)
        and (value(test, "summary", "successes") or 0) < MIN_CURVE_SAMPLES
    )


# Band edges, expressed as scaling efficiency X(N) / (N * X(1)). Every edge is
# printed alongside the table so a reader can check the arithmetic.
LINEAR_EFFICIENCY = 0.75      # still getting most of what each added session costs
SUBLINEAR_EFFICIENCY = 0.30   # still buying a meaningful share
CAPPED_FRACTION = 0.98        # within 2% of the best throughput observed
KV_PRESSURE_FRACTION = 0.90   # KV this full means the cache is the active constraint
QUEUE_BACKLOG_FRACTION = 0.05  # mean waiting this share of offered load is a real admission cost


def classify_curve(curve: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify every concurrency level from measured quantities only.

    Three numbers drive this, each printed in the report:

      scaling efficiency  X(N) / (N * X(1))   share of ideal linear scaling
      throughput fraction X(N) / X_max        share of the best rate observed
      latency multiple    R(N) / R_min        cost paid for it

    The tuned setting is a geometric construction on the measured curve, not a
    chosen threshold. Two straight lines describe its extremes: X(N) = N / R_min
    at low load, where throughput rises in step with concurrency, and X(N) = X_max
    at high load, where it is flat. They cross at N = X_max * R_min. That crossing
    is where the curve stops behaving like the first line and starts behaving like
    the second.
    """
    points = [
        {
            "id": test.get("id"), "concurrency": test.get("concurrency"),
            "throughput": total_tps(test),
            "requests_per_second": value(test, "summary", "requests_per_second"),
            "ttft": value(test, "summary", "p95_ttft_seconds"),
            "e2e": value(test, "summary", "p95_e2e_seconds"),
            "per_user": ((generation_tps(test) or 0) / test["concurrency"]
                         if test.get("concurrency") else None),
            "waiting": value(test, "prometheus", "mean_requests_waiting"),
            "preemptions": value(test, "prometheus", "preemptions"),
            "kv_usage": value(test, "prometheus", "max_kv_cache_usage"),
            "steady": bool(test.get("steady_window_valid", True)),
            "samples": value(test, "summary", "successes"),
        }
        for test in curve
    ]
    points = [p for p in points if p["concurrency"] and p["throughput"] is not None]
    if len(points) < 3:
        return {"levels": [], "tuned": None, "peak": None}

    base = points[0]
    peak_throughput = max(p["throughput"] for p in points)
    rates = [p["requests_per_second"] for p in points if p["requests_per_second"]]
    latencies = [p["e2e"] for p in points if p["e2e"]]
    max_rate = max(rates) if rates else None
    min_latency = min(latencies) if latencies else None
    tuned_exact = max_rate * min_latency if max_rate and min_latency else None

    previous = None
    for point in points:
        ideal = base["requests_per_second"] * point["concurrency"] if base["requests_per_second"] else None
        point["scaling_efficiency"] = (
            point["requests_per_second"] / ideal if ideal and point["requests_per_second"] else None
        )
        point["throughput_fraction"] = point["throughput"] / peak_throughput
        point["latency_multiple"] = (
            point["e2e"] / min_latency if min_latency and point["e2e"] else None
        )
        load_ratio = point["concurrency"] / base["concurrency"]
        point["load_ratio"] = load_ratio
        point["latency_ratio"] = (
            point["ttft"] / base["ttft"] if base["ttft"] and point["ttft"] else None
        )
        point["superlinear"] = (
            point["latency_ratio"] > load_ratio if point["latency_ratio"] is not None else None
        )
        efficiency = point["scaling_efficiency"]
        # An unsteady window measures ramp and drain as well as load, so its
        # throughput reads low. Calling that a regression invents a cliff.
        regressed = bool(
            previous and point["throughput"] < previous["throughput"]
            and point["steady"] and previous["steady"]
        )
        if (point["preemptions"] or 0) > 0 or point["superlinear"] or regressed:
            point["state"] = "degraded"
        elif (point["throughput_fraction"] >= CAPPED_FRACTION and point is not base
                and previous and previous["throughput_fraction"] >= CAPPED_FRACTION):
            # The plateau has to be witnessed across two tested levels. The
            # highest point is always within 2% of itself, so testing it alone
            # labels every run "capped" at its top level and contradicts the
            # capacity section, which says the ceiling was never found.
            point["state"] = "capped"
        elif efficiency is None:
            point["state"] = "sub-linear"
        elif efficiency >= LINEAR_EFFICIENCY:
            point["state"] = "linear"
        elif efficiency >= SUBLINEAR_EFFICIENCY:
            point["state"] = "sub-linear"
        else:
            point["state"] = "flat"
        previous = point

    tuned = (min(points, key=lambda p: abs(p["concurrency"] - tuned_exact))["concurrency"]
             if tuned_exact else None)
    for point in points:
        point["tuned"] = point["concurrency"] == tuned
    usable = [p for p in points if p["state"] != "degraded"]
    peak_point = max(usable, key=lambda p: p["throughput"]) if usable else None
    return {
        "levels": points,
        "tuned": tuned,
        "tuned_exact": tuned_exact,
        "max_request_rate": max_rate,
        "min_latency": min_latency,
        "peak": peak_point["concurrency"] if peak_point else None,
        "peak_throughput": peak_point["throughput"] if peak_point else None,
    }


BINDING_LABEL = {
    "BENCH_MAX_CONCURRENCY": "operator cap",
    "max_num_seqs": "scheduler slots",
    "kv_cache": "KV cache",
}


def executive_summary(report: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    """The run in a handful of readings, plus what to do about it."""
    tests = {test["id"]: test for test in report.get("tests", []) if test.get("id")}
    curve = analysis.get("curve") or {}
    levels = curve.get("levels", [])
    balance = analysis.get("balance")
    if not levels:
        return {"points": [], "actions": []}

    base, top = levels[0], levels[-1]
    peak = max(levels, key=lambda p: p["throughput"])
    tuned = next((p for p in levels if p.get("tuned")), None)
    points = [
        f"Throughput: total tokens per second went from {base['throughput']:,.0f} to "
        f"{peak['throughput']:,.0f} as concurrency increased from {base['concurrency']} to "
        f"{peak['concurrency']}.",
        f"Responsiveness: TTFT at p95 increased from {base['ttft']:.2f}s to {top['ttft']:.2f}s. "
        f"End-to-end at p95 increased from {base['e2e']:.1f}s to {top['e2e']:.0f}s.",
        f"Speed: per-user token rate dropped from {base['per_user']:,.0f} tok/s to "
        f"{top['per_user']:,.0f} tok/s as concurrency increased.",
    ]
    if balance:
        points.append(
            f"Prefill vs decode: prefill averaged {balance['prefill_rate']:,.0f} tok/s, decode "
            f"averaged {balance['decode_rate']:,.0f} tok/s. Decode speed is the bottleneck, and "
            "it is bound by memory bandwidth rather than by request count."
        )
    hot, mixed, cold = tests.get("T08"), tests.get("T09"), tests.get("T10")
    if hot and cold:
        hot_ttft = value(hot, "summary", "p95_ttft_seconds")
        cold_ttft = value(cold, "summary", "p95_ttft_seconds")
        ratio = value(hot, "prometheus", "cached_token_ratio")
        hot_itl = value(hot, "summary", "p50_itl_seconds")
        cold_itl = value(cold, "summary", "p50_itl_seconds")
        cache_concurrency = hot.get("concurrency")
        cache_shape = hot.get("shape", {}).get("ratio")
        if None not in (hot_ttft, cold_ttft, ratio):
            sentence = (
                f"Cache: at concurrency {cache_concurrency} on the {cache_shape} shape, a "
                f"{ratio:.0%} prefix cache hit ratio cut p95 TTFT from {cold_ttft:.2f}s with no "
                f"reuse to {hot_ttft:.2f}s with full reuse."
            )
            if None not in (hot_itl, cold_itl) and hot_itl:
                sentence += (f" ITL improved {cold_itl / hot_itl:,.1f}x over the same pair "
                             f"({cold_itl:.4f}s without reuse against {hot_itl:.4f}s with it).")
            points.append(sentence)
    peak_level = next((p for p in curve.get("levels", [])
                       if p["concurrency"] == curve.get("peak")), None)
    if tuned:
        # Percentages of peak and multiples of baseline are true and hard to act
        # on. State what one user feels and what the pod produces, in tok/s.
        sentence = (
            f"Tuned setting: {tuned['concurrency']} sessions. Each user gets "
            f"{fnum(tuned['per_user'], 0)} tok/s and waits {fnum(tuned['ttft'], 1)}s for the first "
            f"token, and the pod produces {fnum(tuned['throughput'], 0)} tok/s across all of them."
        )
        if peak_level and peak_level["concurrency"] != tuned["concurrency"]:
            sentence += (
                f" At {peak_level['concurrency']} sessions the pod produces "
                f"{fnum(peak_level['throughput'], 0)} tok/s, each user gets "
                f"{fnum(peak_level['per_user'], 0)} tok/s, and the first-token wait is "
                f"{fnum(peak_level['ttft'], 1)}s."
            )
        points.append(sentence)

    actions: list[str] = []
    failed = {item["name"] for item in analysis.get("checks", []) if item["status"] == "FAIL"}
    constraint = report.get("concurrency_constraint") or {}
    if "Curve reaches degradation" in failed:
        knob = ("BENCH_MAX_CONCURRENCY in the Job"
                if constraint.get("binding") == "BENCH_MAX_CONCURRENCY"
                else "--max-num-seqs on the vLLM deployment, then BENCH_MAX_CONCURRENCY in the Job")
        actions.append(
            f"The ceiling was not reached. Nothing degraded at concurrency {top['concurrency']}, "
            f"so treat that as a floor on capacity. To find the real limit, raise {knob}, or raise "
            "BENCH_TOKEN_BUDGET so each request holds more KV cache. Exact values are in the "
            "next-run section below."
        )
    if constraint.get("binding") == "max_num_seqs" and (constraint.get("headroom_ratio") or 0) > 1.5:
        actions.append(
            f"Capacity is bound by scheduler slots, not memory: --max-num-seqs is "
            f"{constraint.get('max_num_seqs')} while KV cache would hold about "
            f"{constraint.get('kv_limit')} sessions at this context length. Raising the slot count "
            "removes a cliff under traffic spikes; it will not necessarily raise peak throughput."
        )
    levels = curve.get("levels", [])
    kv_peak = max((p["kv_usage"] for p in levels if p.get("kv_usage") is not None), default=None)
    preempted = any((p["preemptions"] or 0) > 0 for p in levels)
    memory_bound = preempted or (kv_peak is not None and kv_peak >= KV_PRESSURE_FRACTION)
    if tuned and peak_level and peak_level["concurrency"] != tuned["concurrency"]:
        extra = peak_level["concurrency"] - tuned["concurrency"]
        gain = (peak_level["throughput"] / tuned["throughput"] - 1) if tuned["throughput"] else None
        actions.append(
            f"Headroom first, hardware second. {tuned['concurrency']} sessions is the efficient "
            f"point and {peak_level['concurrency']} is the most this pod sustains, so the last "
            f"{extra} sessions are output you have already paid for: "
            f"{fnum(gain * 100, 0)}% more total tokens/sec, bought by letting per-user speed fall "
            f"from {fnum(tuned['per_user'], 0)} to {fnum(peak_level['per_user'], 0)} tok/s and "
            f"first-token wait rise from {fnum(tuned['ttft'], 1)}s to {fnum(peak_level['ttft'], 1)}s. "
            "Take that trade unless a latency target forbids it."
        )
    if peak_level:
        if memory_bound:
            actions.append(
                f"Scale out past {peak_level['concurrency']} sessions, not up. KV peaked at "
                f"{kv_peak:.0%} of the pool"
                + (" and the scheduler preempted sequences" if preempted else "")
                + ", so no setting on this pod adds capacity at this context length. Add a replica "
                f"when you need more than {peak_level['concurrency']} sessions at once, or when "
                f"{fnum(peak_level['per_user'], 0)} tok/s per user is below what the product needs. "
                "Each replica buys another "
                f"{fnum(peak_level['throughput'], 0)} tok/s and another "
                f"{peak_level['concurrency']} sessions."
            )
        else:
            actions.append(
                f"Scale up before scaling out. KV peaked at {kv_peak:.0%} of the pool"
                if kv_peak is not None else "Scale up before scaling out."
            )
            actions[-1] += (
                f", so this pod still had memory to give at {peak_level['concurrency']} sessions. "
                "Raise concurrency and re-measure before adding replicas."
            )
    hot_kv = value(tests.get("T08") or {}, "prometheus", "max_kv_cache_usage")
    cold_kv = value(tests.get("T10") or {}, "prometheus", "max_kv_cache_usage")
    if memory_bound and None not in (hot_kv, cold_kv) and hot_kv and cold_kv > hot_kv:
        actions.append(
            f"Prefix reuse is the only lever that raises the session count without hardware. At the "
            f"same concurrency the cache-hot test held {hot_kv:.0%} of KV against {cold_kv:.0%} "
            f"cold, so shared context is worth roughly {cold_kv / hot_kv:,.1f}x in sessions per GPU. "
            "Route sessions that share a system prompt or repo context to the same replica."
        )
    return {"points": points, "actions": actions}


def capacity_table(report: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    """What the measured generation ceiling means in users.

    The ceiling is a throughput number; a user count only exists once you say how
    fast each user needs their tokens. This turns one into the other, and flags
    when KV cache runs out before throughput does.
    """
    tests = {test["id"]: test for test in report.get("tests", []) if test.get("id")}
    curve = analysis.get("curve") or {}
    balance = analysis.get("balance")
    points = curve_points(tests, report.get("curve_shape", "1:1"))
    if not points or not balance:
        return {}
    aggregate = max(generation_tps(t) or 0 for t in points)
    single = balance["decode_rate"]
    constraint = report.get("concurrency_constraint") or {}
    kv_limit = constraint.get("kv_limit")
    # Two different limits, and conflating them is how a report ends up claiming
    # both "this is the ceiling" and "the ceiling is higher".
    #   throughput ceiling: adding concurrency stops adding tokens/sec
    #   failure point:      something actually breaks (preemption, regression,
    #                       latency outrunning load)
    levels = curve.get("levels", [])
    plateaued = sum(1 for p in levels[-2:] if p.get("throughput_fraction", 0) >= 0.98) >= 2
    failed_over = any(p["state"] == "degraded" for p in levels)

    ladder = [
        (30, "Reading pace. A person following along as it streams."),
        (100, "Comfortably faster than reading. Short replies feel immediate."),
        (300, "Agentic loops, where code consumes the output rather than a person."),
        (round(single), "One request at a time, no contention. The floor on how many you can serve."),
    ]
    rows = []
    seen = set()
    for rate, comment in ladder:
        if rate <= 0 or rate > single * 1.05 or rate in seen:
            continue
        seen.add(rate)
        users = int(aggregate / rate)
        note = comment
        if kv_limit and users > kv_limit:
            users = kv_limit
            note = f"{comment} Capped by KV cache at {kv_limit} before throughput runs out."
        rows.append({"users": users, "rate": rate, "note": note})
    return {
        "aggregate": aggregate, "single": single, "rows": rows,
        "plateaued": plateaued, "failed_over": failed_over, "kv_limit": kv_limit,
        "peak_concurrency": curve.get("peak"),
        "plateau_from": next((p["concurrency"] for p in levels
                              if p.get("throughput_fraction", 0) >= 0.98), None),
    }


def capacity_ceiling_note(capacity: dict[str, Any]) -> list[str]:
    """Two sentences that must not contradict each other."""
    notes = []
    if capacity["plateaued"]:
        notes.append(
            f"Throughput ceiling: {capacity['aggregate']:,.0f} generated tokens/sec. The curve is "
            f"flat from concurrency {capacity['plateau_from']} onward, so this is the limit of what "
            "this configuration produces at this context length. Adding concurrency past that point "
            "buys latency, not output."
        )
    else:
        notes.append(
            f"Throughput ceiling: at least {capacity['aggregate']:,.0f} generated tokens/sec. "
            "Throughput was still climbing at the highest concurrency tested, so the real ceiling "
            "is higher than this."
        )
    notes.append(
        "Failure point: not reached. Nothing was preempted, throughput never fell, and latency "
        "never grew faster than the load. The configuration runs out of useful throughput well "
        "before it runs out of capacity, so it degrades gently rather than falling over."
        if not capacity["failed_over"] else
        "Failure point: reached. At least one level preempted sequences, lost throughput, or saw "
        "latency outrun the load. That is the hard limit."
    )
    return notes


def concurrency_ruler(analysis: dict[str, Any]) -> str:
    """The whole run as one strip: every level tested, colored by state.

    This is the report's thesis. A reader who looks at nothing else should still
    leave knowing where this configuration stops being comfortable.
    """
    curve = analysis.get("curve") or {}
    levels = curve.get("levels", [])
    if not levels:
        return ""
    marks = {curve.get("tuned"): "tuned", curve.get("peak"): "peak"}
    cells = []
    for point in levels:
        mark = marks.get(point["concurrency"], "")
        cells.append(
            f'<div class="ruler-cell" data-state="{escape(point["state"])}"'
            + (f' data-mark="1"' if mark else "")
            + f' title="{escape(point["concurrency"])} concurrent: {escape(point["state"])}">'
            f'<div class="ruler-bar"></div><span class="ruler-n">{escape(point["concurrency"])}</span>'
            + (f'<span class="ruler-mark">{escape(mark)}</span>' if mark else "")
            + "</div>"
        )
    key = "".join(
        f'<div class="key-row"><i style="background:{color}"></i>'
        f'<span class="key-label">{label}</span>'
        f'<span class="key-note">{escape(STATE_ONE_LINER.get(label, ""))}</span></div>'
        for label, color in (("linear", "var(--good)"), ("sub-linear", "var(--good); opacity:.55"),
                             ("flat", "var(--warning)"),
                             ("capped", "var(--critical); opacity:.55"),
                             ("degraded", "var(--critical)"))
    )
    return (
        '<div class="ruler"><div class="ruler-track">' + "".join(cells) + "</div>"
        '<div class="ruler-scale"><span>concurrent users</span>'
        f'<span>{escape(levels[-1]["concurrency"])} tested</span></div>'
        f'<div class="ruler-key">{key}</div></div>'
    )


def next_run(report: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    """Concrete settings for the run that answers what this one could not."""
    curve = analysis.get("curve") or {}
    levels = curve.get("levels", [])
    if not levels:
        return {}
    constraint = report.get("concurrency_constraint") or {}
    failed = {item["name"] for item in analysis.get("checks", []) if item["status"] == "FAIL"}
    budget = report.get("token_budget") or 4080
    top = levels[-1]["concurrency"]
    kv_tokens = constraint.get("kv_cache_tokens")
    kv_limit = constraint.get("kv_limit")
    seq_limit = constraint.get("max_num_seqs")

    reason: list[str] = []
    env: dict[str, str] = {}
    if "Curve reaches degradation" in failed:
        target = min(kv_limit, top * 2) if kv_limit else top * 2
        reason.append(
            f"Nothing degraded at concurrency {top}, so this run found a floor on capacity rather "
            "than a ceiling. Either push concurrency until it breaks, or change the workload so "
            "the limit is reachable."
        )
        env["BENCH_MAX_CONCURRENCY"] = str(target)
        env["BENCH_CONCURRENCY_LEVELS"] = "1,0.33,0.67,1.0"
        env["BENCH_SWEEP_LEVELS"] = "0.08,0.17,0.25,0.5,0.83"
        if target > 96:
            reason.append(
                f"Concurrency {target} is past what a single pod can drive without the load "
                "generator adding to measured latency. Split it across replicas: run the same "
                "manifest three times at a third of the count each and sum the throughput."
            )
    kv_peak = max((p["kv_usage"] for p in levels if p.get("kv_usage") is not None), default=None)
    preempted = any((p["preemptions"] or 0) > 0 for p in levels)
    memory_bound = preempted or (kv_peak is not None and kv_peak >= KV_PRESSURE_FRACTION)
    if memory_bound:
        reason.append(
            f"Memory bound this run: KV peaked at {kv_peak:.0%} of the pool"
            + (" and the scheduler preempted sequences" if preempted else "")
            + f". The {budget:,}-token budget is the right size to exercise KV on this "
            "configuration, so keep it and vary concurrency around the ceiling rather than "
            "raising context further."
        )
    elif kv_tokens and seq_limit:
        memory_bound_context = int(kv_tokens / seq_limit)
        if budget < memory_bound_context * 0.8:
            reason.append(
                f"Memory never bound because each context was small. With {kv_tokens:,} KV tokens "
                f"and {seq_limit} scheduler slots, memory only binds above roughly "
                f"{memory_bound_context:,} tokens per request."
            )
    elif kv_tokens:
        reason.append(
            f"Memory never bound because each context was small. KV cache holds {kv_tokens:,} "
            f"tokens, so at {budget:,} per request it takes about {kv_tokens // budget:,} "
            "concurrent sessions to fill. Raising context length gets there far sooner than "
            "raising concurrency."
        )
    return {"reason": reason, "env": env, "budget": budget,
            "agentic_budget": 50000 if budget < 50000 else budget * 2}


def test_reference(report: dict[str, Any]) -> list[dict[str, str]]:
    """One row per test explaining what it ran and why."""
    rows = []
    # The workload example belongs to the ratio, not the test, and eleven of these
    # rows are 1:1. Print it the first time a ratio appears and leave the repeats blank.
    described: set[str] = set()
    for test in report.get("tests", []):
        shape = test.get("shape", {})
        test_id = str(test.get("id"))
        cache = {"cold": "every prompt unique",
                 "hot": "all prompts share a long opening",
                 "mixed": "half share that opening"}.get(test.get("cache"), test.get("cache"))
        rows.append({
            "id": test_id,
            "workload": f"{shape.get('input_tokens'):,} in / {shape.get('output_tokens'):,} out "
                        f"({shape.get('ratio')})",
            "sessions": str(test.get("concurrency")),
            "reuse": cache,
            "purpose": TEST_PURPOSE.get(test_id, SWEEP_PURPOSE),
            "looks_like": "" if shape.get("ratio") in described
                          else SHAPE_MEANING.get(shape.get("ratio"), ""),
        })
        described.add(shape.get("ratio"))
    return rows


def time_balanced_ratio(tests: dict[str, Any]) -> dict[str, float] | None:
    """Input:output ratio at which prefill time equals decode time on this hardware.

    Prefill runs the whole prompt through the model in parallel while decode
    emits one token at a time, so the token ratio that balances the two is far
    from 1:1 and is the number that makes every other shape result legible.
    """
    baselines = [tests.get(test_id) for test_id in ("T01", "T02", "T03", "T04")]
    rates = []
    for test in baselines:
        if not test:
            continue
        prefill = value(test, "summary", "mean_prefill_seconds")
        decode = value(test, "summary", "mean_decode_seconds")
        shape = test.get("shape", {})
        if not prefill or not decode or not shape.get("input_tokens"):
            continue
        rates.append((shape["input_tokens"] / prefill, shape["output_tokens"] / decode))
    if not rates:
        return None
    prefill_rate = sum(item[0] for item in rates) / len(rates)
    decode_rate = sum(item[1] for item in rates) / len(rates)
    if decode_rate <= 0:
        return None
    return {"prefill_rate": prefill_rate, "decode_rate": decode_rate,
            "ratio": prefill_rate / decode_rate}


def analyze(report: dict[str, Any]) -> dict[str, Any]:
    tests = {test["id"]: test for test in report.get("tests", []) if test.get("id")}
    missing = [test_id for test_id in EXPECTED_TESTS if test_id not in tests]
    errors = sum(int((test.get("summary") or {}).get("errors", 0)) for test in tests.values())
    mismatches = sum(len(test.get("token_mismatches", [])) for test in tests.values())
    unsteady = [test_id for test_id, test in tests.items()
                if test.get("steady_window_valid") is False]
    checks = [
        check("Complete T01-T10 suite", not missing, "missing: " + (", ".join(missing) or "none")),
        check("All requests succeeded", errors == 0, f"request errors: {errors}"),
        check("Exact prompt-token budgets", mismatches == 0, f"token mismatches: {mismatches}"),
        check("Steady measurement window in every test", not unsteady,
              "unsteady: " + (", ".join(sorted(unsteady)) or "none")),
    ]
    if missing:
        return {"checks": checks, "missing_tests": missing, "classification": {}, "notes": []}

    notes: list[str] = []
    t01, t02, t03, t04 = (tests[key] for key in ("T01", "T02", "T03", "T04"))
    t05, t06, t07 = (tests[key] for key in ("T05", "T06", "T07"))
    t08, t09, t10 = (tests[key] for key in ("T08", "T09", "T10"))

    # Shape behavior. The verifiable claim is the ordering of the
    # prefill share, since prefill is parallel over the prompt while decode is
    # sequential: equal token counts never mean equal time.
    shares = [value(test, "summary", "prefill_share") for test in (t01, t02, t03, t04)]
    checks.extend([
        check("1:5 is decode-dominated", shares[3] < 0.1 if shares[3] is not None else None,
              f"T04 prefill share {fnum(shares[3], 2)}"),
        check("Prefill share falls as the shape tilts toward output", ordered(*shares),
              "T01 %s > T02 %s > T03 %s > T04 %s" % tuple(fnum(s, 3) for s in shares)),
        check("1:1 is decode-bound despite equal token counts",
              shares[2] < 0.25 if shares[2] is not None else None,
              f"T03 prefill share {fnum(shares[2], 3)}"),
    ])
    balance = time_balanced_ratio(tests)
    if balance:
        notes.append(
            f"Reading a prompt runs at about {balance['prefill_rate']:,.0f} tokens/sec. Writing a "
            f"reply runs at about {balance['decode_rate']:,.0f}. A prompt token therefore costs "
            f"roughly {balance['ratio']:,.0f} times less time than a generated token. That is why a "
            f"request with equal input and output is almost entirely generation time, and why the "
            f"two only balance out near a {balance['ratio']:,.0f}:1 input-to-output ratio."
        )

    # Concurrency behavior.
    tps03, tps05, tps06, tps07 = (total_tps(test) for test in (t03, t05, t06, t07))
    ttft03, ttft05, ttft06, ttft07 = (
        value(test, "summary", "p95_ttft_seconds") for test in (t03, t05, t06, t07)
    )
    waiting05, waiting06, waiting07 = (
        value(test, "prometheus", "max_requests_waiting") for test in (t05, t06, t07)
    )
    preempt05 = value(t05, "prometheus", "preemptions")
    # The suite passes when the curve *demonstrates* the progression from
    # batching payoff through diminishing returns to degradation. A level sitting in a
    # loaded-but-in-tolerance regime is a success, not a failure, so the checks
    # ask what the curve revealed rather than holding each point to a fixed bar.
    curve_shape = report.get("curve_shape", "1:1")
    curve = classify_curve(curve_points(tests, curve_shape))
    levels = curve["levels"]
    states = {point["state"] for point in levels}
    best_gain = max((p["throughput"] / tps03 for p in levels
                     if p["state"] != "baseline" and tps03), default=None)
    worst_efficiency = min((p["scaling_efficiency"] for p in levels
                            if p.get("scaling_efficiency") is not None), default=None)
    sublinear_levels = [
        p["superlinear"] is False for p in levels
        if p["state"] != "degraded" and p["superlinear"] is not None
    ]
    checks.extend([
        check("Batching pays off",
              best_gain > 3 if best_gain is not None else None,
              f"peak throughput {fnum(curve['peak_throughput'], 0)} tokens/s at "
              f"{curve['peak']} concurrent, {fnum(best_gain, 1)}x the single-session baseline"),
        check("Latency grows slower than load",
              all(sublinear_levels) if sublinear_levels else None,
              "; ".join(f"{p['concurrency']}: {fnum(p['latency_ratio'], 1)}x TTFT at "
                        f"{fnum(p['load_ratio'], 0)}x load" for p in levels
                        if p["state"] != "degraded")),
        check("Curve reaches diminishing returns",
              worst_efficiency < SUBLINEAR_EFFICIENCY if worst_efficiency is not None else None,
              f"scaling efficiency falls to {fnum(worst_efficiency, 2)} of its "
              f"initial value; tuned setting at {curve['tuned']} concurrent"),
        check("Curve reaches degradation",
              "degraded" in states,
              f"levels observed: {', '.join(sorted(states))}"
              + ("" if "degraded" in states else
                 "; the run never degraded, so the ceiling was not found. Raise concurrency, "
                 "raise BENCH_TOKEN_BUDGET, or accept that this configuration has no cliff")),
        check("No preemptions below the tuned setting",
              all((p["preemptions"] or 0) == 0 for p in levels
                  if p["state"] in {"linear", "sub-linear"})
              if any(p["preemptions"] is not None for p in levels) else None,
              "preemptions at or below the tuned setting: " + ", ".join(
                  f"{p['concurrency']}:{fnum(p['preemptions'], 0)}" for p in levels
                  if p["state"] in {"linear", "sub-linear"})),
    ])

    # Prefix cache behavior.
    hot_ttft, mixed_ttft, cold_ttft = (
        value(test, "summary", "p95_ttft_seconds") for test in (t08, t09, t10)
    )
    hot_hits, mixed_hits, cold_hits = (
        value(test, "prometheus", "cached_token_ratio") for test in (t08, t09, t10)
    )
    hot_itl, cold_itl = (value(test, "summary", "p50_itl_seconds") for test in (t08, t10))
    checks.extend([
        check("Prefix-cache TTFT ordering",
              ordered(cold_ttft, mixed_ttft, hot_ttft),
              f"hot {fnum(hot_ttft)}s, mixed {fnum(mixed_ttft)}s, cold {fnum(cold_ttft)}s"),
        check("Prefix-cache hit ordering", ordered(hot_hits, mixed_hits, cold_hits),
              f"hot {fnum(hot_hits)}, mixed {fnum(mixed_hits)}, cold {fnum(cold_hits)}"),
        # Decode is often assumed to be untouched by the cache. Under concurrency
        # it is usually faster, because prefill chunks and decode steps compete
        # for the same forward passes and a cache hit removes the prefill work.
        check("Prefix cache does not slow decode",
              hot_itl <= cold_itl * 1.1 if None not in (hot_itl, cold_itl) and cold_itl else None,
              f"hot ITL {fnum(hot_itl)}s vs cold ITL {fnum(cold_itl)}s"),
    ])
    if None not in (hot_itl, cold_itl) and cold_itl and hot_itl < cold_itl * 0.9:
        notes.append(
            f"Prompt reuse sped up generation itself by {cold_itl / hot_itl:.1f}x "
            f"({hot_itl:.4f}s per token against {cold_itl:.4f}s). Reuse is normally described as "
            "saving only the time spent reading the prompt. Under load it saves more than that, "
            "because reading and writing share the same passes through the model, so removing "
            "reading work leaves more of each pass for writing. Prompt reuse is a throughput "
            "lever here, not only a first-token lever."
        )

    constraint = report.get("concurrency_constraint") or {}
    if constraint.get("binding") == "max_num_seqs" and (constraint.get("headroom_ratio") or 0) > 1.5:
        notes.append(
            f"The concurrency ceiling came from the scheduler's sequence limit "
            f"(max_num_seqs = {constraint.get('max_num_seqs')}), not from memory. There was enough "
            f"cache for roughly {constraint.get('kv_limit')} sessions at this context length, about "
            f"{constraint.get('headroom_ratio')} times the level actually tested. So what this run "
            "shows is requests queueing for a sequence slot, and it says nothing about running out "
            "of memory. Use a longer context to make memory the limit instead."
        )
    if not report.get("metric_selector") and any(test.get("prometheus") for test in tests.values()):
        notes.append(
            "No metric label selector was set, so every server-side figure sums all vLLM instances "
            "in the cluster. Other traffic is mixed in; treat these as upper bounds."
        )
    if report.get("metrics_missing"):
        notes.append("Metric families absent from /metrics: " + ", ".join(report["metrics_missing"]))
    if unsteady:
        notes.append(
            "These tests never had all workers busy at once, so their throughput includes ramp-up "
            "and drain and reads low: " + ", ".join(sorted(unsteady))
        )
    dropped = undersampled_curve_tests(tests, curve_shape)
    if dropped:
        notes.append(
            f"Dropped from the curve for completing fewer than {MIN_CURVE_SAMPLES} requests, which "
            "leaves nothing to take a percentile of: " + ", ".join(dropped)
            + ". Raise BENCH_MIN_REQUESTS_PER_WORKER or BENCH_TEST_DURATION_SECONDS so every "
            "worker finishes several requests at this shape."
        )
    notes.append(
        f"The concurrency curve ran the {curve_shape} shape. Latency at each level describes that "
        "shape only, and a different ratio at the same concurrency will not match it."
    )

    tuned_point = next((p for p in curve["levels"] if p.get("tuned")), None)
    if tuned_point:
        notes.append(
            f"Tuned setting is concurrency {tuned_point['concurrency']}, where this run's "
            f"linear-scaling line crosses its maximum-throughput line: peak rate "
            f"{curve['max_request_rate']:.2f} requests/sec times minimum latency "
            f"{curve['min_latency']:.2f}s gives {curve['tuned_exact']:.1f}. It delivers "
            f"{tuned_point['throughput_fraction']:.0%} of peak throughput at "
            f"{tuned_point['latency_multiple']:.1f}x single-session latency."
        )
    return {
        "checks": checks,
        "missing_tests": missing,
        "notes": notes,
        "curve": curve,
        "balance": balance,
        "peak_throughput_concurrency": curve["peak"],
        "tuned": curve["tuned"],
    }


# ----------------------------------------------------------------------- charts


def nice_ceiling(value: float) -> float:
    if value <= 0:
        return 1.0
    magnitude = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 2.5, 5, 10):
        if value <= step * magnitude:
            return step * magnitude
    return 10 * magnitude


def axis_ticks(maximum: float, count: int = 4) -> list[float]:
    top = nice_ceiling(maximum)
    return [top * index / count for index in range(count + 1)]


def escape(text: Any) -> str:
    return html.escape(str(text), quote=True)


def line_chart(
    title: str, notes: list[str], x_label: str, y_label: str,
    series: list[dict[str, Any]], value_format: Callable[[float], str],
    highlight: tuple[float, str] | None = None,
    baseline: tuple[float, str] | None = None,
    axis_floor: float | None = None,
    table: str = "",
) -> str:
    width, height = 720, 320
    left, right, top, bottom = 64, 24, 28, 52
    points = [point for item in series for point in item["points"]]
    if not points:
        return ""
    xs = sorted({x for x, _ in points})
    # Without a floor the axis rescales to whatever tiny range the data occupies,
    # which turns measurement noise into a dramatic-looking curve.
    y_max = max(max(y for _, y in points), axis_floor or 0)
    ticks = axis_ticks(y_max)
    x_min, x_max = min(xs), max(xs)
    span = (x_max - x_min) or 1

    def px(x: float) -> float:
        return left + (x - x_min) / span * (width - left - right)

    def py(y: float) -> float:
        return height - bottom - (y / ticks[-1]) * (height - top - bottom)

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart" '
             f'aria-label="{escape(title)}">']
    for tick in ticks:
        parts.append(
            f'<line class="grid" x1="{left}" y1="{py(tick):.1f}" x2="{width - right}" y2="{py(tick):.1f}"/>'
            f'<text class="tick" x="{left - 10}" y="{py(tick) + 4:.1f}" text-anchor="end">'
            f'{escape(value_format(tick))}</text>'
        )
    parts.append(f'<line class="axis" x1="{left}" y1="{height - bottom}" '
                 f'x2="{width - right}" y2="{height - bottom}"/>')
    for x in xs:
        parts.append(
            f'<text class="tick" x="{px(x):.1f}" y="{height - bottom + 18}" '
            f'text-anchor="middle">{escape(int(x))}</text>'
        )
    parts.append(f'<text class="axis-label" x="{(left + width - right) / 2:.0f}" '
                 f'y="{height - 8}" text-anchor="middle">{escape(x_label)}</text>')
    parts.append(f'<text class="axis-label" x="14" y="{top - 12}" text-anchor="start">'
                 f'{escape(y_label)}</text>')
    if highlight:
        x_value, label = highlight
        # Flip the label inward once the marker sits near the right edge.
        near_edge = px(x_value) > left + 0.7 * (width - left - right)
        anchor, offset = ("end", -6) if near_edge else ("start", 6)
        parts.append(
            f'<line class="marker" x1="{px(x_value):.1f}" y1="{top}" '
            f'x2="{px(x_value):.1f}" y2="{height - bottom}"/>'
            f'<text class="marker-label" x="{px(x_value) + offset:.1f}" y="{top + 4}" '
            f'text-anchor="{anchor}">{escape(label)}</text>'
        )
    if baseline and baseline[0] is not None and baseline[0] <= ticks[-1]:
        # A horizontal reference at the unloaded value, so a reader can see how
        # far from "machine to itself" any point on the curve really is.
        parts.append(
            f'<line class="marker" x1="{left}" y1="{py(baseline[0]):.1f}" '
            f'x2="{width - right}" y2="{py(baseline[0]):.1f}"/>'
        )
        # Put the label on whichever end the data sits furthest from the
        # reference, so it never lands on a mark or a series label.
        ordered_points = sorted(series[0]["points"])
        first_y, last_y = ordered_points[0][1], ordered_points[-1][1]
        on_left = abs(first_y - baseline[0]) > abs(last_y - baseline[0])
        label_x, anchor = (left + 6, "start") if on_left else (width - right - 4, "end")
        parts.append(
            f'<text class="marker-label" x="{label_x}" y="{py(baseline[0]) - 7:.1f}" '
            f'text-anchor="{anchor}">{escape(baseline[1])}</text>'
        )
    for index, item in enumerate(series):
        color = f"var({SERIES[index % len(SERIES)]})"
        path = " ".join(
            f"{'M' if position == 0 else 'L'}{px(x):.1f},{py(y):.1f}"
            for position, (x, y) in enumerate(sorted(item["points"]))
        )
        parts.append(f'<path class="line" d="{path}" stroke="{color}"/>')
        for x, y in sorted(item["points"]):
            parts.append(
                f'<circle class="dot" cx="{px(x):.1f}" cy="{py(y):.1f}" r="5" fill="{color}">'
                f'<title>{escape(item["name"])} at {escape(int(x))} concurrent: '
                f'{escape(value_format(y))}</title></circle>'
            )
        last_x, last_y = max(sorted(item["points"]))
        # Series that end at the same value would print their labels on top of
        # each other, so each one steps further above the final point.
        parts.append(
            f'<text class="series-label" x="{px(last_x) - 8:.1f}" '
            f'y="{py(last_y) - 12 - index * 15:.1f}" '
            f'text-anchor="end">{escape(item["name"])}</text>'
        )
    parts.append("</svg>")
    legend = "".join(
        f'<span class="key"><i style="background:var({SERIES[index % len(SERIES)]})"></i>'
        f'{escape(item["name"])}</span>'
        for index, item in enumerate(series)
    ) if len(series) > 1 else ""
    return figure(title, notes, "".join(parts), legend, table)


def stacked_bars(title: str, notes: list[str], rows: list[dict[str, Any]], names: list[str],
                 value_suffix: str = "") -> str:
    if not rows:
        return ""
    width, row_height, label_width = 720, 46, 190
    height = len(rows) * row_height + 24
    bar_width = width - label_width - 90
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart" '
             f'aria-label="{escape(title)}">']
    for index, row in enumerate(rows):
        y = index * row_height + 12
        total = sum(row["values"]) or 1
        parts.append(f'<text class="row-label" x="0" y="{y + 20}">{escape(row["label"])}</text>')
        offset = 0.0
        for position, amount in enumerate(row["values"]):
            span = amount / total * bar_width
            # 2px surface gap between adjacent segments keeps the boundary legible.
            drawn = max(span - 2, 0)
            parts.append(
                f'<rect class="seg" x="{label_width + offset:.1f}" y="{y}" width="{drawn:.1f}" '
                f'height="24" rx="4" fill="var({SERIES[position % len(SERIES)]})">'
                f'<title>{escape(row["label"])} {escape(names[position])}: '
                f'{amount / total * 100:.1f}% ({amount:.2f}s)</title></rect>'
            )
            offset += span
        parts.append(
            f'<text class="row-value" x="{width - 84}" y="{y + 17}">'
            f'{row["values"][0] / total * 100:.1f}%{escape(value_suffix)}</text>'
        )
    parts.append("</svg>")
    legend = "".join(
        f'<span class="key"><i style="background:var({SERIES[index % len(SERIES)]})"></i>{escape(name)}</span>'
        for index, name in enumerate(names)
    )
    return figure(title, notes, "".join(parts), legend)


def bar_chart(
    title: str, notes: list[str], categories: list[str], values: list[float | None],
    value_format: Callable[[float], str], y_label: str,
) -> str:
    usable = [v for v in values if v is not None]
    if not usable:
        return ""
    width, height = 720, 280
    left, right, top, bottom = 64, 24, 28, 52
    ticks = axis_ticks(max(usable))
    slot = (width - left - right) / len(categories)
    bar = min(slot - 26, 96)

    def py(y: float) -> float:
        return height - bottom - (y / ticks[-1]) * (height - top - bottom)

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" class="chart" '
             f'aria-label="{escape(title)}">']
    for tick in ticks:
        parts.append(
            f'<line class="grid" x1="{left}" y1="{py(tick):.1f}" x2="{width - right}" y2="{py(tick):.1f}"/>'
            f'<text class="tick" x="{left - 10}" y="{py(tick) + 4:.1f}" text-anchor="end">'
            f'{escape(value_format(tick))}</text>'
        )
    parts.append(f'<line class="axis" x1="{left}" y1="{height - bottom}" '
                 f'x2="{width - right}" y2="{height - bottom}"/>')
    parts.append(f'<text class="axis-label" x="14" y="{top - 12}">{escape(y_label)}</text>')
    for index, (label, amount) in enumerate(zip(categories, values)):
        centre = left + slot * (index + 0.5)
        parts.append(
            f'<text class="tick" x="{centre:.1f}" y="{height - bottom + 18}" '
            f'text-anchor="middle">{escape(label)}</text>'
        )
        if amount is None:
            parts.append(f'<text class="tick" x="{centre:.1f}" y="{py(0) - 10:.1f}" '
                         f'text-anchor="middle">not observed</text>')
            continue
        parts.append(
            f'<rect class="seg" x="{centre - bar / 2:.1f}" y="{py(amount):.1f}" width="{bar:.1f}" '
            f'height="{max(height - bottom - py(amount), 1):.1f}" rx="4" '
            f'fill="var({SERIES[index % len(SERIES)]})">'
            f'<title>{escape(label)}: {escape(value_format(amount))}</title></rect>'
            f'<text class="bar-value" x="{centre:.1f}" y="{py(amount) - 8:.1f}" text-anchor="middle">'
            f'{escape(value_format(amount))}</text>'
        )
    parts.append("</svg>")
    return figure(title, notes, "".join(parts), "")


def figure(title: str, notes: list[str], svg: str, legend: str, table: str = "") -> str:
    legend_block = f'<div class="legend">{legend}</div>' if legend else ""
    note_block = ("<ul class=\"notes\">"
                  + "".join(f"<li>{escape(note)}</li>" for note in notes) + "</ul>") if notes else ""
    table_block = f'<div class="figure-table">{table}</div>' if table else ""
    return (
        f'<figure class="card"><h3>{escape(title)}</h3>'
        f'{note_block}{legend_block}{svg}{table_block}</figure>'
    )


CHART_CSS = """
:root {
  color-scheme: light;
  --paper: #f6f7f9; --surface: #ffffff;
  --ink: #0f1319; --ink-2: #4a515e; --ink-3: #838b98;
  --rule: #e3e6ea; --rule-strong: #c6cbd3;
  --series-1: #2a78d6; --series-2: #eb6834; --series-3: #1baf7a;
  --good: #0ca30c; --warning: #fab219; --critical: #d03b3b;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Inter, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --paper: #0b0d11; --surface: #14171d;
    --ink: #f2f4f7; --ink-2: #b3bac6; --ink-3: #7d8592;
    --rule: #232830; --rule-strong: #363d48;
    --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --paper: #0b0d11; --surface: #14171d;
  --ink: #f2f4f7; --ink-2: #b3bac6; --ink-3: #7d8592;
  --rule: #232830; --rule-strong: #363d48;
  --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 20px 96px; background: var(--paper); color: var(--ink);
  font: 15px/1.6 var(--sans);
  -webkit-font-smoothing: antialiased;
}
main { max-width: 1000px; margin: 0 auto; }
.num, code, pre, th, td, .tick, .axis-label { font-variant-numeric: tabular-nums; }

/* masthead ---------------------------------------------------------------- */
.masthead { padding: 56px 0 28px; border-bottom: 1px solid var(--rule-strong); }
h1 {
  font-size: clamp(30px, 4.4vw, 46px); line-height: 1.02; letter-spacing: -0.033em;
  font-weight: 780; margin: 0 0 22px; max-width: 16ch;
}
.facts {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1px; background: var(--rule); border: 1px solid var(--rule);
}
.fact { background: var(--surface); padding: 11px 14px; }
.fact dt {
  font: 600 10.5px/1 var(--mono); letter-spacing: 0.11em; text-transform: uppercase;
  color: var(--ink-3); margin-bottom: 6px;
}
.fact dd { margin: 0; font: 500 14px/1.3 var(--mono); color: var(--ink); word-break: break-word; }
.fact-src {
  display: block; margin-top: 5px; font: 500 10.5px/1.35 var(--mono); color: var(--ink-3);
  letter-spacing: 0.01em;
}
.facts.limits { margin-top: -1px; }
.facts.limits .fact dd { color: var(--ink-2); }

/* the ruler: the whole run in one strip ----------------------------------- */
.ruler { margin: 32px 0 8px; }
.ruler-track { display: flex; gap: 3px; }
.ruler-cell { flex: 1 1 0; min-width: 0; }
.ruler-bar { height: 8px; border-radius: 2px; background: var(--rule-strong); }
.ruler-cell[data-state="linear"] .ruler-bar { background: var(--good); }
.ruler-cell[data-state="sub-linear"] .ruler-bar { background: var(--good); opacity: 0.55; }
.ruler-cell[data-state="flat"] .ruler-bar { background: var(--warning); }
.ruler-cell[data-state="capped"] .ruler-bar { background: var(--critical); opacity: 0.55; }
.ruler-cell[data-state="degraded"] .ruler-bar { background: var(--critical); }
.ruler-n {
  display: block; margin-top: 7px; font: 500 12px/1 var(--mono); color: var(--ink-2);
  text-align: center;
}
.ruler-cell[data-mark] .ruler-n { color: var(--ink); font-weight: 700; }
.ruler-mark {
  display: block; margin-top: 5px; font: 600 9.5px/1.3 var(--mono);
  letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-3); text-align: center;
}
.ruler-scale {
  display: flex; justify-content: space-between; margin-top: 14px;
  font: 600 10.5px/1 var(--mono); letter-spacing: 0.11em; text-transform: uppercase;
  color: var(--ink-3);
}
.ruler-key {
  display: grid; grid-template-columns: 18px max-content 1fr; column-gap: 14px; row-gap: 9px;
  margin-top: 22px; padding-top: 18px; border-top: 1px solid var(--rule);
}
.key-row { display: contents; }
.shape-key {
  display: grid; grid-template-columns: max-content 1fr; column-gap: 14px; row-gap: 9px;
  margin: 18px 0 4px; padding-top: 16px; border-top: 1px solid var(--rule);
}
.ruler-key i { width: 18px; height: 6px; border-radius: 2px; margin-top: 7px; }
.key-label { font: 600 12px/1.6 var(--mono); color: var(--ink); }
.key-note { font: 400 13.5px/1.6 var(--sans); color: var(--ink-2); }

/* sections ---------------------------------------------------------------- */
.eyebrow {
  font: 600 10.5px/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--ink-3); margin: 60px 0 14px; padding-bottom: 10px;
  border-bottom: 1px solid var(--rule);
}
h2 { font-size: 23px; letter-spacing: -0.018em; font-weight: 720; margin: 0 0 18px; }
h3 { font-size: 16px; letter-spacing: -0.008em; font-weight: 700; margin: 0 0 12px; }
p { color: var(--ink-2); margin: 0 0 14px; }

/* summary ------------------------------------------------------------------ */
.summary-card { margin: 26px 0 0; }
.summary { color: var(--ink); font-size: 16px; margin: 0 0 16px; max-width: 74ch; }
.takeaway {
  font: 600 10.5px/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--ink-3); margin: 26px 0 12px;
}
.actions { margin: 0; padding: 0; list-style: none; }
.actions li {
  padding: 12px 0 12px 18px; border-top: 1px solid var(--rule); color: var(--ink-2);
  position: relative; max-width: 82ch;
}
.actions li::before {
  content: ""; position: absolute; left: 0; top: 20px; width: 7px; height: 1px;
  background: var(--series-1);
}
.actions li:last-child { border-bottom: 1px solid var(--rule); }

/* figures ------------------------------------------------------------------ */
.card {
  margin: 0 0 22px; padding: 22px 24px 14px; background: var(--surface);
  border: 1px solid var(--rule);
}
.notes { margin: 0 0 16px; padding: 0; list-style: none; max-width: 82ch; }
.notes li {
  position: relative; padding-left: 15px; margin-bottom: 5px; color: var(--ink-2);
  font-size: 13.5px; line-height: 1.55;
}
.notes li::before {
  content: ""; position: absolute; left: 0; top: 9px; width: 5px; height: 5px;
  border-radius: 50%; background: var(--rule-strong);
}
.chart { width: 100%; height: auto; overflow: visible; margin-top: 4px; }
.grid { stroke: var(--rule); stroke-width: 1; }
.axis { stroke: var(--rule-strong); stroke-width: 1; }
.marker { stroke: var(--ink-3); stroke-width: 1; stroke-dasharray: 2 4; }
.marker-label, .tick, .axis-label, .row-label, .row-value, .bar-value, .series-label {
  font: 500 12px var(--mono); fill: var(--ink-3);
}
.axis-label {
  fill: var(--ink-3); font-size: 10.5px; letter-spacing: 0.11em; text-transform: uppercase;
  font-weight: 600;
}
.row-label { fill: var(--ink-2); }
.row-value, .bar-value, .series-label { fill: var(--ink); font-weight: 700; }
.line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
.dot { stroke: var(--surface); stroke-width: 2; }
.seg { stroke: var(--surface); stroke-width: 2; }
.legend { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 12px; }
.key { display: inline-flex; align-items: center; gap: 7px; font: 500 12px var(--mono);
  color: var(--ink-2); }
.key i { width: 12px; height: 12px; border-radius: 2px; display: inline-block; }

/* tables ------------------------------------------------------------------- */
table { border-collapse: collapse; width: 100%; font: 500 12.5px/1.5 var(--mono);
  margin-bottom: 8px; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--rule); text-align: right;
  white-space: nowrap; }
th:first-child, td:first-child { text-align: left; }
th {
  color: var(--ink-3); font-weight: 600; font-size: 10.5px; letter-spacing: 0.08em;
  text-transform: uppercase; border-bottom: 1px solid var(--rule-strong);
}
.text-left th, .text-left td { text-align: left; white-space: normal; }
.wrap { overflow-x: auto; }
.status { font-weight: 700; }
.PASS { color: var(--good); }
.FAIL { color: var(--critical); }
.NOT { color: var(--ink-3); }
.state-linear { color: var(--good); font-weight: 700; }
.state-sub-linear { color: var(--good); font-weight: 700; opacity: 0.78; }
.state-flat { color: var(--warning); font-weight: 700; }
.state-capped { color: var(--critical); font-weight: 700; opacity: 0.8; }
.state-degraded { color: var(--critical); font-weight: 700; }
.tuned-mark {
  font: 600 9.5px var(--mono); letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--series-1); margin-left: 6px;
}

/* misc --------------------------------------------------------------------- */
.note {
  border-left: 2px solid var(--warning); padding: 4px 0 4px 16px; margin: 0 0 16px;
  font-size: 14px; color: var(--ink-2); max-width: 82ch;
}
.glossary { margin: 20px 0 0; font-size: 13.5px; }
.glossary dt { font: 700 12.5px var(--mono); margin-top: 12px; color: var(--ink); }
.glossary dd { margin: 3px 0 0; color: var(--ink-2); max-width: 82ch; }
a { color: var(--series-1); text-decoration-thickness: 1px; text-underline-offset: 2px; }
td a[class^="state-"] { text-decoration: none; border-bottom: 1px dotted currentColor;
  cursor: help; }
.figure-table { margin-top: 18px; border-top: 1px solid var(--rule); padding-top: 4px; }
.figure-table table { font-size: 12px; margin-bottom: 0; }
.figure-table th, .figure-table td { padding: 6px 8px; }
.capacity td:last-child, .capacity th:last-child { text-align: left; white-space: normal; }
.capacity td:first-child { font-weight: 700; color: var(--ink); }
code { font: 500 12.5px var(--mono); background: var(--paper); border: 1px solid var(--rule);
  border-radius: 3px; padding: 1px 5px; }
.snippet {
  background: var(--paper); border: 1px solid var(--rule); padding: 14px 16px;
  overflow-x: auto; font: 500 12.5px/1.6 var(--mono); color: var(--ink); margin: 0 0 16px;
}
details.checks { margin: 0 0 8px; }
details.checks > summary {
  cursor: pointer; font: 500 13px var(--mono); color: var(--ink-2); padding: 12px 0;
  border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule);
  list-style: none;
}
details.checks > summary::-webkit-details-marker { display: none; }
details.checks > summary::before { content: "+ "; color: var(--ink-3); }
details[open].checks > summary::before { content: "- "; }
details.checks > summary:hover { color: var(--ink); }
details.checks .wrap { margin-top: 14px; }
footer {
  margin-top: 56px; padding-top: 20px; border-top: 1px solid var(--rule);
  font: 500 12px/1.6 var(--mono); color: var(--ink-3); max-width: 82ch;
}
@media (max-width: 640px) {
  .masthead { padding-top: 36px; }
  .card { padding: 18px 16px 12px; }
  .ruler-n { font-size: 10px; }
  .ruler-key { grid-template-columns: 18px 1fr; row-gap: 4px; }
  .shape-key { grid-template-columns: 1fr; row-gap: 2px; }
  .ruler-key .key-note { grid-column: 2; }
  .key-note { margin-bottom: 6px; }
}
"""


def html_table(headers: list[str], rows: list[list[str]], css_class: str = "") -> str:
    head = "".join(f"<th>{escape(item)}</th>" for item in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    return (f'<div class="wrap"><table class="{css_class}"><thead><tr>{head}</tr></thead>'
            f'<tbody>{body}</tbody></table></div>')


def build_html(report: dict[str, Any], analysis: dict[str, Any], source: str) -> str:
    tests = {test["id"]: test for test in report.get("tests", []) if test.get("id")}
    curve = curve_points(tests, report.get("curve_shape", "1:1"))
    peak = analysis.get("peak_throughput_concurrency")
    load: list[str] = []
    shape_charts: list[str] = []
    cache_charts: list[str] = []

    if curve:
        base_point, top_point = curve[0], curve[-1]
        shape = base_point.get("shape", {})
        top_total = max((total_tps(t) for t in curve if total_tps(t) is not None), default=None)
        peak_gen = max((generation_tps(t) or 0 for t in curve), default=0)
        single_gen = generation_tps(base_point) or 0
        # Prompt and generated throughput are identical for a 1:1 shape, so the
        # second line is total rather than prompt: two distinct, useful readings
        # instead of one drawn on top of the other.
        load.append(line_chart(
            "Throughput against concurrency",
            [
                f"Every request reads {shape.get('input_tokens', 0):,} tokens and writes "
                f"{shape.get('output_tokens', 0):,}. No two requests share any text.",
                "Total counts prompt plus generated tokens. Generated counts only what the model "
                "produced, which is the half that costs real time.",
                f"Throughput climbs steeply while batching still pays, then flattens near "
                f"{top_total:,.0f} tokens/sec total.",
                f"Size capacity from the generated line: {peak_gen:,.0f} tokens/sec divided by the "
                f"rate one user needs. At 30 tokens/sec each, roughly {int(peak_gen / 30):,} users.",
            ],
            "concurrent users", "tokens / second",
            [
                {"name": "total", "points": [(t["concurrency"], total_tps(t)) for t in curve
                                             if total_tps(t) is not None]},
                {"name": "generated", "points": [(t["concurrency"], generation_tps(t)) for t in curve
                                                 if generation_tps(t) is not None]},
            ],
            lambda v: f"{v:,.0f}",
        ))

        base_ttft = value(base_point, "summary", "p95_ttft_seconds")
        top_ttft = value(top_point, "summary", "p95_ttft_seconds")
        base_e2e = value(base_point, "summary", "p95_e2e_seconds")
        top_e2e = value(top_point, "summary", "p95_e2e_seconds")
        ttft_growth = top_ttft / base_ttft if base_ttft and top_ttft else None
        e2e_growth = top_e2e / base_e2e if base_e2e and top_e2e else None
        out_tokens = shape.get("output_tokens", 0)

        # Means for the three that must add up; percentiles do not sum, because
        # the p95 TTFT request and the p95 end-to-end request are not the same one.
        latency_rows = []
        shares = []
        for test in curve:
            prefill = value(test, "summary", "mean_prefill_seconds")
            decode = value(test, "summary", "mean_decode_seconds")
            itl = value(test, "summary", "p50_itl_seconds")
            e2e95 = value(test, "summary", "p95_e2e_seconds")
            ttft95 = value(test, "summary", "p95_ttft_seconds")
            if None in (prefill, decode):
                continue
            total = prefill + decode
            shares.append(decode / total)
            latency_rows.append([
                escape(test["concurrency"]), f"{prefill:.2f}s", f"{decode:.2f}s", f"{total:.2f}s",
                f"{decode / total:.0%}", f"{itl * 1000:.2f}ms" if itl else "n/a",
                f"{ttft95:.2f}s" if ttft95 else "n/a", f"{e2e95:.1f}s" if e2e95 else "n/a",
            ])
        latency_table = html_table(
            ["Users", "TTFT", "Decode", "E2E", "Decode share", "ITL", "TTFT p95", "E2E p95"],
            latency_rows) if latency_rows else ""

        itl_base = value(curve[0], "summary", "p50_itl_seconds")
        itl_top = value(curve[-1], "summary", "p50_itl_seconds")
        notes = [
            "TTFT is queue time plus prefill: how long until the first token. End-to-end adds "
            f"decode for the remaining {out_tokens - 1:,} tokens.",
            f"Both lines are seconds on one axis. TTFT sitting near the floor is the finding: at "
            f"concurrency {top_point['concurrency']} it is {top_ttft:.1f}s of a {top_e2e:.0f}s "
            f"request.",
            f"TTFT grew {ttft_growth:,.0f}x and flattens. End-to-end grew {e2e_growth:,.0f}x and "
            "does not, because decode time scales with how many sequences share each forward pass.",
        ]
        if shares:
            notes.append(
                f"Decode is {shares[0]:.0%} of the request at concurrency {curve[0]['concurrency']} "
                f"and {shares[-1]:.0%} at {curve[-1]['concurrency']}. TTFT's share falls as load "
                "rises, so the growing part of a request is the part TTFT does not measure."
            )
        if None not in (itl_base, itl_top) and itl_base:
            notes.append(
                f"ITL went from {itl_base * 1000:.2f}ms to {itl_top * 1000:.2f}ms, "
                f"{itl_top / itl_base:,.0f}x. Multiplied by {out_tokens:,} output tokens that "
                f"accounts for the whole end-to-end increase: every 1ms of ITL costs "
                f"{out_tokens / 1000:.1f}s of end-to-end time at this output length."
            )
        notes.append(
            "In the table below TTFT, decode and end-to-end are means so the three add up. The "
            "chart plots p95, which is what a slow user actually experiences."
        )
        load.append(line_chart(
            "Latency against concurrency", notes,
            "concurrent users", "seconds (p95)",
            [
                {"name": "end-to-end",
                 "points": [(t["concurrency"], value(t, "summary", "p95_e2e_seconds")) for t in curve
                            if value(t, "summary", "p95_e2e_seconds") is not None]},
                {"name": "time to first token",
                 "points": [(t["concurrency"], value(t, "summary", "p95_ttft_seconds")) for t in curve
                            if value(t, "summary", "p95_ttft_seconds") is not None]},
            ],
            lambda v: f"{v:,.0f}s", table=latency_table,
        ))

        per_user = [(t["concurrency"], (generation_tps(t) or 0) / t["concurrency"])
                    for t in curve if generation_tps(t) is not None]
        if per_user:
            fastest, slowest = per_user[0][1], per_user[-1][1]
            load.append(line_chart(
                "Per-user token rate against concurrency",
                [
                    "Generated throughput divided by concurrency: the rate a single user sees "
                    "their response stream.",
                    f"{fastest:,.0f} tokens/sec alone, {slowest:,.0f} at concurrency "
                    f"{per_user[-1][0]}. That is {fastest / slowest:,.0f}x slower per user.",
                    "This is the trade concurrency makes: aggregate output up, individual speed "
                    "down. Dashed line marks 30 tokens/sec, roughly human reading pace.",
                ],
                "concurrent users", "tokens / second per user",
                [{"name": "per-user rate", "points": per_user}], lambda v: f"{v:,.0f}",
                baseline=(30.0, "reading pace"),
            ))

        queue = [(t["concurrency"], value(t, "prometheus", "mean_requests_waiting")) for t in curve
                 if value(t, "prometheus", "mean_requests_waiting") is not None]
        if queue:
            worst = max(depth for _, depth in queue)
            worst_at = max(queue, key=lambda item: item[1])[0]
            top_running = value(curve[-1], "prometheus", "mean_requests_running")
            top_rate = value(curve[-1], "summary", "requests_per_second")
            top_prefill = value(curve[-1], "summary", "mean_prefill_seconds")
            # Depth only means something against the load offered at that level.
            share = worst / worst_at if worst_at else 0
            below = max([d for c, d in queue if c < worst_at], default=0.0)
            backlogged = share >= QUEUE_BACKLOG_FRACTION
            queue_notes = [
                "Requests that have arrived but have not yet been admitted to the running batch, "
                "averaged across each test window. This counts admission backlog only.",
                (f"Peak mean depth {worst:.2f} requests at concurrency {worst_at}, which is "
                 f"{share:.0%} of the load offered at that level, so admission is a real cost "
                 f"there. Every level below it stayed at or under {below:.2f}, so the backlog "
                 "appears only at the top of the curve.")
                if backlogged else
                (f"Peak mean depth {worst:.2f} requests at concurrency {worst_at}, under "
                 f"{QUEUE_BACKLOG_FRACTION:.0%} of the load offered at that level, so admission "
                 "was never the bottleneck: the scheduler had a free slot essentially whenever a "
                 "request showed up."),
            ]
            if not backlogged and None not in (top_running, top_rate, top_prefill) and top_prefill:
                queue_notes.append(
                    f"That is not the same as being fast. At concurrency {curve[-1]['concurrency']}, "
                    f"{top_running:.0f} requests were in the running state on average and TTFT was "
                    f"{top_prefill:.2f}s. Had requests spent that time queued, average depth would "
                    f"have been about {top_rate * top_prefill:.1f}, not {worst:.2f}."
                )
            queue_notes.append(
                "Chunked prefill is why this line stays low for most of the curve. vLLM admits a "
                "request almost immediately and then processes its prompt a slice at a time, "
                "sharing each forward pass with every sequence already generating. The wait moves "
                "out of the queue and into execution, so a low line here says the scheduler kept "
                "up with admission and says nothing about latency."
            )
            load.append(line_chart(
                "Scheduler queue depth against concurrency", queue_notes,
                "concurrent users", "requests waiting",
                [{"name": "mean waiting", "points": queue}], lambda v: f"{v:,.1f}",
                axis_floor=1.0,
            ))
        kv = [(t["concurrency"], value(t, "prometheus", "max_kv_cache_usage")) for t in curve
              if value(t, "prometheus", "max_kv_cache_usage") is not None]
        if kv:
            worst_kv = max(fraction for _, fraction in kv)
            kv_notes = [
                "Fraction of GPU KV cache held by active sequences. Each request holds memory for "
                "its whole context until it finishes.",
                f"Peaked at {worst_kv:.0%}.",
            ]
            kv_notes.append(
                "Memory was never the binding constraint and nothing was preempted. Context length "
                "fills this far faster than concurrency does: raise BENCH_TOKEN_BUDGET, not the "
                "user count, to find the memory limit."
                if worst_kv < 0.8 else
                "Close to full. Past this the scheduler preempts and recomputes sequences, which "
                "is the most expensive failure mode available."
            )
            load.append(line_chart(
                "KV cache utilization against concurrency", kv_notes,
                "concurrent users", "fraction of cache in use",
                [{"name": "peak utilization", "points": kv}], lambda v: f"{v:,.0%}",
                axis_floor=1.0,
            ))

    shape_rows = []
    for test_id in ("T01", "T02", "T03", "T04"):
        test = tests.get(test_id)
        if not test:
            continue
        prefill = value(test, "summary", "mean_prefill_seconds")
        decode = value(test, "summary", "mean_decode_seconds")
        if None in (prefill, decode):
            continue
        shape = test.get("shape", {})
        shape_rows.append({
            "label": f"{test_id}  {shape.get('ratio')}  {shape.get('input_tokens')}in / "
                     f"{shape.get('output_tokens')}out",
            "values": [prefill, decode],
        })
    if shape_rows:
        shape_charts.append(stacked_bars(
            "Prefill and decode time per request",
            [
                "Single request, no other load. Blue is prefill (processing the prompt), orange is "
                "decode (generating the response).",
                "Prefill runs the whole prompt through the model in one pass. Decode needs one "
                "pass per token, so it dominates wall-clock time.",
                "This is why equal input and output token counts are nowhere near equal time, and "
                "why token counts alone predict latency badly.",
            ],
            shape_rows, ["prefill", "decode"], " prefill",
        ))
        seen_ratios = []
        for test_id in ("T01", "T02", "T03", "T04"):
            ratio = (tests.get(test_id) or {}).get("shape", {}).get("ratio")
            if ratio in SHAPE_MEANING and ratio not in seen_ratios:
                seen_ratios.append(ratio)
        if seen_ratios:
            shape_charts.append(
                '<div class="shape-key">' + "".join(
                    f'<div class="key-row"><span class="key-label">{escape(ratio)}</span>'
                    f'<span class="key-note">{escape(SHAPE_MEANING[ratio])}</span></div>'
                    for ratio in seen_ratios
                ) + "</div>"
            )

    cache_ids = ["T08", "T09", "T10"]
    labels = ["hot", "mixed", "cold"]
    if all(test_id in tests for test_id in cache_ids):
        cache_charts.append(bar_chart(
            "Prefix cache effect on TTFT",
            [
                "Same shape, same concurrency in all three. Only the amount of shared prompt text "
                "changes.",
                "vLLM keeps the KV blocks for a prompt prefix it has already processed and reuses "
                "them instead of recomputing.",
                "More sharing means less prefill work, so the first token arrives sooner.",
            ],
            [f"{label} ({test_id})" for label, test_id in zip(labels, cache_ids)],
            [value(tests[test_id], "summary", "p95_ttft_seconds") for test_id in cache_ids],
            lambda v: f"{v:,.2f}s", "p95 TTFT (seconds)",
        ))
        token_rows, token_table_rows = [], []
        for label, test_id in zip(labels, cache_ids):
            test = tests[test_id]
            ratio = value(test, "prometheus", "cached_token_ratio")
            successes = value(test, "summary", "successes") or 0
            queried = value(test, "prometheus", "prefix_cache_queries")
            computed = value(test, "prometheus", "prefill_kv_computed_tokens")
            if ratio is None or not successes or not queried:
                continue
            per_request = queried / successes
            reused = per_request * ratio
            recomputed = (computed / successes) if computed else per_request - reused
            token_rows.append({"label": f"{label} ({test_id})", "values": [reused, recomputed]})
            token_table_rows.append([
                escape(f"{label} ({test_id})"), f"{per_request:,.0f}", f"{reused:,.0f}",
                f"{recomputed:,.0f}", f"{ratio:.0%}",
            ])
        if token_rows:
            cold_compute = token_rows[-1]["values"][1]
            hot_compute = token_rows[0]["values"][1]
            cache_charts.append(stacked_bars(
                "Prompt tokens reused against tokens recomputed",
                [
                    "Per request, in tokens. Blue is prompt text the server already had cached and "
                    "skipped. Orange is text it had to push through the model again.",
                    f"With no reuse every request recomputes {cold_compute:,.0f} tokens. With full "
                    f"reuse that falls to {hot_compute:,.0f}, "
                    + (f"a {cold_compute / hot_compute:,.1f}x reduction in prefill work."
                       if hot_compute else "eliminating prefill work almost entirely."),
                    "The hit ratio is the percentage; this is what the percentage costs in work. "
                    "Scale it to your own context length to see what reuse is worth.",
                ],
                token_rows, ["reused from cache", "recomputed"], " reused",
            ))
            cache_charts.append(
                '<figure class="card"><h3>Prefix cache token accounting</h3>'
                + html_table(
                    ["Cache state", "Prompt tokens / request", "Reused", "Recomputed", "Hit ratio"],
                    token_table_rows)
                + '<ul class="notes"><li>Counted from vLLM\'s own counters over each test window '
                  'and divided by the requests completed in it.</li></ul></figure>'
            )
        cache_charts.append(bar_chart(
            "Prefix cache effect on inter-token latency",
            [
                "ITL is the gap between generated tokens. Prefix caching saves prefill work, so in "
                "isolation it should leave decode untouched.",
                "Under concurrency it does not. vLLM schedules prefill chunks and decode steps into "
                "the same forward passes, so prefill work crowds out decode.",
                "Remove the prefill and each pass has more room to decode, and responses stream "
                "faster. The effect disappears at concurrency 1, where there is nothing to compete "
                "with.",
            ],
            [f"{label} ({test_id})" for label, test_id in zip(labels, cache_ids)],
            [value(tests[test_id], "summary", "p50_itl_seconds") for test_id in cache_ids],
            lambda v: f"{v:,.3f}s", "p50 ITL (seconds)",
        ))

    table_rows = []
    for test in report.get("tests", []):
        summary = test.get("summary") or {}
        table_rows.append([
            f'<a href="#test-{escape(test.get("id"))}">{escape(test.get("id"))}</a>',
            escape(test.get("shape", {}).get("ratio")),
            escape(test.get("cache")), escape(test.get("concurrency")),
            escape(summary.get("successes")),
            fnum(finite(summary.get("prompt_tokens_per_second")), 0),
            fnum(finite(summary.get("generation_tokens_per_second")), 0),
            fnum(finite(summary.get("p50_ttft_seconds"))),
            fnum(finite(summary.get("p95_ttft_seconds"))),
            fnum(finite(summary.get("p95_e2e_seconds")), 1),
            fnum(finite(summary.get("p50_itl_seconds")), 4),
            fnum(value(test, "prometheus", "max_requests_waiting"), 0),
            fnum(value(test, "prometheus", "max_kv_cache_usage"), 2),
        ])
    data_table = html_table(
        ["Test", "Shape", "Cache", "Users", "Reqs", "Prompt tok/s", "Gen tok/s",
         "p50 first word", "p95 first word", "p95 full reply", "p50 ITL", "Peak waiting", "KV max"],
        table_rows,
    )
    check_rows = [
        [f'<span class="status {item["status"].split()[0]}">{escape(item["status"])}</span>',
         escape(item["name"]), escape(item["evidence"])]
        for item in analysis["checks"]
    ]
    passed = sum(1 for item in analysis["checks"] if item["status"] == "PASS")
    checks_table = (
        f'<details class="checks"><summary>{len(analysis["checks"])} automated checks, '
        f'{passed} passed. Open if you want the verification detail.</summary>'
        + html_table(["Status", "Expectation", "Evidence"], check_rows, "text-left")
        + "</details>"
    )
    notes = "".join(f'<p class="note">{escape(note)}</p>' for note in analysis.get("notes", []))
    levels = (analysis.get("curve") or {}).get("levels", [])
    state_rows = [
        [escape(p["concurrency"]) + (' <span class="tuned-mark">tuned</span>'
                                     if p.get("tuned") else ""),
         fnum(p["throughput"], 0), f'{p["throughput_fraction"]:.0%}',
         fnum(p.get("scaling_efficiency"), 2),
         fnum(p.get("ttft"), 2) + "s", fnum(p.get("e2e"), 1) + "s",
         fnum(p.get("latency_multiple"), 1) + "x", fnum(p.get("per_user"), 0),
         f'<a class="state-{escape(p["state"].replace(" ", "-"))}" href="#states" '
         f'title="{escape(dict(STATE_MEANING).get(p["state"], ""))}">{escape(p["state"])}</a>']
        for p in levels
    ]
    classification = html_table(
        ["Users", "Total tok/s", "% of peak", "Scaling eff.", "p95 TTFT", "p95 E2E",
         "Latency x", "Per-user tok/s", "State"], state_rows)
    if levels:
        classification += ('<dl class="glossary" id="states">' + "".join(
            f"<dt>{escape(name)}</dt><dd>{escape(meaning)}</dd>"
            for name, meaning in STATE_MEANING) + "</dl>")
        classification += (
            f'<p>Tuned setting <strong>{escape(analysis.get("tuned"))}</strong> concurrent '
            f'sessions, where the scaling line crosses the throughput ceiling. Peak throughput at '
            f'<strong>{escape(analysis.get("peak_throughput_concurrency"))}</strong>, which costs '
            f'more latency for the last increment.</p>'
        )
    constraint = report.get("concurrency_constraint") or {}
    brief = executive_summary(report, analysis)
    summary_block = ('<ul class="actions">'
                     + "".join(f"<li>{escape(point)}</li>" for point in brief["points"])
                     + "</ul>") if brief["points"] else ""
    if brief["actions"]:
        summary_block += ('<h3 class="takeaway">What to do about it</h3><ul class="actions">'
                          + "".join(f"<li>{escape(a)}</li>" for a in brief["actions"]) + "</ul>")
    plan = next_run(report, analysis)
    next_block = ""
    if plan.get("reason"):
        next_block = "".join(f"<p>{escape(item)}</p>" for item in plan["reason"])
        if plan.get("env"):
            body = "\n".join(f'            - name: {k}\n              value: "{v}"'
                              for k, v in plan["env"].items())
            next_block += ("<p>Edit these values in <code>k8s/job.yaml</code> and create it "
                           f"again:</p><pre class=\"snippet\">{escape(body)}</pre>")
        next_block += (
            "<p>To test the memory limit instead, change one value and rerun: "
            f"<code>BENCH_TOKEN_BUDGET={escape(plan['agentic_budget'])}</code>. Raise "
            "<code>BENCH_TEST_DURATION_SECONDS</code> to 420 and drop "
            "<code>BENCH_MIN_REQUESTS_PER_WORKER</code> to 1, because each request takes far "
            "longer at that size.</p>")
    ruler_block = concurrency_ruler(analysis)
    capacity = capacity_table(report, analysis)
    capacity_block = ""
    if capacity.get("rows"):
        rows = [[escape(f"{r['users']:,}"), escape(f"{r['rate']:,} tok/s"), escape(r["note"])]
                for r in capacity["rows"]]
        capacity_block = (
            "".join(f"<p>{escape(note)}</p>" for note in capacity_ceiling_note(capacity))
            + "<p>A throughput number only becomes a user count once you say how fast each user "
              "needs their tokens:</p>"
            + html_table(["Concurrent users", "Per-user rate", "What that rate means"],
                         rows, "capacity")
            + '<p class="note">These counts assume every user is generating at once. Real traffic '
              'is bursty, so the number of people a deployment serves is higher than the number '
              'generating simultaneously.</p>'
        )
    kv_limit = constraint.get("kv_limit")
    kv_tokens = constraint.get("kv_cache_tokens")
    seq_limit = constraint.get("max_num_seqs")
    kv_sessions = f"{kv_limit} sessions" if kv_limit else "unknown"
    kv_detail = (f"{kv_tokens:,} tok / {report.get('token_budget', 0):,} per request"
                 if kv_tokens else "hardware derived")
    running = [value(t, "prometheus", "max_requests_running") for t in report.get("tests", [])]
    running = [r for r in running if r]
    offered = max((t.get("concurrency") or 0) for t in report.get("tests", [])) or 0
    if running:
        observed = max(running)
        peak_running = f"{observed:.0f} sessions"
        peak_running_note = ("scheduler capped below offered load" if observed < offered
                             else "no scheduler cap reached")
    else:
        peak_running, peak_running_note = "not observed", "needs Prometheus"
    binding_note = ("set by the Job, not by hardware"
                    if constraint.get("binding") == "BENCH_MAX_CONCURRENCY"
                    else "hardware or server config")
    reference_rows = [
        [f'<span id="test-{escape(row["id"])}">{escape(row["id"])}</span>', escape(row["workload"]),
         escape(row["looks_like"]), escape(row["sessions"]), escape(row["reuse"]),
         escape(row["purpose"])]
        for row in test_reference(report)
    ]
    reference_block = html_table(
        ["Test", "Workload", "Looks like", "Sessions", "Prompt reuse", "Purpose"],
        reference_rows, "text-left")
    reference_block += '<dl class="glossary">' + "".join(
        f"<dt>{escape(term)}</dt><dd>{escape(meaning)}</dd>" for term, meaning in GLOSSARY) + "</dl>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vLLM inference behavior</title>
<style>{CHART_CSS}</style></head>
<body><main>
<header class="masthead">
<h1>Inference behavior under concurrency</h1>
<dl class="facts">
<div class="fact"><dt>Model</dt><dd>{escape(report.get('model', 'unknown'))}</dd></div>
<div class="fact"><dt>Context per request</dt><dd>{escape(f"{report.get('token_budget', 0):,}")} tok</dd></div>
<div class="fact"><dt>Started</dt><dd>{escape(str(report.get('started_at', 'unknown'))[:19].replace('T', ' '))}</dd></div>
</dl>
<dl class="facts limits">
<div class="fact"><dt>Concurrency tested</dt><dd>{escape(report.get('theoretical_concurrency', '?'))}<span class="fact-src">benchmark parameter</span></dd></div>
<div class="fact"><dt>KV cache capacity</dt><dd>{escape(kv_sessions)}<span class="fact-src">{escape(kv_detail)}</span></dd></div>
<div class="fact"><dt>Peak running</dt><dd>{escape(peak_running)}<span class="fact-src">{escape(peak_running_note)}</span></dd></div>
<div class="fact"><dt>Binding limit</dt><dd>{escape(BINDING_LABEL.get(constraint.get('binding'), constraint.get('binding', 'unknown')))}<span class="fact-src">{escape(binding_note)}</span></dd></div>
</dl>
{ruler_block}
</header>
<section class="summary-card">{summary_block}</section>
<p class="eyebrow">Capacity</p>\n<h2>What this configuration supports</h2>
{capacity_block}
<p class="eyebrow">Concurrency</p>\n<h2>Throughput, latency and saturation</h2>
{''.join(load)}
<p class="eyebrow">Request shape</p>\n<h2>Where request time is spent</h2>
{''.join(shape_charts)}
<p class="eyebrow">Prefix cache</p>\n<h2>What prompt reuse buys</h2>
{''.join(cache_charts)}
<p class="eyebrow">Classification</p>\n<h2>Operational classification by concurrency</h2>
{classification}
<p class="eyebrow">Verification</p>
{checks_table}
<p class="eyebrow">Caveats</p>\n<h2>Measurement caveats</h2>
{notes}
<p class="eyebrow">Raw data</p>\n<h2>Every measurement</h2>
{data_table}
<p class="eyebrow">Next run</p>\n<h2>What to run next</h2>
{next_block}
<p class="eyebrow">Appendix</p>\n<h2>Appendix: what each test ran</h2>
{reference_block}
<footer>Source: {escape(source)}. Throughput is measured over the steady window of each test,
excluding ramp-up and drain. Prompt tokens and generated tokens cost different amounts of compute,
so the two throughput columns are never summed across shapes.</footer>
</main></body></html>
"""


# --------------------------------------------------------------------- markdown


def markdown(report: dict[str, Any], analysis: dict[str, Any], source: str) -> str:
    constraint = report.get("concurrency_constraint") or {}
    lines = [
        "# vLLM benchmark analysis", "", f"- Source: `{source}`",
        f"- Run started: {report.get('started_at', 'unknown')}",
        f"- Model: `{report.get('model', 'unknown')}`",
        f"- Token budget: {report.get('token_budget', 'unknown')}",
        f"- Theoretical concurrency: {report.get('theoretical_concurrency', 'unknown')}"
        + (f" (bound by {constraint['binding']})" if constraint.get("binding") else ""),
        f"- Metric selector: `{report.get('metric_selector') or 'unset'}`", "",
    ]
    brief = executive_summary(report, analysis)
    if brief["points"]:
        lines.extend(["## Summary", ""])
        lines.extend(f"- {point}" for point in brief["points"])
        lines.append("")
    if brief["actions"]:
        lines.extend(["### What to do about it", ""])
        lines.extend(f"- {action}" for action in brief["actions"])
        lines.append("")
    capacity = capacity_table(report, analysis)
    if capacity.get("rows"):
        lines.extend(["## What this configuration supports", ""]
                     + [note + "\n" for note in capacity_ceiling_note(capacity)]
                     + ["",
                      "A throughput number only becomes a user count once you say how fast each "
                      "user needs their tokens:", "",
                      "| Concurrent users | Per-user rate | What that rate means |",
                      "|---:|---:|---|"])
        for row in capacity["rows"]:
            lines.append(f"| {row['users']:,} | {row['rate']:,} tok/s | {row['note']} |")
        lines.extend(["", "These counts assume every user is generating at once. Real traffic is "
                      "bursty, so the number of people a deployment serves is higher than the "
                      "number generating simultaneously.", ""])
    lines.extend([
        "## Test curve", "",
        "| Test | Shape | Cache | Users | Reqs | Prompt tok/s | Gen tok/s | p50 first word "
        "| p95 first word | p95 full reply | Reading share | Peak waiting | KV max |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for test in report.get("tests", []):
        summary = test.get("summary") or {}
        lines.append(
            f"| {test.get('id')} | {test.get('shape', {}).get('ratio', '?')} | {test.get('cache', '?')} | "
            f"{test.get('concurrency', '?')} | {summary.get('successes', '?')} | "
            f"{fnum(finite(summary.get('prompt_tokens_per_second')), 0)} | "
            f"{fnum(finite(summary.get('generation_tokens_per_second')), 0)} | "
            f"{fnum(finite(summary.get('p50_ttft_seconds')))}s | "
            f"{fnum(finite(summary.get('p95_ttft_seconds')))}s | "
            f"{fnum(finite(summary.get('p95_e2e_seconds')), 1)}s | "
            f"{fnum(finite(summary.get('prefill_share')), 3)} | "
            f"{fnum(value(test, 'prometheus', 'max_requests_waiting'), 0)} | "
            f"{fnum(value(test, 'prometheus', 'max_kv_cache_usage'), 2)} |"
        )
    lines.extend(["", "Prompt tokens and generated tokens cost different amounts of compute. "
                  "Compare each column within one shape, never across shapes.", ""])
    lines.extend(["## Relationship checks", "", "| Status | Expectation | Evidence |", "|---|---|---|"])
    for item in analysis["checks"]:
        lines.append(f"| {item['status']} | {item['name']} | {item['evidence']} |")
    levels = (analysis.get("curve") or {}).get("levels", [])
    if levels:
        lines.extend([
            "", "## Operational classification by concurrency", "",
            "| Users | Total tok/s | % of peak | Scaling eff. | p95 TTFT | p95 E2E | "
            "Latency x | Per-user tok/s | State |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ])
        for point in levels:
            lines.append(
                f"| {point['concurrency']}{' *' if point.get('tuned') else ''} | "
                f"{fnum(point['throughput'], 0)} | "
                f"{point['throughput_fraction']:.0%} | "
                f"{fnum(point.get('scaling_efficiency'), 2)} | {fnum(point.get('ttft'), 2)}s | "
                f"{fnum(point.get('e2e'), 1)}s | {fnum(point.get('latency_multiple'), 1)}x | "
                f"{fnum(point.get('per_user'), 0)} | **{point['state']}** |"
            )
        lines.extend(["", "What the states mean:", ""])
        lines.extend(f"- **{name}** — {meaning}" for name, meaning in STATE_MEANING)
        lines.extend([
            "",
            f"- Tuned setting: **{analysis.get('tuned')}** concurrent sessions "
            "(where the scaling line crosses the throughput ceiling)",
            f"- Peak throughput at **{analysis.get('peak_throughput_concurrency')}** concurrent, "
            "which costs more latency for the last increment",
        ])
    if analysis.get("notes"):
        lines.extend(["", "## Measurement caveats", ""])
        lines.extend(f"- {note}" for note in analysis["notes"])
    plan = next_run(report, analysis)
    if plan.get("reason"):
        lines.extend(["", "## What to run next", ""])
        lines.extend(f"- {item}" for item in plan["reason"])
        if plan.get("env"):
            lines.extend([
                "", "Edit these values in `k8s/job.yaml` and create it again:", "", "```yaml",
            ])
            for key, val in plan["env"].items():
                lines.extend([f"            - name: {key}", f'              value: "{val}"'])
            lines.append("```")
        lines.extend([
            "",
            f"To test the memory limit instead, change one value and rerun: "
            f"`BENCH_TOKEN_BUDGET={plan['agentic_budget']}`. Raise "
            "`BENCH_TEST_DURATION_SECONDS` to 420 and drop `BENCH_MIN_REQUESTS_PER_WORKER` to 1, "
            "because each request takes far longer at that size.",
        ])
    reference = test_reference(report)
    if reference:
        lines.extend([
            "", "## Appendix: what each test ran", "",
            "| Test | Workload | Looks like | Sessions | Prompt reuse | Purpose |",
            "|---|---|---|---:|---|---|",
        ])
        for row in reference:
            lines.append(f"| {row['id']} | {row['workload']} | {row['looks_like']} | "
                         f"{row['sessions']} | {row['reuse']} | {row['purpose']} |")
        lines.extend(["", "### Terms", ""])
        lines.extend(f"- **{term}** — {meaning}" for term, meaning in GLOSSARY)
    lines.extend([
        "", "## Analyst notes", "",
        "`NOT OBSERVED` means the evidence is missing, not that the check passed. Read the "
        "normalized JSON and the raw log before blaming the model or the hardware.", ""
    ])
    return "\n".join(lines)


def grafana_annotations(report: dict[str, Any]) -> list[dict[str, Any]]:
    def epoch_ms(stamp: str | None) -> int | None:
        if not stamp:
            return None
        return int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp() * 1000)

    annotations = []
    for test in report.get("tests", []):
        start = epoch_ms(test.get("steady_started_at") or test.get("started_at"))
        end = epoch_ms(test.get("steady_ended_at") or test.get("ended_at"))
        if start is None or end is None:
            continue
        shape = test.get("shape", {})
        annotations.append({
            "text": f"{test.get('id')} {shape.get('ratio')} {test.get('cache')} "
                    f"@ {test.get('concurrency')} concurrent",
            "tags": ["vllm-benchmark", str(test.get("id")), str(test.get("cache"))],
            "time": start, "timeEnd": end,
        })
    return annotations


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

    report = backfill(normalize_nonfinite(parse_report(raw)))
    analysis = analyze(report)
    outputs = {
        "normalized_json": output_dir / f"{stem}-normalized.json",
        "analysis_markdown": output_dir / f"{stem}-analysis.md",
        "report_html": output_dir / f"{stem}-report.html",
        "grafana_annotations": output_dir / f"{stem}-annotations.json",
    }
    outputs["normalized_json"].write_text(json.dumps(
        {"source": source_name, "report": report, "analysis": analysis}, indent=2, allow_nan=False) + "\n")
    outputs["analysis_markdown"].write_text(markdown(report, analysis, source_name))
    outputs["report_html"].write_text(build_html(report, analysis, source_name))
    outputs["grafana_annotations"].write_text(json.dumps(grafana_annotations(report), indent=2) + "\n")
    print(json.dumps({"source": source_name, **{k: str(v) for k, v in outputs.items()}}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
