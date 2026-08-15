#!/usr/bin/env python3
"""Deterministic vLLM workload runner for the T01-T10 benchmark suite."""

from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import json
import math
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class BenchmarkError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)]


@dataclasses.dataclass(frozen=True)
class Config:
    endpoint: str
    api_key: str | None
    model: str | None
    token_budget: int
    max_concurrency: int | None
    scheduler_max_seqs: int | None
    levels: tuple[float, float, float, float]
    prometheus_url: str | None
    request_timeout: float
    results_path: str
    prometheus_settle_seconds: float

    @classmethod
    def from_env(cls) -> "Config":
        endpoint = os.getenv("BENCH_VLLM_ENDPOINT", "").rstrip("/")
        if not endpoint:
            raise BenchmarkError("BENCH_VLLM_ENDPOINT is required")
        budget = int(os.getenv("BENCH_TOKEN_BUDGET", "4080"))
        if budget < 16:
            raise BenchmarkError("BENCH_TOKEN_BUDGET must be at least 16")
        raw_levels = tuple(float(v.strip()) for v in os.getenv(
            "BENCH_CONCURRENCY_LEVELS", "1,0.5,1.0,1.25"
        ).split(","))
        if len(raw_levels) != 4 or raw_levels[0] != 1 or any(v <= 0 for v in raw_levels):
            raise BenchmarkError(
                "BENCH_CONCURRENCY_LEVELS must contain baseline, moderate, saturation, overload; "
                "for example 1,0.5,1.0,1.25"
            )
        max_concurrency = os.getenv("BENCH_MAX_CONCURRENCY")
        scheduler_max = os.getenv("BENCH_SCHEDULER_MAX_SEQS")
        return cls(
            endpoint=endpoint,
            api_key=os.getenv("BENCH_API_KEY"),
            model=os.getenv("BENCH_MODEL"),
            token_budget=budget,
            max_concurrency=int(max_concurrency) if max_concurrency else None,
            scheduler_max_seqs=int(scheduler_max) if scheduler_max else None,
            levels=raw_levels,  # type: ignore[arg-type]
            prometheus_url=os.getenv("BENCH_PROMETHEUS_URL", "").rstrip("/") or None,
            request_timeout=float(os.getenv("BENCH_REQUEST_TIMEOUT", "7200")),
            results_path=os.getenv("BENCH_RESULTS_PATH", "/results/results.json"),
            prometheus_settle_seconds=float(os.getenv("BENCH_PROMETHEUS_SETTLE_SECONDS", "15")),
        )


class VLLMClient:
    def __init__(self, config: Config):
        self.config = config

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def json_request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{self.config.endpoint}{path}", data=body, headers=self._headers(), method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.request_timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise BenchmarkError(f"{method} {path} failed ({exc.code}): {detail}") from exc

    def text_request(self, path: str) -> str:
        request = urllib.request.Request(f"{self.config.endpoint}{path}", headers=self._headers())
        with urllib.request.urlopen(request, timeout=self.config.request_timeout) as response:
            return response.read().decode()

    def discover_model(self) -> str:
        if self.config.model:
            return self.config.model
        models = self.json_request("GET", "/v1/models").get("data", [])
        if not models:
            raise BenchmarkError("vLLM returned no served models")
        return str(models[0]["id"])

    def count_tokens(self, model: str, prompt: str) -> int:
        try:
            result = self.json_request("POST", "/tokenize", {
                "model": model, "prompt": prompt, "add_special_tokens": False
            })
            if "count" in result:
                return int(result["count"])
            return len(result["tokens"])
        except BenchmarkError as exc:
            # Some protected vLLM distributions hide /tokenize. A one-token
            # completion still returns the authoritative tokenizer count.
            if "(404)" not in str(exc):
                raise
            result = self.json_request("POST", "/v1/completions", {
                "model": model,
                "prompt": prompt,
                "max_tokens": 1,
                "temperature": 0,
                "seed": 0,
                "ignore_eos": True,
            })
            return int(result["usage"]["prompt_tokens"])

    def stream_completion(self, model: str, prompt: str, output_tokens: int, request_id: str) -> dict[str, Any]:
        payload = {
            "model": model,
            "prompt": prompt,
            "max_tokens": output_tokens,
            "temperature": 0,
            "seed": 0,
            "ignore_eos": True,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        request = urllib.request.Request(
            f"{self.config.endpoint}/v1/completions",
            data=json.dumps(payload).encode(),
            headers={**self._headers(), "X-Request-Id": request_id},
        )
        started = time.monotonic()
        token_times: list[float] = []
        usage: dict[str, Any] = {}
        try:
            with urllib.request.urlopen(request, timeout=self.config.request_timeout) as response:
                for raw_line in response:
                    line = raw_line.decode(errors="replace").strip()
                    if not line.startswith("data: ") or line == "data: [DONE]":
                        continue
                    event = json.loads(line[6:])
                    if event.get("usage"):
                        usage = event["usage"]
                    choices = event.get("choices", [])
                    if choices and choices[0].get("text"):
                        token_times.append(time.monotonic())
        except Exception as exc:
            return {"request_id": request_id, "error": str(exc), "e2e_seconds": time.monotonic() - started}
        ended = time.monotonic()
        intervals = [b - a for a, b in zip(token_times, token_times[1:])]
        return {
            "request_id": request_id,
            "prompt_tokens": usage.get("prompt_tokens"),
            "output_tokens": usage.get("completion_tokens"),
            "ttft_seconds": token_times[0] - started if token_times else None,
            "mean_itl_seconds": statistics.fmean(intervals) if intervals else None,
            "e2e_seconds": ended - started,
            "error": None,
        }


class PrometheusClient:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def query(self, promql: str, at: str) -> float | None:
        query = urllib.parse.urlencode({"query": promql, "time": at})
        with urllib.request.urlopen(
            f"{self.base_url}/api/v1/query?{query}", timeout=60
        ) as response:
            payload = json.load(response)
        if payload.get("status") != "success":
            raise BenchmarkError(f"Prometheus query failed: {payload}")
        values = payload["data"].get("result", [])
        if not values:
            return None
        return sum(float(item["value"][1]) for item in values)

    def window_summary(self, ended_at: str, window_seconds: float) -> dict[str, float | None]:
        window = f"{max(1, math.ceil(window_seconds))}s"
        histogram = lambda metric: (
            f'histogram_quantile(0.95, sum by (le) (rate({metric}_bucket[{window}])))'
        )
        queries = {
            "prompt_tokens_per_second": f'sum(rate(vllm:prompt_tokens_total[{window}]))',
            "generation_tokens_per_second": f'sum(rate(vllm:generation_tokens_total[{window}]))',
            "max_requests_running": f'max(max_over_time(vllm:num_requests_running[{window}]))',
            "max_requests_waiting": f'max(max_over_time(vllm:num_requests_waiting[{window}]))',
            "max_kv_cache_usage": f'max(max_over_time(vllm:kv_cache_usage_perc[{window}]))',
            "preemptions": f'sum(increase(vllm:num_preemptions[{window}]))',
            "prefix_cache_queries": f'sum(increase(vllm:prefix_cache_queries_total[{window}]))',
            "prefix_cache_hits": f'sum(increase(vllm:prefix_cache_hits_total[{window}]))',
            "prompt_tokens_cached": f'sum(increase(vllm:prompt_tokens_cached_total[{window}]))',
            "prefill_kv_computed_tokens": f'sum(increase(vllm:request_prefill_kv_computed_tokens_sum[{window}]))',
            "p95_ttft_seconds": histogram("vllm:time_to_first_token_seconds"),
            "p95_itl_seconds": histogram("vllm:inter_token_latency_seconds"),
            "p95_queue_seconds": histogram("vllm:request_queue_time_seconds"),
            "p95_e2e_seconds": histogram("vllm:e2e_request_latency_seconds"),
            "mean_prefill_seconds": (
                f'sum(increase(vllm:request_prefill_time_seconds_sum[{window}])) / '
                f'sum(increase(vllm:request_prefill_time_seconds_count[{window}]))'
            ),
            "mean_decode_seconds": (
                f'sum(increase(vllm:request_decode_time_seconds_sum[{window}])) / '
                f'sum(increase(vllm:request_decode_time_seconds_count[{window}]))'
            ),
        }
        result: dict[str, float | None] = {}
        for name, query in queries.items():
            try:
                result[name] = self.query(query, ended_at)
            except (OSError, ValueError, BenchmarkError) as exc:
                print(json.dumps({"warning": f"Prometheus {name}: {exc}"}), file=sys.stderr, flush=True)
                result[name] = None
        queries_count = result.get("prefix_cache_queries") or 0
        hits_count = result.get("prefix_cache_hits") or 0
        result["prefix_cache_hit_ratio"] = hits_count / queries_count if queries_count else None
        return result


@dataclasses.dataclass(frozen=True)
class Shape:
    name: str
    ratio: str
    input_tokens: int
    output_tokens: int


def derive_shapes(budget: int) -> dict[str, Shape]:
    ratios = {"15:1": (15, 1, "prefill-heavy"), "5:1": (5, 1, "input-heavy"),
              "1:1": (1, 1, "balanced"), "1:5": (1, 5, "decode-heavy")}
    result = {}
    for key, (input_ratio, output_ratio, name) in ratios.items():
        input_tokens = round(budget * input_ratio / (input_ratio + output_ratio))
        result[key] = Shape(name, key, input_tokens, budget - input_tokens)
    return result


class PromptFactory:
    FILLER = " benchmark"

    def __init__(self, client: VLLMClient, model: str):
        self.client = client
        self.model = model
        self._cache: dict[tuple[str, int], str] = {}

    def fit(self, prefix: str, target: int) -> str:
        key = (prefix, target)
        if key in self._cache:
            return self._cache[key]
        prefix_count = self.client.count_tokens(self.model, prefix)
        if prefix_count > target:
            raise BenchmarkError(f"prompt prefix has {prefix_count} tokens, exceeding target {target}")
        low, high = 0, max(1, (target - prefix_count) * 2 + 32)
        best = prefix
        while low <= high:
            middle = (low + high) // 2
            candidate = prefix + self.FILLER * middle
            count = self.client.count_tokens(self.model, candidate)
            if count == target:
                self._cache[key] = candidate
                return candidate
            if count < target:
                best, low = candidate, middle + 1
            else:
                high = middle - 1
        # Leading-space words are one token on the supported tokenizers. This
        # loop also verifies that assumption rather than relying on it.
        for _ in range(target - self.client.count_tokens(self.model, best) + 8):
            count = self.client.count_tokens(self.model, best)
            if count == target:
                self._cache[key] = best
                return best
            if count > target:
                break
            best += " x"
        raise BenchmarkError(f"could not construct an exact {target}-token prompt")

    @staticmethod
    def request_marker(seed: str) -> str:
        # A hash makes the very first token vary. "cat"/"dog" have identical
        # byte length and are separated by spaces, so reordering them preserves
        # the marker's token count while destroying the prefix hash chain.
        digest = hashlib.sha256(seed.encode()).digest()
        bits = "".join(f"{byte:08b}" for byte in digest)
        return " ".join("cat" if bit == "0" else "dog" for bit in bits) + "\n"

    def prompts(self, input_tokens: int, cache: str, count: int, test_id: str) -> list[str]:
        if cache not in {"cold", "mixed", "hot"}:
            raise BenchmarkError(f"unknown cache state: {cache}")
        shared_target = min(3000, round(input_tokens * 0.9)) if input_tokens <= 3825 else round(input_tokens * 0.9)
        shared = self.fit("Shared benchmark corpus.\n", shared_target) if cache != "cold" else ""
        result: list[str] = []
        templates: dict[bool, tuple[str, str]] = {}
        for use_shared in {cache == "hot", cache != "cold"}:
            template_marker = self.request_marker(f"{test_id}-template-{use_shared}")
            prefix = shared + "\nUnique user section: " + template_marker if use_shared else template_marker
            templates[use_shared] = (template_marker, self.fit(prefix, input_tokens))
        for index in range(count):
            use_shared = cache == "hot" or (cache == "mixed" and index % 2 == 0)
            template_marker, template = templates[use_shared]
            marker = self.request_marker(f"{test_id}-{index}")
            result.append(template.replace(template_marker, marker, 1))
        return result


def parse_cache_capacity(metrics: str) -> int | None:
    match = re.search(r'vllm:cache_config_info\{[^}]*block_size="(\d+)"[^}]*num_gpu_blocks="(\d+)"', metrics)
    if not match:
        return None
    return int(match.group(1)) * int(match.group(2))


def theoretical_concurrency(config: Config, client: VLLMClient) -> tuple[int, str]:
    if config.max_concurrency:
        return config.max_concurrency, "BENCH_MAX_CONCURRENCY"
    capacity = parse_cache_capacity(client.text_request("/metrics"))
    if not capacity:
        raise BenchmarkError(
            "could not auto-detect KV capacity from vllm:cache_config_info; set BENCH_MAX_CONCURRENCY"
        )
    concurrency = max(1, capacity // config.token_budget)
    if config.scheduler_max_seqs:
        concurrency = min(concurrency, config.scheduler_max_seqs)
    return concurrency, f"{capacity} KV tokens / {config.token_budget} token budget"


TESTS = (
    ("T01", "15:1", "baseline", "cold"),
    ("T02", "5:1", "baseline", "cold"),
    ("T03", "1:1", "baseline", "cold"),
    ("T04", "1:5", "baseline", "cold"),
    ("T05", "1:1", "moderate", "cold"),
    ("T06", "1:1", "saturation", "cold"),
    ("T07", "1:1", "overload", "cold"),
    ("T08", "15:1", "moderate", "hot"),
    ("T09", "15:1", "moderate", "mixed"),
    ("T10", "15:1", "moderate", "cold"),
)


def concurrency_levels(config: Config, theoretical: int) -> dict[str, int]:
    names = ("baseline", "moderate", "saturation", "overload")
    values = [1] + [max(1, math.ceil(theoretical * fraction)) for fraction in config.levels[1:]]
    return dict(zip(names, values))


def summarize(requests: list[dict[str, Any]], elapsed: float) -> dict[str, Any]:
    successes = [r for r in requests if not r["error"]]
    ttft = [r["ttft_seconds"] for r in successes if r["ttft_seconds"] is not None]
    itl = [r["mean_itl_seconds"] for r in successes if r["mean_itl_seconds"] is not None]
    return {
        "requests": len(requests),
        "successes": len(successes),
        "errors": len(requests) - len(successes),
        "elapsed_seconds": elapsed,
        "prompt_tokens_per_second": sum(r["prompt_tokens"] or 0 for r in successes) / elapsed,
        "generation_tokens_per_second": sum(r["output_tokens"] or 0 for r in successes) / elapsed,
        "p50_ttft_seconds": percentile(ttft, 0.50),
        "p95_ttft_seconds": percentile(ttft, 0.95),
        "p50_itl_seconds": percentile(itl, 0.50),
        "p95_itl_seconds": percentile(itl, 0.95),
    }


def run() -> int:
    config = Config.from_env()
    client = VLLMClient(config)
    model = client.discover_model()
    shapes = derive_shapes(config.token_budget)
    theoretical, source = theoretical_concurrency(config, client)
    levels = concurrency_levels(config, theoretical)
    factory = PromptFactory(client, model)
    prometheus = PrometheusClient(config.prometheus_url) if config.prometheus_url else None
    report: dict[str, Any] = {
        "schema_version": 1,
        "started_at": utc_now(),
        "endpoint": config.endpoint,
        "model": model,
        "token_budget": config.token_budget,
        "theoretical_concurrency": theoretical,
        "concurrency_source": source,
        "concurrency_levels": levels,
        "tests": [],
    }
    print(json.dumps({k: report[k] for k in report if k != "tests"}), flush=True)

    # Warm model/CUDA without contaminating measured prompt prefixes.
    warm_prompt = factory.fit("warmup-only unique prefix\n", 32)
    warm = client.stream_completion(model, warm_prompt, 8, "benchmark-warmup")
    if warm["error"]:
        raise BenchmarkError(f"warmup failed: {warm['error']}")

    for test_id, ratio, level, cache in TESTS:
        shape = shapes[ratio]
        concurrency = levels[level]
        prompts = factory.prompts(shape.input_tokens, cache, concurrency, test_id)
        if cache in {"hot", "mixed"}:
            # Prime the common prefix outside the measured window.
            prime = client.stream_completion(model, prompts[0], 1, f"{test_id}-prime")
            if prime["error"]:
                raise BenchmarkError(f"{test_id} cache prime failed: {prime['error']}")
        # Prometheus needs a quiet sample before each short test window. Two
        # scrape intervals put cache priming and prompt calibration outside the
        # analysis range; one interval afterward captures final counters.
        if prometheus and config.prometheus_settle_seconds:
            time.sleep(config.prometheus_settle_seconds * 2)
        started_at = utc_now()
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(
                client.stream_completion, model, prompt, shape.output_tokens, f"{test_id}-{index:05d}"
            ) for index, prompt in enumerate(prompts)]
            requests = [future.result() for future in futures]
        elapsed = time.monotonic() - started
        ended_at = utc_now()
        token_mismatches = [r["request_id"] for r in requests if not r["error"] and r["prompt_tokens"] != shape.input_tokens]
        result = {
            "id": test_id,
            "shape": dataclasses.asdict(shape),
            "cache": cache,
            "level": level,
            "concurrency": concurrency,
            "started_at": started_at,
            "ended_at": ended_at,
            "summary": summarize(requests, elapsed),
            "token_mismatches": token_mismatches,
            "requests": requests,
        }
        if prometheus:
            if config.prometheus_settle_seconds:
                time.sleep(config.prometheus_settle_seconds)
            query_at = utc_now()
            result["prometheus"] = prometheus.window_summary(
                query_at, elapsed + config.prometheus_settle_seconds * 2
            )
        report["tests"].append(result)
        print(json.dumps({k: v for k, v in result.items() if k != "requests"}), flush=True)
        Path(config.results_path).parent.mkdir(parents=True, exist_ok=True)
        Path(config.results_path).write_text(json.dumps(report, indent=2) + "\n")
        if token_mismatches:
            raise BenchmarkError(f"{test_id} produced prompts with unexpected token counts")
    report["ended_at"] = utc_now()
    Path(config.results_path).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"final_report": report}), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (BenchmarkError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "at": utc_now()}), file=sys.stderr, flush=True)
        raise SystemExit(2)
