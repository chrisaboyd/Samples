#!/usr/bin/env python3
"""Deterministic vLLM workload runner for the T01-T10 benchmark suite.

Load is closed-loop: each test holds `concurrency` workers in flight, every
worker issuing a new request as soon as its previous one returns, for a fixed
duration. Statistics come from a steady window that excludes the ramp-up and the
drain, so a concurrency level measures sustained load rather than one burst.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import http.client
import json
import math
import os
import re
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

# Above this many client threads, CPython's GIL and urllib's blocking reads
# start adding to measured TTFT and the inflation reads as server saturation.
CLIENT_THREAD_WARNING = 64


class BenchmarkError(RuntimeError):
    pass


# Setup traffic (tokenize, /metrics, Prometheus) is retried on transport
# failures. A single reset while constructing a 46,875-token prompt otherwise
# discards a multi-hour run, which is how the 50k agentic run died. Measured
# completions are never retried: a retry would put a request in the steady
# window that the server had already started once.
SETUP_RETRY_ATTEMPTS = 4
SETUP_RETRY_BACKOFF_SECONDS = 1.0


def with_retry(description: str, operation: Callable[[], Any]) -> Any:
    for attempt in range(1, SETUP_RETRY_ATTEMPTS + 1):
        try:
            return operation()
        except urllib.error.HTTPError:
            # A status code is an answer, not a transport failure. Let the
            # caller turn it into a BenchmarkError with the response body.
            raise
        except (OSError, http.client.HTTPException) as exc:
            if attempt == SETUP_RETRY_ATTEMPTS:
                raise BenchmarkError(
                    f"{description} failed after {attempt} attempts: {exc}"
                ) from exc
            delay = SETUP_RETRY_BACKOFF_SECONDS * 2 ** (attempt - 1)
            print(json.dumps({"retry": description, "attempt": attempt,
                              "error": str(exc), "sleep_seconds": delay}),
                  file=sys.stderr, flush=True)
            time.sleep(delay)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)]


class Clock:
    """Maps monotonic timestamps onto wall-clock UTC for Prometheus queries."""

    def __init__(self) -> None:
        self.wall = datetime.now(timezone.utc)
        self.mono = time.monotonic()

    def iso(self, monotonic: float) -> str:
        moment = self.wall + timedelta(seconds=monotonic - self.mono)
        return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclasses.dataclass(frozen=True)
class Config:
    endpoint: str
    api_key: str | None
    model: str | None
    token_budget: int
    token_max: int | None
    curve_shape: str
    max_concurrency: int | None
    scheduler_max_seqs: int | None
    levels: tuple[float, float, float, float]
    sweep_levels: tuple[float, ...]
    prometheus_url: str | None
    metric_selector: str
    request_timeout: float
    results_path: str
    prometheus_settle_seconds: float
    test_duration_seconds: float
    ramp_seconds: float
    min_requests_per_worker: int
    test_max_seconds: float
    prompt_salt: str

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
                "for example 1,0.5,1.0,1.25. Use BENCH_SWEEP_LEVELS to add curve detail."
            )
        raw_sweep = os.getenv("BENCH_SWEEP_LEVELS", "0.25,0.75").strip()
        sweep = tuple(float(v.strip()) for v in raw_sweep.split(",")) if raw_sweep else ()
        if any(v <= 0 for v in sweep):
            raise BenchmarkError("BENCH_SWEEP_LEVELS values must be positive")
        curve_shape = os.getenv("BENCH_CURVE_SHAPE", "1:1").strip()
        if curve_shape not in SHAPE_RATIOS:
            raise BenchmarkError(
                f"BENCH_CURVE_SHAPE must be one of {', '.join(SHAPE_RATIOS)}"
            )
        raw_token_max = os.getenv("BENCH_TOKEN_MAX")
        token_max = int(raw_token_max) if raw_token_max else None
        if token_max is not None and token_max < budget:
            raise BenchmarkError(
                "BENCH_TOKEN_MAX must be at least BENCH_TOKEN_BUDGET; a KV pool smaller "
                "than one session cannot hold even the baseline test"
            )
        max_concurrency = os.getenv("BENCH_MAX_CONCURRENCY")
        scheduler_max = os.getenv("BENCH_SCHEDULER_MAX_SEQS")
        duration = float(os.getenv("BENCH_TEST_DURATION_SECONDS", "120"))
        ramp = float(os.getenv("BENCH_RAMP_SECONDS", "15"))
        if ramp >= duration:
            raise BenchmarkError("BENCH_RAMP_SECONDS must be smaller than BENCH_TEST_DURATION_SECONDS")
        return cls(
            endpoint=endpoint,
            api_key=os.getenv("BENCH_API_KEY"),
            model=os.getenv("BENCH_MODEL"),
            token_budget=budget,
            token_max=token_max,
            curve_shape=curve_shape,
            max_concurrency=int(max_concurrency) if max_concurrency else None,
            scheduler_max_seqs=int(scheduler_max) if scheduler_max else None,
            levels=raw_levels,  # type: ignore[arg-type]
            sweep_levels=sweep,
            prometheus_url=os.getenv("BENCH_PROMETHEUS_URL", "").rstrip("/") or None,
            metric_selector=os.getenv("BENCH_METRIC_SELECTOR", "").strip().strip("{}"),
            request_timeout=float(os.getenv("BENCH_REQUEST_TIMEOUT", "7200")),
            results_path=os.getenv("BENCH_RESULTS_PATH", "/results/results.json"),
            prometheus_settle_seconds=float(os.getenv("BENCH_PROMETHEUS_SETTLE_SECONDS", "15")),
            test_duration_seconds=duration,
            ramp_seconds=ramp,
            min_requests_per_worker=int(os.getenv("BENCH_MIN_REQUESTS_PER_WORKER", "2")),
            test_max_seconds=float(os.getenv("BENCH_TEST_MAX_SECONDS", "900")),
            # Markers are a hash of their seed, so without a per-run salt two
            # consecutive Jobs send byte-identical prompts and a cold-cache test
            # can score hits on blocks the previous run left resident.
            prompt_salt=os.getenv("BENCH_PROMPT_SALT") or utc_now(),
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

        # Rebuilt per attempt: urllib mutates the Request while sending it.
        def send() -> Any:
            request = urllib.request.Request(
                f"{self.config.endpoint}{path}", data=body, headers=self._headers(), method=method
            )
            with urllib.request.urlopen(request, timeout=self.config.request_timeout) as response:
                return json.load(response)

        try:
            return with_retry(f"{method} {path}", send)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise BenchmarkError(f"{method} {path} failed ({exc.code}): {detail}") from exc

    def text_request(self, path: str) -> str:
        def send() -> str:
            request = urllib.request.Request(
                f"{self.config.endpoint}{path}", headers=self._headers()
            )
            with urllib.request.urlopen(request, timeout=self.config.request_timeout) as response:
                return response.read().decode()

        return with_retry(f"GET {path}", send)

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
            ended = time.monotonic()
            return {
                "request_id": request_id, "error": str(exc),
                "started_monotonic": started, "ended_monotonic": ended,
                "prompt_tokens": None, "output_tokens": None, "ttft_seconds": None,
                "mean_itl_seconds": None, "prefill_seconds": None, "decode_seconds": None,
                "e2e_seconds": ended - started,
            }
        ended = time.monotonic()
        ttft = token_times[0] - started if token_times else None
        e2e = ended - started
        # vLLM batches several tokens into one SSE chunk whenever the client
        # falls behind, so averaging the gaps between chunks overstates ITL by
        # the batch factor. Dividing the decode span by the tokenizer's own count
        # gives time per output token regardless of how the stream was framed.
        completion_tokens = usage.get("completion_tokens")
        decode_span = token_times[-1] - token_times[0] if len(token_times) > 1 else None
        itl = (
            decode_span / (completion_tokens - 1)
            if decode_span is not None and (completion_tokens or 0) > 1 else None
        )
        return {
            "request_id": request_id,
            "prompt_tokens": usage.get("prompt_tokens"),
            "output_tokens": completion_tokens,
            "ttft_seconds": ttft,
            "mean_itl_seconds": itl,
            "stream_chunks": len(token_times),
            # Client-visible proxy for the server's prefill/decode split. The
            # authoritative split comes from vLLM's request_prefill_time_seconds
            # and request_decode_time_seconds when Prometheus is available.
            "prefill_seconds": ttft,
            "decode_seconds": e2e - ttft if ttft is not None else None,
            "e2e_seconds": e2e,
            "started_monotonic": started,
            "ended_monotonic": ended,
            "error": None,
        }


# Metric families whose names differ across vLLM builds. The first name present
# in /metrics wins; a missing family is reported rather than silently nulled.
METRIC_ALIASES: dict[str, tuple[str, ...]] = {
    "prompt_tokens": ("vllm:prompt_tokens_total", "vllm:prompt_tokens"),
    "generation_tokens": ("vllm:generation_tokens_total", "vllm:generation_tokens"),
    "requests_running": ("vllm:num_requests_running",),
    "requests_waiting": ("vllm:num_requests_waiting",),
    "kv_cache_usage": ("vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc"),
    "preemptions": ("vllm:num_preemptions_total", "vllm:num_preemptions"),
    "prefix_cache_queries": ("vllm:prefix_cache_queries_total", "vllm:gpu_prefix_cache_queries_total"),
    "prefix_cache_hits": ("vllm:prefix_cache_hits_total", "vllm:gpu_prefix_cache_hits_total"),
    "prompt_tokens_cached": ("vllm:prompt_tokens_cached_total",),
    "prefill_kv_computed_tokens": ("vllm:request_prefill_kv_computed_tokens",),
    "ttft": ("vllm:time_to_first_token_seconds",),
    "itl": ("vllm:inter_token_latency_seconds",),
    "queue_time": ("vllm:request_queue_time_seconds",),
    "e2e_latency": ("vllm:e2e_request_latency_seconds",),
    "prefill_time": ("vllm:request_prefill_time_seconds",),
    "decode_time": ("vllm:request_decode_time_seconds",),
}


def exposed_metric_names(metrics_text: str) -> set[str]:
    names = set(re.findall(r"^# TYPE (\S+)", metrics_text, flags=re.MULTILINE))
    names.update(re.findall(r"^([a-zA-Z_:][\w:]*)[{ ]", metrics_text, flags=re.MULTILINE))
    return {re.sub(r"_(bucket|sum|count)$", "", name) for name in names} | names


def resolve_metrics(metrics_text: str) -> tuple[dict[str, str], list[str]]:
    exposed = exposed_metric_names(metrics_text)
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for key, candidates in METRIC_ALIASES.items():
        match = next((name for name in candidates if name in exposed), None)
        if match:
            resolved[key] = match
        else:
            missing.append(key)
    return resolved, missing


class PrometheusClient:
    def __init__(self, base_url: str, selector: str, metrics: dict[str, str]):
        self.base_url = base_url
        self.selector = selector
        self.metrics = metrics

    def series(self, key: str, suffix: str = "") -> str | None:
        name = self.metrics.get(key)
        if not name:
            return None
        return f"{name}{suffix}{{{self.selector}}}" if self.selector else f"{name}{suffix}"

    def query(self, promql: str, at: str) -> float | None:
        query = urllib.parse.urlencode({"query": promql, "time": at})

        def send() -> Any:
            with urllib.request.urlopen(
                f"{self.base_url}/api/v1/query?{query}", timeout=60
            ) as response:
                return json.load(response)

        payload = with_retry("Prometheus query", send)
        if payload.get("status") != "success":
            raise BenchmarkError(f"Prometheus query failed: {payload}")
        values = payload["data"].get("result", [])
        if not values:
            return None
        return sum(float(item["value"][1]) for item in values)

    def build_queries(self, window: str) -> dict[str, str]:
        """PromQL for the steady window, keyed by output field."""
        def histogram(key: str) -> str | None:
            bucket = self.series(key, "_bucket")
            return f"histogram_quantile(0.95, sum by (le) (rate({bucket}[{window}])))" if bucket else None

        def counter(key: str, function: str = "increase") -> str | None:
            series = self.series(key)
            return f"sum({function}({series}[{window}]))" if series else None

        def histogram_total(key: str) -> str | None:
            series = self.series(key, "_sum")
            return f"sum(increase({series}[{window}]))" if series else None

        def gauge(key: str) -> str | None:
            series = self.series(key)
            return f"max(max_over_time({series}[{window}]))" if series else None

        def mean(key: str) -> str | None:
            total, count = self.series(key, "_sum"), self.series(key, "_count")
            if not total:
                return None
            return (f"sum(increase({total}[{window}])) / "
                    f"clamp_min(sum(increase({count}[{window}])), 1)")

        candidates = {
            "prompt_tokens_per_second": counter("prompt_tokens", "rate"),
            "generation_tokens_per_second": counter("generation_tokens", "rate"),
            "max_requests_running": gauge("requests_running"),
            "mean_requests_running": (
                f"max(avg_over_time({self.series('requests_running')}[{window}]))"
                if self.series("requests_running") else None
            ),
            "max_requests_waiting": gauge("requests_waiting"),
            "mean_requests_waiting": (
                f"max(avg_over_time({self.series('requests_waiting')}[{window}]))"
                if self.series("requests_waiting") else None
            ),
            "max_kv_cache_usage": gauge("kv_cache_usage"),
            "mean_kv_cache_usage": (
                f"max(avg_over_time({self.series('kv_cache_usage')}[{window}]))"
                if self.series("kv_cache_usage") else None
            ),
            "preemptions": counter("preemptions"),
            "prefix_cache_queries": counter("prefix_cache_queries"),
            "prefix_cache_hits": counter("prefix_cache_hits"),
            "prompt_tokens_cached": counter("prompt_tokens_cached"),
            "prefill_kv_computed_tokens": histogram_total("prefill_kv_computed_tokens"),
            "p95_ttft_seconds": histogram("ttft"),
            "p95_itl_seconds": histogram("itl"),
            "p95_queue_seconds": histogram("queue_time"),
            "p95_e2e_seconds": histogram("e2e_latency"),
            "mean_queue_seconds": mean("queue_time"),
            "mean_prefill_seconds": mean("prefill_time"),
            "mean_decode_seconds": mean("decode_time"),
        }
        return {name: query for name, query in candidates.items() if query}

    def window_summary(self, ended_at: str, window_seconds: float) -> dict[str, float | None]:
        window = f"{max(1, math.ceil(window_seconds))}s"
        result: dict[str, float | None] = {}
        for name, query in self.build_queries(window).items():
            try:
                result[name] = self.query(query, ended_at)
            except (OSError, ValueError, BenchmarkError) as exc:
                print(json.dumps({"warning": f"Prometheus {name}: {exc}"}), file=sys.stderr, flush=True)
                result[name] = None
        queries_count = result.get("prefix_cache_queries")
        hits_count = result.get("prefix_cache_hits")
        result["prefix_cache_hit_ratio"] = (
            hits_count / queries_count if queries_count else None
        ) if None not in (queries_count, hits_count) else None
        # PRD section 3 defines the hit ratio over cached tokens. On observed
        # builds prompt_tokens_cached/prefix_cache_queries reproduces the
        # designed cache states exactly while prefix_cache_hits_total does not,
        # so the cached-token ratio is the one to trust.
        cached = result.get("prompt_tokens_cached")
        result["cached_token_ratio"] = (
            cached / queries_count if queries_count else None
        ) if None not in (queries_count, cached) else None
        prefill = result.get("mean_prefill_seconds")
        decode = result.get("mean_decode_seconds")
        result["prefill_share"] = (
            prefill / (prefill + decode) if (prefill or 0) + (decode or 0) > 0 else None
        ) if None not in (prefill, decode) else None
        return result


@dataclasses.dataclass(frozen=True)
class Shape:
    name: str
    ratio: str
    input_tokens: int
    output_tokens: int


SHAPE_RATIOS = {"15:1": (15, 1, "prefill-heavy"), "5:1": (5, 1, "input-heavy"),
                "1:1": (1, 1, "balanced"), "1:5": (1, 5, "decode-heavy")}


def derive_shapes(budget: int) -> dict[str, Shape]:
    result = {}
    for key, (input_ratio, output_ratio, name) in SHAPE_RATIOS.items():
        input_tokens = round(budget * input_ratio / (input_ratio + output_ratio))
        result[key] = Shape(name, key, input_tokens, budget - input_tokens)
    return result


class PromptFactory:
    FILLER = " benchmark"
    HEADER = "\nUnique user section: "
    HEADER_TOKENS = 8  # generous allowance for the header plus fitting slack

    def __init__(self, client: VLLMClient, model: str, salt: str = ""):
        self.client = client
        self.model = model
        self.salt = salt
        self._fitted: dict[tuple[str, int], str] = {}
        self._templates: dict[tuple[str, str], dict[bool, tuple[str, str]]] = {}
        self._marker_tokens: int | None = None

    def marker_tokens(self) -> int:
        if self._marker_tokens is None:
            self._marker_tokens = self.client.count_tokens(self.model, self.marker("probe"))
        return self._marker_tokens

    def fit(self, prefix: str, target: int) -> str:
        key = (prefix, target)
        if key in self._fitted:
            return self._fitted[key]
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
                self._fitted[key] = candidate
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
                self._fitted[key] = best
                return best
            if count > target:
                break
            best += " x"
        raise BenchmarkError(f"could not construct an exact {target}-token prompt")

    def marker(self, seed: str) -> str:
        return self.request_marker(f"{self.salt}|{seed}")

    @staticmethod
    def request_marker(seed: str) -> str:
        # A hash makes the very first token vary. "cat"/"dog" have identical
        # byte length and are separated by spaces, so reordering them preserves
        # the marker's token count while destroying the prefix hash chain.
        digest = hashlib.sha256(seed.encode()).digest()
        bits = "".join(f"{byte:08b}" for byte in digest)
        return " ".join("cat" if bit == "0" else "dog" for bit in bits) + "\n"

    def build_templates(self, input_tokens: int, cache: str, test_id: str) -> None:
        """Construct the fixed-length templates a test reuses for every request."""
        if cache not in {"cold", "mixed", "hot"}:
            raise BenchmarkError(f"unknown cache state: {cache}")
        key = (test_id, cache)
        if key in self._templates:
            return
        shared_target = (
            min(3000, round(input_tokens * 0.9)) if input_tokens <= 3825 else round(input_tokens * 0.9)
        )
        # The unique marker and its header sit after the shared corpus, so the
        # corpus cannot claim the whole prompt. Small budgets hit this first.
        headroom = input_tokens - self.marker_tokens() - self.HEADER_TOKENS
        if cache != "cold" and headroom < 1:
            raise BenchmarkError(
                f"{input_tokens}-token input is too small to hold a unique marker; "
                "raise BENCH_TOKEN_BUDGET"
            )
        shared_target = min(shared_target, headroom)
        # Salting the corpus per test keeps a cache-hot test from pre-warming the
        # shared half of a later mixed test.
        shared = (
            self.fit(f"Shared benchmark corpus {self.salt} {test_id}.\n", shared_target)
            if cache != "cold" else ""
        )
        templates: dict[bool, tuple[str, str]] = {}
        for use_shared in {cache == "hot", cache != "cold"}:
            template_marker = self.marker(f"{test_id}-template-{use_shared}")
            prefix = shared + self.HEADER + template_marker if use_shared else template_marker
            templates[use_shared] = (template_marker, self.fit(prefix, input_tokens))
        self._templates[key] = templates

    def prompt(self, cache: str, test_id: str, index: int) -> str:
        templates = self._templates[(test_id, cache)]
        use_shared = cache == "hot" or (cache == "mixed" and index % 2 == 0)
        template_marker, template = templates[use_shared]
        return template.replace(template_marker, self.marker(f"{test_id}-{index}"), 1)


def parse_cache_capacity(metrics: str) -> int | None:
    """KV tokens as vLLM reports them: block_size x num_gpu_blocks.

    Labels are read by name because their order in the info metric follows the
    CacheConfig field names and changes between vLLM releases. num_gpu_blocks is
    the string "None" before the engine finishes profiling, which reads as absent.
    """
    match = re.search(r"^vllm:cache_config_info\{([^}]*)\}", metrics, flags=re.MULTILINE)
    if not match:
        return None
    labels = dict(re.findall(r'(\w+)="([^"]*)"', match.group(1)))
    try:
        return int(labels["block_size"]) * int(labels["num_gpu_blocks"])
    except (KeyError, ValueError):
        return None


# vllm:cache_config_info multiplies block_size by num_gpu_blocks, which on
# boyd-ref reads 10-13% above the "GPU KV cache size: N tokens" the engine logs
# and schedules against. Past this gap, pin the real number with BENCH_TOKEN_MAX.
KV_TOKENS_DIVERGENCE_RATIO = 0.05


def kv_token_pool(config: Config, metrics_text: str) -> tuple[int | None, dict[str, Any]]:
    """The KV token pool concurrency divides, and where the number came from."""
    reported = parse_cache_capacity(metrics_text)
    pool = config.token_max or reported
    return pool, {
        "kv_cache_tokens": pool,
        "kv_cache_tokens_source": (
            "BENCH_TOKEN_MAX" if config.token_max
            else "vllm:cache_config_info" if reported else None
        ),
        "kv_cache_tokens_reported": reported,
    }


def kv_tokens_warning(config: Config, detail: dict[str, Any]) -> str | None:
    reported = detail.get("kv_cache_tokens_reported")
    if not (config.token_max and reported):
        return None
    drift = abs(reported - config.token_max) / config.token_max
    if drift <= KV_TOKENS_DIVERGENCE_RATIO:
        return None
    return (
        f"BENCH_TOKEN_MAX is {config.token_max} but vllm:cache_config_info reports "
        f"{reported} ({drift:.0%} apart). Check BENCH_TOKEN_MAX against the engine's "
        "'GPU KV cache size' startup log line before trusting the ceiling"
    )


def theoretical_concurrency(config: Config, metrics_text: str) -> tuple[int, dict[str, Any]]:
    """Concurrency ceiling plus the constraint that actually binds it.

    The ceiling is one division: KV token pool over per-session token budget. So
    a level is a statement about tokens resident in KV, not about a user count
    someone picked, and the same fractions mean the same pressure at any context
    length.

    Reporting the binding constraint matters: on a cluster with a large KV cache
    and a small max_num_seqs, a saturation test demonstrates scheduler queueing
    and says nothing at all about KV pressure.
    """
    kv_tokens, detail = kv_token_pool(config, metrics_text)
    kv_limit = max(1, kv_tokens // config.token_budget) if kv_tokens else None
    detail.update({
        "kv_limit": kv_limit,
        "max_num_seqs": config.scheduler_max_seqs,
        "override": config.max_concurrency,
    })
    if config.max_concurrency:
        detail["binding"] = "BENCH_MAX_CONCURRENCY"
        detail["source"] = f"operator override of {config.max_concurrency}"
        return config.max_concurrency, detail
    if not kv_limit:
        raise BenchmarkError(
            "could not read KV capacity from vllm:cache_config_info; set BENCH_TOKEN_MAX "
            "to the engine's 'GPU KV cache size' in tokens"
        )
    concurrency, binding = kv_limit, "kv_cache"
    if config.scheduler_max_seqs and config.scheduler_max_seqs < kv_limit:
        concurrency, binding = config.scheduler_max_seqs, "max_num_seqs"
    detail["binding"] = binding
    detail["source"] = f"{kv_tokens} KV tokens / {config.token_budget} token budget"
    detail["headroom_ratio"] = round(kv_limit / concurrency, 2)
    return concurrency, detail


# T05-T07 and the sweeps trace the concurrency curve, so they all run whatever
# BENCH_CURVE_SHAPE names. T08-T10 exist to compare cache states against each
# other and stay on 15:1 whatever the curve is doing.
CURVE_TESTS = ("T05", "T06", "T07")
CACHE_TESTS = ("T08", "T09", "T10")

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


def build_plan(config: Config, levels: dict[str, int],
               theoretical: int) -> list[tuple[str, str, int, str, str, bool]]:
    """Every test to run, with the ratio it uses and whether it is on the curve.

    Curve membership is recorded per test rather than inferred later from the
    ratio. When BENCH_CURVE_SHAPE is 15:1 the curve tests and the cache-cold
    test T10 run identical workloads, and an analyzer that selects by ratio
    would read T10 as a second, contradictory measurement at that concurrency.
    """
    plan = []
    for test_id, ratio, level, cache in TESTS:
        if test_id in CURVE_TESTS:
            ratio = config.curve_shape
        on_curve = (
            test_id in CURVE_TESTS
            or (test_id not in CACHE_TESTS and level == "baseline"
                and ratio == config.curve_shape and cache == "cold")
        )
        plan.append((test_id, ratio, levels[level], cache, level, on_curve))
    for sweep_id, value, fraction in sweep_plan(config, theoretical, set(levels.values())):
        plan.append((sweep_id, config.curve_shape, value, "cold", f"sweep-{fraction:g}", True))
    return plan


def concurrency_levels(config: Config, theoretical: int) -> dict[str, int]:
    names = ("baseline", "moderate", "saturation", "overload")
    values = [1] + [max(1, math.ceil(theoretical * fraction)) for fraction in config.levels[1:]]
    return dict(zip(names, values))


def sweep_plan(config: Config, theoretical: int, covered: set[int]) -> list[tuple[str, int, float]]:
    """Extra 1:1 points so the concurrency curve has enough samples to show a knee."""
    plan: list[tuple[str, int, float]] = []
    seen = set(covered)
    for fraction in sorted(config.sweep_levels):
        value = max(1, math.ceil(theoretical * fraction))
        if value in seen:
            continue
        seen.add(value)
        plan.append((f"S{len(plan) + 1:02d}", value, fraction))
    return plan


def summarize(requests: list[dict[str, Any]], window_seconds: float) -> dict[str, Any]:
    successes = [r for r in requests if not r["error"]]
    pick = lambda field: [r[field] for r in successes if r.get(field) is not None]
    ttft, itl = pick("ttft_seconds"), pick("mean_itl_seconds")
    prefill, decode = pick("prefill_seconds"), pick("decode_seconds")
    prompt_tokens = sum(r["prompt_tokens"] or 0 for r in successes)
    output_tokens = sum(r["output_tokens"] or 0 for r in successes)
    mean_prefill = statistics.fmean(prefill) if prefill else None
    mean_decode = statistics.fmean(decode) if decode else None
    return {
        "requests": len(requests),
        "successes": len(successes),
        "errors": len(requests) - len(successes),
        "window_seconds": window_seconds,
        "requests_per_second": len(successes) / window_seconds if window_seconds > 0 else None,
        "prompt_tokens_per_second": prompt_tokens / window_seconds if window_seconds > 0 else None,
        "generation_tokens_per_second": output_tokens / window_seconds if window_seconds > 0 else None,
        "p50_ttft_seconds": percentile(ttft, 0.50),
        "p95_ttft_seconds": percentile(ttft, 0.95),
        "p50_itl_seconds": percentile(itl, 0.50),
        "p95_itl_seconds": percentile(itl, 0.95),
        "p95_e2e_seconds": percentile(pick("e2e_seconds"), 0.95),
        "mean_prefill_seconds": mean_prefill,
        "mean_decode_seconds": mean_decode,
        "prefill_share": (
            mean_prefill / (mean_prefill + mean_decode)
            if None not in (mean_prefill, mean_decode) and (mean_prefill + mean_decode) > 0 else None
        ),
    }


def steady_window(worker_last_end: list[float], started: float, ramp: float) -> tuple[float, float, bool]:
    """Interval during which every worker was continuously in flight.

    A worker loops without gaps, so it is busy from the test start until its
    final request returns. Every worker is therefore in flight up to the earliest
    of those endings, and that interval minus the ramp is the only stretch where
    offered concurrency actually equalled the configured level.
    """
    if not worker_last_end:
        return started, started, False
    window_start, window_end = started + ramp, min(worker_last_end)
    if window_end <= window_start:
        return started, max(worker_last_end), False
    return window_start, window_end, True


def effective_seconds(requests: list[dict[str, Any]], fallback: float) -> float:
    """Wall time the counted requests actually cover.

    Dividing tokens by the raw window overstates nothing when requests are short,
    but a decode-heavy shape can run one request across most of the window, and
    the request that straddles the boundary is excluded. Workers never idle, so
    their combined busy time divided by the number of workers that contributed is
    the interval those requests really spanned.
    """
    busy = sum(r["e2e_seconds"] for r in requests if r.get("e2e_seconds"))
    workers = len({r["worker"] for r in requests if "worker" in r})
    return busy / workers if busy and workers else fallback


def run_test(
    client: VLLMClient, factory: PromptFactory, config: Config, model: str,
    test_id: str, shape: Shape, cache: str, concurrency: int,
) -> dict[str, Any]:
    factory.build_templates(shape.input_tokens, cache, test_id)
    if cache in {"hot", "mixed"}:
        # Prime the common prefix outside the measured window.
        prime = client.stream_completion(model, factory.prompt(cache, test_id, 0), 1, f"{test_id}-prime")
        if prime["error"]:
            raise BenchmarkError(f"{test_id} cache prime failed: {prime['error']}")

    clock = Clock()
    started = time.monotonic()
    deadline = started + config.test_duration_seconds
    hard_deadline = started + config.test_max_seconds
    records: list[dict[str, Any]] = []
    worker_last_end: list[float] = []
    lock = threading.Lock()
    sequence = iter(range(1, 10_000_000))

    def worker(worker_id: int) -> float:
        completed, last_end = 0, started
        while True:
            now = time.monotonic()
            if now >= hard_deadline:
                break
            if now >= deadline and completed >= config.min_requests_per_worker:
                break
            with lock:
                index = next(sequence)
            prompt = factory.prompt(cache, test_id, index)
            result = client.stream_completion(
                model, prompt, shape.output_tokens, f"{test_id}-{index:06d}"
            )
            result["worker"] = worker_id
            with lock:
                records.append(result)
            completed += 1
            last_end = result["ended_monotonic"]
        return last_end

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        worker_last_end = [future.result() for future in
                           [executor.submit(worker, index) for index in range(concurrency)]]

    window_start, window_end, valid = steady_window(worker_last_end, started, config.ramp_seconds)
    in_window = [
        r for r in records
        if r["started_monotonic"] >= window_start and r["ended_monotonic"] <= window_end
    ] if valid else []
    if not in_window:
        # Requests longer than the test window leave nothing inside the steady
        # interval. Fall back to the whole test and flag the run as unsteady.
        in_window, valid = records, False
        window_start, window_end = started, max(worker_last_end or [started])
    window_seconds = max(window_end - window_start, 1e-6)
    throughput_seconds = effective_seconds(in_window, window_seconds)
    mismatches = [
        r["request_id"] for r in in_window if not r["error"] and r["prompt_tokens"] != shape.input_tokens
    ]
    return {
        "id": test_id,
        "shape": dataclasses.asdict(shape),
        "cache": cache,
        "concurrency": concurrency,
        "started_at": clock.iso(started),
        "ended_at": clock.iso(max(worker_last_end or [started])),
        "steady_started_at": clock.iso(window_start),
        "steady_ended_at": clock.iso(window_end),
        "steady_window_valid": valid,
        "steady_window_seconds": window_seconds,
        "throughput_seconds": throughput_seconds,
        "total_requests": len(records),
        "summary": summarize(in_window, throughput_seconds),
        "token_mismatches": mismatches,
        "requests": in_window,
    }


def run() -> int:
    config = Config.from_env()
    client = VLLMClient(config)
    model = client.discover_model()
    shapes = derive_shapes(config.token_budget)
    metrics_text = client.text_request("/metrics")
    resolved, missing = resolve_metrics(metrics_text)
    theoretical, concurrency_detail = theoretical_concurrency(config, metrics_text)
    levels = concurrency_levels(config, theoretical)
    factory = PromptFactory(client, model, config.prompt_salt)
    prometheus = (
        PrometheusClient(config.prometheus_url, config.metric_selector, resolved)
        if config.prometheus_url else None
    )
    if prometheus and not config.metric_selector:
        print(json.dumps({"warning": (
            "BENCH_METRIC_SELECTOR is unset; Prometheus queries will sum every vLLM "
            "target in the cluster and unrelated traffic will contaminate results"
        )}), file=sys.stderr, flush=True)
    if missing:
        print(json.dumps({"warning": f"metrics absent from /metrics: {', '.join(missing)}"}),
              file=sys.stderr, flush=True)
    drift = kv_tokens_warning(config, concurrency_detail)
    if drift:
        print(json.dumps({"warning": drift}), file=sys.stderr, flush=True)

    plan = build_plan(config, levels, theoretical)
    if max(item[2] for item in plan) > CLIENT_THREAD_WARNING:
        print(json.dumps({"warning": (
            f"peak concurrency exceeds {CLIENT_THREAD_WARNING} client threads; measured TTFT "
            "may include client-side scheduling delay, so run multiple Job replicas instead"
        )}), file=sys.stderr, flush=True)

    report: dict[str, Any] = {
        "schema_version": 2,
        "started_at": utc_now(),
        "endpoint": config.endpoint,
        "model": model,
        "token_budget": config.token_budget,
        "curve_shape": config.curve_shape,
        "kv_cache_tokens": concurrency_detail["kv_cache_tokens"],
        "theoretical_concurrency": theoretical,
        "concurrency_constraint": concurrency_detail,
        "concurrency_levels": levels,
        "metric_selector": config.metric_selector or None,
        "metrics_missing": missing,
        "prompt_salt": config.prompt_salt,
        "test_duration_seconds": config.test_duration_seconds,
        "ramp_seconds": config.ramp_seconds,
        "tests": [],
    }
    print(json.dumps({k: report[k] for k in report if k != "tests"}), flush=True)

    # Warm model/CUDA without contaminating measured prompt prefixes.
    warm_prompt = factory.fit("warmup-only unique prefix\n", 32)
    warm = client.stream_completion(model, warm_prompt, 8, "benchmark-warmup")
    if warm["error"]:
        raise BenchmarkError(f"warmup failed: {warm['error']}")

    for test_id, ratio, concurrency, cache, level, on_curve in plan:
        shape = shapes[ratio]
        result = run_test(client, factory, config, model, test_id, shape, cache, concurrency)
        result["level"] = level
        result["curve"] = on_curve
        if prometheus:
            # One scrape has to land after the steady window closes before the
            # counters covering it are queryable.
            time.sleep(config.prometheus_settle_seconds * 2)
            result["prometheus"] = prometheus.window_summary(
                result["steady_ended_at"], result["steady_window_seconds"]
            )
        report["tests"].append(result)
        print(json.dumps({k: v for k, v in result.items() if k != "requests"}), flush=True)
        Path(config.results_path).parent.mkdir(parents=True, exist_ok=True)
        Path(config.results_path).write_text(json.dumps(report, indent=2) + "\n")
        if result["summary"]["successes"] == 0:
            raise BenchmarkError(f"{test_id} completed no successful requests")
        if result["token_mismatches"]:
            raise BenchmarkError(f"{test_id} produced prompts with unexpected token counts")
    report["ended_at"] = utc_now()
    Path(config.results_path).write_text(json.dumps(report, indent=2) + "\n")
    # Per-request detail stays in the results file; stdout carries the summary so
    # kubectl logs remain usable after a long run.
    compact = {**report, "tests": [{k: v for k, v in test.items() if k != "requests"}
                                   for test in report["tests"]]}
    print(json.dumps({"final_report": compact}), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (BenchmarkError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "at": utc_now()}), file=sys.stderr, flush=True)
        raise SystemExit(2)
