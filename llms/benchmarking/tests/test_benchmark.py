import io
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import benchmark
from benchmark import (
    BenchmarkError, Config, PromptFactory, concurrency_levels, derive_shapes,
    effective_seconds, exposed_metric_names, parse_cache_capacity, percentile,
    build_plan, kv_tokens_warning, PrometheusClient, resolve_metrics, steady_window,
    summarize, sweep_plan, theoretical_concurrency, with_retry,
)


def make_config(**overrides):
    base = dict(
        endpoint="x", api_key=None, model=None, token_budget=4080, token_max=None,
        curve_shape="1:1", max_concurrency=None,
        scheduler_max_seqs=None, levels=(1, .5, 1, 1.25), sweep_levels=(), prometheus_url=None,
        metric_selector="", request_timeout=1, results_path="x", prometheus_settle_seconds=0,
        test_duration_seconds=120, ramp_seconds=15, min_requests_per_worker=2,
        test_max_seconds=900, prompt_salt="test-salt",
    )
    return Config(**{**base, **overrides})


class ShapeTests(unittest.TestCase):
    def test_compact_shapes(self):
        shapes = derive_shapes(4080)
        self.assertEqual((shapes["15:1"].input_tokens, shapes["15:1"].output_tokens), (3825, 255))
        self.assertEqual((shapes["5:1"].input_tokens, shapes["5:1"].output_tokens), (3400, 680))
        self.assertEqual((shapes["1:1"].input_tokens, shapes["1:1"].output_tokens), (2040, 2040))
        self.assertEqual((shapes["1:5"].input_tokens, shapes["1:5"].output_tokens), (680, 3400))

    def test_agentic_shapes(self):
        shapes = derive_shapes(50000)
        self.assertEqual((shapes["15:1"].input_tokens, shapes["15:1"].output_tokens), (46875, 3125))
        self.assertEqual((shapes["5:1"].input_tokens, shapes["5:1"].output_tokens), (41667, 8333))


class ConcurrencyTests(unittest.TestCase):
    METRICS = 'vllm:cache_config_info{block_size="16",engine="0",num_gpu_blocks="60798"} 1.0'

    def test_cache_capacity_metric(self):
        self.assertEqual(parse_cache_capacity(self.METRICS), 972768)

    def test_cache_capacity_ignores_label_order(self):
        reordered = 'vllm:cache_config_info{num_gpu_blocks="60798",block_size="16"} 1.0'
        self.assertEqual(parse_cache_capacity(reordered), 972768)

    def test_cache_capacity_absent_before_profiling(self):
        unprofiled = 'vllm:cache_config_info{block_size="16",num_gpu_blocks="None"} 1.0'
        self.assertIsNone(parse_cache_capacity(unprofiled))

    def test_rounds_up_and_keeps_baseline_one(self):
        self.assertEqual(concurrency_levels(make_config(), 31), {
            "baseline": 1, "moderate": 16, "saturation": 31, "overload": 39
        })

    def test_reports_kv_as_the_binding_constraint(self):
        value, detail = theoretical_concurrency(make_config(), self.METRICS)
        self.assertEqual(value, 238)
        self.assertEqual(detail["binding"], "kv_cache")

    def test_reports_scheduler_cap_as_the_binding_constraint(self):
        value, detail = theoretical_concurrency(make_config(scheduler_max_seqs=32), self.METRICS)
        self.assertEqual(value, 32)
        self.assertEqual(detail["binding"], "max_num_seqs")
        # The headroom ratio is what tells a reader KV pressure went untested.
        self.assertGreater(detail["headroom_ratio"], 7)

    def test_token_max_replaces_the_reported_kv_pool(self):
        config = make_config(token_max=861597)
        value, detail = theoretical_concurrency(config, self.METRICS)
        self.assertEqual(value, 211)
        self.assertEqual(detail["kv_cache_tokens"], 861597)
        self.assertEqual(detail["kv_cache_tokens_source"], "BENCH_TOKEN_MAX")
        self.assertEqual(detail["kv_cache_tokens_reported"], 972768)
        self.assertEqual(detail["binding"], "kv_cache")

    def test_token_max_scales_the_ceiling_with_context_length(self):
        config = make_config(token_max=1184878, token_budget=50000)
        self.assertEqual(theoretical_concurrency(config, self.METRICS)[0], 23)

    def test_warns_when_the_metric_disagrees_with_token_max(self):
        config = make_config(token_max=861597)
        _, detail = theoretical_concurrency(config, self.METRICS)
        self.assertIn("972768", kv_tokens_warning(config, detail))
        close = make_config(token_max=960000)
        self.assertIsNone(kv_tokens_warning(close, theoretical_concurrency(close, self.METRICS)[1]))

    def test_missing_kv_capacity_asks_for_token_max(self):
        with self.assertRaises(BenchmarkError) as raised:
            theoretical_concurrency(make_config(), "")
        self.assertIn("BENCH_TOKEN_MAX", str(raised.exception))

    def test_sweep_skips_levels_the_named_tests_already_cover(self):
        config = make_config(sweep_levels=(0.25, 0.5, 0.75))
        plan = sweep_plan(config, 32, covered={1, 16, 32, 40})
        self.assertEqual([(value, round(fraction, 2)) for _, value, fraction in plan],
                         [(8, 0.25), (24, 0.75)])


class PlanTests(unittest.TestCase):
    LEVELS = {"baseline": 1, "moderate": 12, "saturation": 23, "overload": 35}

    def plan(self, **overrides):
        config = make_config(sweep_levels=(0.25, 0.75), **overrides)
        return {row[0]: row for row in build_plan(config, self.LEVELS, 23)}

    def test_curve_defaults_to_the_balanced_shape(self):
        plan = self.plan()
        self.assertEqual([plan[t][1] for t in ("T05", "T06", "T07")], ["1:1"] * 3)
        self.assertEqual(plan["S01"][1], "1:1")

    def test_curve_shape_moves_the_curve_tests_and_sweeps(self):
        plan = self.plan(curve_shape="15:1")
        self.assertEqual([plan[t][1] for t in ("T05", "T06", "T07")], ["15:1"] * 3)
        self.assertEqual(plan["S01"][1], "15:1")

    def test_cache_tests_stay_on_15_1_whatever_the_curve_runs(self):
        for shape in ("1:1", "15:1", "1:5"):
            plan = self.plan(curve_shape=shape)
            self.assertEqual([plan[t][1] for t in ("T08", "T09", "T10")], ["15:1"] * 3)

    def test_curve_anchor_follows_the_curve_shape(self):
        on_curve = lambda plan: {t for t, row in plan.items() if row[5]}
        self.assertEqual(on_curve(self.plan()),
                         {"T03", "T05", "T06", "T07", "S01", "S02"})
        self.assertEqual(on_curve(self.plan(curve_shape="15:1")),
                         {"T01", "T05", "T06", "T07", "S01", "S02"})

    def test_cache_cold_test_is_never_on_the_curve(self):
        # T10 runs 15:1 cold at the moderate level, identical to T05 when the
        # curve is 15:1. Two points at one concurrency would read as a collapse.
        self.assertFalse(self.plan(curve_shape="15:1")["T10"][5])

    def test_shape_is_validated(self):
        os.environ.update(BENCH_VLLM_ENDPOINT="http://x", BENCH_CURVE_SHAPE="3:1")
        try:
            with self.assertRaises(BenchmarkError):
                Config.from_env()
        finally:
            os.environ.pop("BENCH_CURVE_SHAPE")


class WindowTests(unittest.TestCase):
    def test_window_ends_when_the_first_worker_stops(self):
        start, end, valid = steady_window([130.0, 142.0, 150.0], started=0.0, ramp=15.0)
        self.assertEqual((start, end, valid), (15.0, 130.0, True))

    def test_window_is_invalid_when_requests_outlast_the_test(self):
        start, end, valid = steady_window([9.0, 11.0], started=0.0, ramp=15.0)
        self.assertFalse(valid)
        self.assertEqual((start, end), (0.0, 11.0))

    def test_effective_seconds_ignores_the_idle_tail_of_a_long_window(self):
        # One 100s request counted inside a 185s window: the request spanned
        # 100s of it, and dividing by 185 would halve the reported throughput.
        requests = [{"e2e_seconds": 100.0, "worker": 0}]
        self.assertEqual(effective_seconds(requests, fallback=185.0), 100.0)

    def test_effective_seconds_averages_across_contributing_workers(self):
        requests = [
            {"e2e_seconds": 50.0, "worker": 0}, {"e2e_seconds": 50.0, "worker": 0},
            {"e2e_seconds": 100.0, "worker": 1},
        ]
        self.assertEqual(effective_seconds(requests, fallback=999.0), 100.0)

    def test_effective_seconds_falls_back_when_nothing_was_counted(self):
        self.assertEqual(effective_seconds([], fallback=42.0), 42.0)

    def test_summary_rates_use_the_window_not_the_request_count(self):
        requests = [
            {"error": None, "prompt_tokens": 100, "output_tokens": 50, "ttft_seconds": 0.2,
             "mean_itl_seconds": 0.01, "prefill_seconds": 0.2, "decode_seconds": 0.8,
             "e2e_seconds": 1.0},
            {"error": None, "prompt_tokens": 100, "output_tokens": 50, "ttft_seconds": 0.4,
             "mean_itl_seconds": 0.02, "prefill_seconds": 0.4, "decode_seconds": 0.6,
             "e2e_seconds": 1.0},
        ]
        summary = summarize(requests, window_seconds=10.0)
        self.assertEqual(summary["prompt_tokens_per_second"], 20.0)
        self.assertEqual(summary["generation_tokens_per_second"], 10.0)
        self.assertAlmostEqual(summary["prefill_share"], 0.3)


class MetricTests(unittest.TestCase):
    SAMPLE = (
        "# TYPE vllm:prompt_tokens_total counter\n"
        'vllm:prompt_tokens_total{model_name="L"} 5\n'
        "# TYPE vllm:gpu_prefix_cache_hits_total counter\n"
        "# TYPE vllm:time_to_first_token_seconds histogram\n"
        'vllm:time_to_first_token_seconds_bucket{le="0.1"} 3\n'
    )

    def test_exposed_names_cover_histogram_suffixes(self):
        names = exposed_metric_names(self.SAMPLE)
        self.assertIn("vllm:time_to_first_token_seconds", names)
        self.assertIn("vllm:prompt_tokens_total", names)

    def test_alias_resolution_prefers_the_name_the_build_exposes(self):
        resolved, missing = resolve_metrics(self.SAMPLE)
        self.assertEqual(resolved["prefix_cache_hits"], "vllm:gpu_prefix_cache_hits_total")
        self.assertIn("preemptions", missing)

    def test_selector_is_injected_into_every_query(self):
        resolved, _ = resolve_metrics(self.SAMPLE)
        client = PrometheusClient("http://p", 'model_name="L"', resolved)
        queries = client.build_queries("120s")
        self.assertTrue(all('model_name="L"' in query for query in queries.values()), queries)
        self.assertIn(
            'rate(vllm:time_to_first_token_seconds_bucket{model_name="L"}[120s])',
            queries["p95_ttft_seconds"],
        )

    def test_absent_metrics_produce_no_query_rather_than_a_null(self):
        resolved, _ = resolve_metrics(self.SAMPLE)
        self.assertNotIn("preemptions", PrometheusClient("http://p", "", resolved).build_queries("60s"))


class PromptTests(unittest.TestCase):
    def test_percentile(self):
        self.assertEqual(percentile([4, 1, 2, 3], .95), 4)
        self.assertIsNone(percentile([], .5))

    def test_salt_changes_prompts_between_runs(self):
        class FakeClient:
            def count_tokens(self, model, prompt):
                return len(prompt.split())

        first = PromptFactory(FakeClient(), "m", "run-a")
        second = PromptFactory(FakeClient(), "m", "run-b")
        # Same test id and index, different run: a cold test must not be able to
        # hit blocks the previous run left in the prefix cache.
        self.assertNotEqual(first.marker("T10-1"), second.marker("T10-1"))
        self.assertEqual(first.marker("T10-1"), PromptFactory(FakeClient(), "m", "run-a").marker("T10-1"))

    def test_markers_are_fixed_length_and_unique_at_the_start(self):
        first = PromptFactory.request_marker("T05-0")
        second = PromptFactory.request_marker("T05-1")
        self.assertEqual(len(first), len(second))
        self.assertNotEqual(first, second)
        self.assertNotEqual(first.split()[0], second.split()[0])

    def test_shared_corpus_is_salted_per_test(self):
        recorded = []

        class FakeClient:
            def count_tokens(self, model, prompt):
                return len(prompt.split())

        factory = PromptFactory(FakeClient(), "m", "salt")
        original_fit = factory.fit

        def spy(prefix, target):
            recorded.append(prefix)
            return original_fit(prefix, target)

        factory.fit = spy
        factory.build_templates(1200, "hot", "T08")
        factory.build_templates(1200, "hot", "T09")
        seeds = {prefix.splitlines()[0] for prefix in recorded
                 if prefix.startswith("Shared benchmark corpus")}
        # A shared corpus reused verbatim would leave T09 pre-warmed by T08.
        self.assertEqual(seeds, {"Shared benchmark corpus salt T08.",
                                 "Shared benchmark corpus salt T09."})


class RetryTest(unittest.TestCase):
    """The 50k agentic run died on one reset while building a prompt."""

    def setUp(self):
        self.backoff = benchmark.SETUP_RETRY_BACKOFF_SECONDS
        benchmark.SETUP_RETRY_BACKOFF_SECONDS = 0.0

    def tearDown(self):
        benchmark.SETUP_RETRY_BACKOFF_SECONDS = self.backoff

    def test_transient_transport_failure_recovers(self):
        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) < 3:
                raise BrokenPipeError(32, "Broken pipe")
            return "ok"

        self.assertEqual(with_retry("tokenize", flaky), "ok")
        self.assertEqual(len(attempts), 3)

    def test_exhausted_retries_become_benchmark_error(self):
        def always():
            raise ConnectionResetError(104, "reset")

        with self.assertRaises(BenchmarkError):
            with_retry("tokenize", always)

    def test_http_status_is_not_retried(self):
        attempts = []

        def not_found():
            attempts.append(1)
            raise urllib.error.HTTPError("u", 404, "Not Found", {}, io.BytesIO(b""))

        # count_tokens falls back to /v1/completions on 404, so a status has to
        # reach the caller unchanged and on the first try.
        with self.assertRaises(urllib.error.HTTPError):
            with_retry("tokenize", not_found)
        self.assertEqual(len(attempts), 1)

    def test_benchmark_error_is_not_swallowed(self):
        def boom():
            raise BenchmarkError("inner")

        with self.assertRaisesRegex(BenchmarkError, "inner"):
            with_retry("tokenize", boom)


if __name__ == "__main__":
    unittest.main()
