import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from benchmark import Config, PromptFactory, concurrency_levels, derive_shapes, parse_cache_capacity, percentile


class BenchmarkTests(unittest.TestCase):
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

    def test_cache_capacity_metric(self):
        metric = 'vllm:cache_config_info{block_size="16",engine="0",num_gpu_blocks="60798"} 1.0'
        self.assertEqual(parse_cache_capacity(metric), 972768)

    def test_concurrency_rounds_up_and_keeps_baseline_one(self):
        config = Config("x", None, None, 4080, None, None, (1, .5, 1, 1.25), None, 1, "x", 0)
        self.assertEqual(concurrency_levels(config, 31), {
            "baseline": 1, "moderate": 16, "saturation": 31, "overload": 39
        })

    def test_percentile(self):
        self.assertEqual(percentile([4, 1, 2, 3], .95), 4)
        self.assertIsNone(percentile([], .5))

    def test_markers_are_fixed_length_and_unique_at_the_start(self):
        first = PromptFactory.request_marker("T05-0")
        second = PromptFactory.request_marker("T05-1")
        self.assertEqual(len(first), len(second))
        self.assertNotEqual(first, second)
        self.assertNotEqual(first.split()[0], second.split()[0])


if __name__ == "__main__":
    unittest.main()
