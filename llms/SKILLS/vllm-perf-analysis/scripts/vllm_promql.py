#!/usr/bin/env python3
"""
Pull the vLLM performance panel out of Prometheus (or a Grafana datasource proxy)
over a time range, so you can see WHEN behavior changed rather than just that it did.

Usage
-----
  # Direct Prometheus
  vllm_promql.py --url http://prometheus:9090 --hours 6

  # Through Grafana's datasource proxy (find the numeric/uid datasource id in
  # Grafana -> Connections -> Data sources -> the URL bar)
  vllm_promql.py --url https://grafana.example.com/api/datasources/proxy/uid/PABCD1234 \
                 --token "$GRAFANA_TOKEN" --hours 6

  # Narrow to one pod / model
  vllm_promql.py --url http://prometheus:9090 --hours 6 \
                 --selector 'model_name="Laguna-m-p6",pod="vllm-0"'

  --step 5m     resolution (default: range/60, min 30s)
  --json        emit raw series instead of the table
  --instant     evaluate a single point in time instead of a range

Everything below is expressed as a rate() or histogram_quantile() over the step,
never as a raw counter, because raw counters are since-boot and tell you nothing
about current behavior.
"""
import argparse, json, sys, time, urllib.parse, urllib.request

# label -> (promql template, format spec, one-line meaning)
# {S} is replaced by the label selector, {W} by the rate window.
QUERIES = [
    ('running',           'sum(vllm:num_requests_running{{{S}}})', '.1f',
     'requests in the execution batch'),
    ('WAITING',           'sum(vllm:num_requests_waiting{{{S}}})', '.1f',
     'queue depth -- >0 sustained means you are out of capacity'),
    ('kv_cache_usage',    'max(vllm:kv_cache_usage_perc{{{S}}})', '.3f',
     'fraction of KV cache blocks in use'),
    ('preempt/s',         'sum(rate(vllm:num_preemptions{{{S}}}[{W}]))', '.4f',
     'requests evicted mid-flight -- any nonzero value is real pain'),
    ('req/s',             'sum(rate(vllm:request_success_total{{{S}}}[{W}]))', '.3f',
     'completed requests per second'),
    ('prompt_tok/s',      'sum(rate(vllm:prompt_tokens_total{{{S}}}[{W}]))', '.4g',
     'prompt tokens submitted per second (includes cache hits)'),
    ('prefill_tok/s',     'sum(rate(vllm:prompt_tokens_total{{{S}}}[{W}])) '
                          '- sum(rate(vllm:prompt_tokens_cached_total{{{S}}}[{W}]))', '.4g',
     'prompt tokens actually COMPUTED per second -- the real prefill load'),
    ('gen_tok/s',         'sum(rate(vllm:generation_tokens_total{{{S}}}[{W}]))', '.4g',
     'output tokens produced per second'),
    ('prefix_hit',        'sum(rate(vllm:prefix_cache_hits_total{{{S}}}[{W}])) '
                          '/ sum(rate(vllm:prefix_cache_queries_total{{{S}}}[{W}]))', '.3f',
     'prefix cache hit rate -- a drop here explains a prefill spike'),
    ('steps/s',           'sum(rate(vllm:iteration_tokens_total_count{{{S}}}[{W}]))', '.2f',
     'engine iterations per second'),
    ('tok/step',          'sum(rate(vllm:iteration_tokens_total_sum{{{S}}}[{W}])) '
                          '/ sum(rate(vllm:iteration_tokens_total_count{{{S}}}[{W}]))', '.1f',
     'mean tokens per engine step -- rises when prefill packs the batch'),
    ('TTFT_p50',          'histogram_quantile(0.50, sum by (le) '
                          '(rate(vllm:time_to_first_token_seconds_bucket{{{S}}}[{W}])))', '.3f',
     'median time to first token'),
    ('TTFT_p95',          'histogram_quantile(0.95, sum by (le) '
                          '(rate(vllm:time_to_first_token_seconds_bucket{{{S}}}[{W}])))', '.3f',
     'tail time to first token -- what users complain about'),
    ('TPOT_mean',         'sum(rate(vllm:request_time_per_output_token_seconds_sum{{{S}}}[{W}])) '
                          '/ sum(rate(vllm:request_time_per_output_token_seconds_count{{{S}}}[{W}]))', '.4f',
     'mean seconds per output token -- 1/this is per-stream tokens/sec'),
    ('TPOT_p95',          'histogram_quantile(0.95, sum by (le) '
                          '(rate(vllm:request_time_per_output_token_seconds_bucket{{{S}}}[{W}])))', '.4f',
     'tail per-token latency'),
    ('ITL_p95',           'histogram_quantile(0.95, sum by (le) '
                          '(rate(vllm:inter_token_latency_seconds_bucket{{{S}}}[{W}])))', '.4f',
     'tail inter-token gap -- visible as stutter in streaming UIs'),
    ('queue_p95',         'histogram_quantile(0.95, sum by (le) '
                          '(rate(vllm:request_queue_time_seconds_bucket{{{S}}}[{W}])))', '.3f',
     'tail time spent WAITING before execution'),
    ('e2e_mean',          'sum(rate(vllm:request_inference_time_seconds_sum{{{S}}}[{W}])) '
                          '/ sum(rate(vllm:request_inference_time_seconds_count{{{S}}}[{W}]))', '.2f',
     'mean seconds from scheduled to finished'),
    ('prompt_tok/req',    'sum(rate(vllm:request_prompt_tokens_sum{{{S}}}[{W}])) '
                          '/ sum(rate(vllm:request_prompt_tokens_count{{{S}}}[{W}]))', '.4g',
     'mean prompt size -- a change here is a workload change, not a regression'),
    ('out_tok/req',       'sum(rate(vllm:request_generation_tokens_sum{{{S}}}[{W}])) '
                          '/ sum(rate(vllm:request_generation_tokens_count{{{S}}}[{W}]))', '.1f',
     'mean answer length -- longer answers raise e2e without slowing the engine'),
    ('spec_accept',       'sum(rate(vllm:spec_decode_num_accepted_tokens_total{{{S}}}[{W}])) '
                          '/ sum(rate(vllm:spec_decode_num_draft_tokens_total{{{S}}}[{W}]))', '.3f',
     'speculative decode acceptance -- a drop silently costs you throughput'),
    ('gpu_TFLOPs',        'sum(rate(vllm:estimated_flops_per_gpu_total{{{S}}}[{W}])) / 1e12', '.1f',
     'per-GPU compute -- divide by your accelerator peak to get MFU'),
    ('gpu_read_TB/s',     'sum(rate(vllm:estimated_read_bytes_per_gpu_total{{{S}}}[{W}])) / 1e12', '.2f',
     'per-GPU HBM reads -- divide by peak bandwidth to get MBU'),
]


def q(base, path, params, token=None, timeout=60):
    url = base.rstrip('/') + path + '?' + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.load(r)
    if body.get('status') != 'success':
        raise RuntimeError(f"query failed: {body.get('error', body)}\n  query={params.get('query')}")
    return body['data']['result']


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--url', required=True, help='Prometheus base URL, or Grafana datasource proxy URL')
    ap.add_argument('--token', help='bearer token (Grafana service-account token)')
    ap.add_argument('--hours', type=float, default=6)
    ap.add_argument('--step', help='e.g. 5m; default range/60, floor 30s')
    ap.add_argument('--selector', default='', help='extra label matchers, e.g. model_name="x",pod="y"')
    ap.add_argument('--instant', action='store_true', help='single point instead of a range')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    end = time.time()
    start = end - args.hours * 3600
    step_s = max(30, int(args.hours * 3600 / 60))
    step = args.step or f'{step_s}s'
    window = step if step.endswith(('m', 'h')) else f'{max(60, step_s * 2)}s'

    out = {}
    for name, tmpl, spec, meaning in QUERIES:
        query = tmpl.format(S=args.selector, W=window)
        try:
            if args.instant:
                res = q(args.url, '/api/v1/query', {'query': query, 'time': end}, args.token)
                vals = [[end, res[0]['value'][1]]] if res else []
            else:
                res = q(args.url, '/api/v1/query_range',
                        {'query': query, 'start': start, 'end': end, 'step': step}, args.token)
                vals = res[0]['values'] if res else []
        except Exception as e:
            print(f'  ! {name}: {e}', file=sys.stderr)
            vals = []
        out[name] = {'query': query, 'spec': spec, 'meaning': meaning, 'values': vals}

    if args.json:
        print(json.dumps(out, indent=2))
        return

    stamps = sorted({float(t) for v in out.values() for t, _ in v['values']})
    if not stamps:
        print('No data returned. Check --url, --selector, and that vLLM metrics are being scraped.',
              file=sys.stderr)
        sys.exit(1)
    # Thin to at most 12 columns so the table stays readable.
    keep = stamps[::max(1, len(stamps) // 12)][:12]

    print(f'# vLLM metrics  |  last {args.hours}h  |  step={step}  rate window={window}')
    print(f'# selector: {{{args.selector}}}\n')
    hdr = f"{'metric':<16}" + ''.join(f'{time.strftime("%H:%M", time.localtime(t)):>11}' for t in keep)
    print(hdr)
    print('-' * len(hdr))
    for name, d in out.items():
        m = {float(t): val for t, val in d['values']}
        row = f'{name:<16}'
        for t in keep:
            v = m.get(t)
            try:
                row += f'{float(v):>11{d["spec"]}}' if v is not None else f"{'-':>11}"
            except (TypeError, ValueError):
                row += f"{'-':>11}"

        print(row)

    print('\n# what each row means')
    for name, d in out.items():
        print(f'  {name:<16} {d["meaning"]}')


if __name__ == '__main__':
    main()
