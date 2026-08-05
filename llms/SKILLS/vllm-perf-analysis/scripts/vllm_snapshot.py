#!/usr/bin/env python3
"""
Analyze vLLM /metrics snapshots and turn cumulative counters into interval rates.

Usage
-----
  # Live: scrape an endpoint 3 times, 5 min apart (the normal case)
  vllm_snapshot.py --url http://vllm:8000/metrics --samples 3 --interval 300

  # Offline: analyze saved snapshot files, oldest first
  vllm_snapshot.py --files 10am.txt 11am.txt 12pm.txt --gaps 3600,3600

  # Offline, unknown gaps: wall time is reconstructed via Little's law
  vllm_snapshot.py --files *.txt

  --json  emit machine-readable output instead of the text report

Why this exists: every vllm:*_total is a counter since process start and every
vllm:*_bucket is a cumulative histogram. Reading one snapshot tells you about
all of history, not about now. Everything here is computed as a DELTA between
consecutive snapshots, which is what "how is it behaving right now" means.
"""
import argparse, json, math, os, re, sys, time
from collections import defaultdict
from urllib.request import urlopen

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([-+0-9.eENaninf]+)\s*$')
LABEL_DIMS = ('finished_reason', 'source', 'reason', 'position')


# ----------------------------------------------------------------- parsing ---
def parse(text):
    """Prometheus text -> {(name, le): value}. Non-bucket series are summed
    across label dimensions; per-dimension values are kept as 'name@dim=val'."""
    out = {}
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue
        m = LINE.match(raw)
        if not m:
            continue
        name, labels, val = m.groups()
        try:
            v = float(val)
        except ValueError:
            continue
        le = ''
        if labels and 'le="' in labels:
            le = re.search(r'le="([^"]+)"', labels).group(1)
        key = (name, le)
        out[key] = v if name.endswith('_bucket') else out.get(key, 0.0) + v
        for dim in LABEL_DIMS:
            dm = re.search(dim + r'="([^"]+)"', labels or '')
            if dm:
                out[(f'{name}@{dim}={dm.group(1)}', '')] = v
    return out


def get(snap, name, default=None):
    v = snap.get((name, ''))
    return default if v is None else v


def buckets(snap, name):
    edges = [(k[1], v) for k, v in snap.items() if k[0] == name + '_bucket']
    f = lambda s: math.inf if s == '+Inf' else float(s)
    return sorted(((f(le), v) for le, v in edges), key=lambda x: x[0])


def hist_quantile(lo, hi, name, q):
    """Quantile over the traffic that happened BETWEEN two scrapes."""
    a, b = buckets(lo, name), buckets(hi, name)
    if not a or len(a) != len(b):
        return None
    deltas = [(le, y - x) for (le, x), (_, y) in zip(a, b)]
    total = deltas[-1][1]
    if total <= 0:
        return None
    target, prev_le, prev_c = q * total, 0.0, 0.0
    for le, c in deltas:
        if c >= target:
            if le == math.inf:
                return prev_le           # tail beyond last finite bucket
            if c == prev_c:
                return le
            return prev_le + (target - prev_c) / (c - prev_c) * (le - prev_le)
        prev_le, prev_c = le, c
    return None


def hist_mean(lo, hi, name):
    s, c = get(hi, name + '_sum'), get(lo, name + '_sum')
    n, m = get(hi, name + '_count'), get(lo, name + '_count')
    if None in (s, c, n, m) or n - m <= 0:
        return None
    return (s - c) / (n - m)


def delta(lo, hi, name):
    a, b = get(lo, name), get(hi, name)
    return None if a is None or b is None else b - a


def safe_div(a, b):
    return None if not a and a != 0 or not b else a / b


# ------------------------------------------------------- config extraction ---
def cache_config(snap_text):
    m = re.search(r'^vllm:cache_config_info\{(.*)\}', snap_text, re.M)
    if not m:
        return {}
    return dict(re.findall(r'([a-z_]+)="([^"]*)"', m.group(1)))


# --------------------------------------------------------------- reporting ---
LATENCY_HISTS = [
    ('vllm:time_to_first_token_seconds',            'TTFT'),
    ('vllm:inter_token_latency_seconds',            'ITL'),
    ('vllm:request_time_per_output_token_seconds',  'TPOT'),
    ('vllm:request_queue_time_seconds',             'queue'),
    ('vllm:request_prefill_time_seconds',           'prefill'),
    ('vllm:request_decode_time_seconds',            'decode'),
    ('vllm:request_inference_time_seconds',         'e2e_inference'),
]
SHAPE_HISTS = [
    ('vllm:request_prompt_tokens',      'prompt_tokens'),
    ('vllm:request_generation_tokens',  'output_tokens'),
    ('vllm:iteration_tokens_total',     'tokens_per_engine_step'),
]


def analyze_interval(lo, hi, wall):
    """All the per-interval numbers worth looking at."""
    r = {'wall_seconds': wall}
    d = lambda n: delta(lo, hi, n)

    reqs = d('vllm:request_success_total')
    r['requests_finished'] = reqs
    r['finish_reasons'] = {
        k[0].split('=', 1)[1]: delta(lo, hi, k[0])
        for k in hi if k[0].startswith('vllm:request_success_total@finished_reason=')
    }

    prompt = d('vllm:prompt_tokens_total')
    cached = d('vllm:prompt_tokens_cached_total')
    gen = d('vllm:generation_tokens_total')
    steps = d('vllm:iteration_tokens_total_count')
    iter_tok = d('vllm:iteration_tokens_total_sum')
    computed_prefill = None if None in (prompt, cached) else prompt - cached

    r['tokens'] = {
        'prompt_submitted': prompt,
        'prompt_cache_hit': cached,
        'prefill_computed': computed_prefill,
        'generated': gen,
        'iteration_total': iter_tok,
        'engine_steps': steps,
    }
    r['ratios'] = {
        'prefix_cache_hit_rate': safe_div(d('vllm:prefix_cache_hits_total'), d('vllm:prefix_cache_queries_total')),
        'external_cache_hit_rate': safe_div(d('vllm:external_prefix_cache_hits_total'), d('vllm:external_prefix_cache_queries_total')),
        'prefill_to_decode_ratio': safe_div(computed_prefill, gen),
        'pct_engine_work_prefill': safe_div(computed_prefill, iter_tok),
        'mean_tokens_per_step': safe_div(iter_tok, steps),
        'gen_tokens_per_step': safe_div(gen, steps),
        'spec_accept_rate': safe_div(d('vllm:spec_decode_num_accepted_tokens_total'), d('vllm:spec_decode_num_draft_tokens_total')),
        'spec_accepted_per_draft': safe_div(d('vllm:spec_decode_num_accepted_tokens_total'), d('vllm:spec_decode_num_drafts_total')),
    }

    if wall:
        r['rates_per_sec'] = {
            'requests': safe_div(reqs, wall),
            'prompt_tokens': safe_div(prompt, wall),
            'prefill_tokens_computed': safe_div(computed_prefill, wall),
            'generation_tokens': safe_div(gen, wall),
            'engine_steps': safe_div(steps, wall),
        }
        r['mean_engine_step_ms'] = safe_div(wall * 1000, steps)
        for label, metric, denom in [
            ('per_gpu_tflops', 'vllm:estimated_flops_per_gpu_total', 1e12),
            ('per_gpu_read_TBps', 'vllm:estimated_read_bytes_per_gpu_total', 1e12),
            ('per_gpu_write_TBps', 'vllm:estimated_write_bytes_per_gpu_total', 1e12),
        ]:
            v = d(metric)
            r.setdefault('gpu', {})[label] = safe_div(v, wall * denom) if v is not None else None

    r['latency'] = {}
    for metric, label in LATENCY_HISTS + SHAPE_HISTS:
        r['latency'][label] = {
            'count': delta(lo, hi, metric + '_count'),
            'mean': hist_mean(lo, hi, metric),
            'p50': hist_quantile(lo, hi, metric, 0.50),
            'p90': hist_quantile(lo, hi, metric, 0.90),
            'p99': hist_quantile(lo, hi, metric, 0.99),
        }
    return r


def little_law_wall(lo, hi):
    """No timestamps? Reconstruct elapsed time from L = lambda*W.
    Only as good as the two concurrency samples at the endpoints -- if either
    endpoint caught the engine idle, this is garbage. Reported, never trusted."""
    n = delta(lo, hi, 'vllm:request_success_total')
    w = hist_mean(lo, hi, 'vllm:request_inference_time_seconds')
    c = [get(s, 'vllm:num_requests_running') for s in (lo, hi)]
    if not n or not w or None in c:
        return None
    avg = (c[0] + c[1]) / 2
    return None if avg <= 0 else n * w / avg


def fmt(v, spec='.4g'):
    return '-' if v is None else format(v, spec)


def report(series_name, snaps, walls, cfg, derived_wall):
    out = []
    P = out.append
    P('=' * 96)
    P(f'{series_name}')
    P('=' * 96)

    labels = [s['label'][:17] for s in snaps]
    ivs = [f'{labels[i]}->{labels[i+1]}'[-17:] for i in range(len(snaps) - 1)]
    col = lambda vals, spec='.4g': ''.join(f'{fmt(v, spec):>18}' for v in vals)

    if cfg:
        blocks = int(cfg.get('num_gpu_blocks') or 0)
        bs = int(cfg.get('block_size') or 0)
        P('\nENGINE CONFIG')
        P(f"  block_size={bs}  num_gpu_blocks={blocks:,}  kv_cache_dtype={cfg.get('cache_dtype')}  "
          f"prefix_caching={cfg.get('enable_prefix_caching')}  gpu_mem_util={cfg.get('gpu_memory_utilization')}")
        if blocks and bs:
            P(f'  => KV cache capacity: {blocks*bs:,} tokens')

    P('\nSATURATION SIGNALS (instantaneous, at each scrape)')
    P(f"{'':<34}" + ''.join(f'{l:>18}' for l in labels))
    kvcap = int(cfg.get('num_gpu_blocks') or 0) * int(cfg.get('block_size') or 0)
    for metric, label, spec in [
        ('vllm:num_requests_running',   'running (batch size)', '.0f'),
        ('vllm:num_requests_waiting',   'WAITING (queue depth)', '.0f'),
        ('vllm:kv_cache_usage_perc',    'kv_cache_usage', '.3f'),
        ('vllm:num_preemptions',        'preemptions (cumulative)', '.0f'),
        ('vllm:num_dropped',            'dropped (cumulative)', '.0f'),
    ]:
        P(f'{label:<34}' + col([get(s['data'], metric) for s in snaps], spec))
    if kvcap:
        P(f"{'  => KV tokens resident':<34}" +
          col([(get(s['data'], 'vllm:kv_cache_usage_perc') or 0) * kvcap for s in snaps], ',.0f'))

    P('\nWALL CLOCK')
    P(f"{'':<34}" + ''.join(f'{i:>18}' for i in ivs))
    P(f"{'elapsed seconds':<34}" + col(walls, '.0f'))
    P(f"{'  source':<34}" + ''.join(f"{'LITTLE-LAW' if derived_wall else 'measured':>18}" for _ in ivs))
    if derived_wall:
        P('  NOTE: no scrape timestamps available; elapsed time reconstructed from')
        P('        Little\'s law (N x mean_e2e / mean_concurrency). Treat all per-second')
        P('        rates and GPU utilization below as approximate.')

    res = [analyze_interval(snaps[i]['data'], snaps[i + 1]['data'], walls[i]) for i in range(len(snaps) - 1)]

    P('\nLOAD')
    P(f"{'':<34}" + ''.join(f'{i:>18}' for i in ivs))
    P(f"{'requests finished':<34}" + col([r['requests_finished'] for r in res], '.0f'))
    if any(r.get('rates_per_sec') for r in res):
        for k, label in [('requests', 'requests/sec'), ('prompt_tokens', 'prompt tokens/sec (submitted)'),
                         ('prefill_tokens_computed', 'prefill tokens/sec (COMPUTED)'),
                         ('generation_tokens', 'generation tokens/sec'), ('engine_steps', 'engine steps/sec')]:
            P(f'{label:<34}' + col([(r.get('rates_per_sec') or {}).get(k) for r in res]))
        P(f"{'mean engine step (ms)':<34}" + col([r.get('mean_engine_step_ms') for r in res], '.1f'))
    for fr in sorted({k for r in res for k, v in r['finish_reasons'].items() if v}):
        P(f'{"  finish=" + fr:<34}' + col([r['finish_reasons'].get(fr) for r in res], '.0f'))

    P('\nWORKLOAD SHAPE (independent of wall clock)')
    P(f"{'':<34}" + ''.join(f'{i:>18}' for i in ivs))
    for k, label, spec in [
        ('prefix_cache_hit_rate', 'prefix cache hit rate', '.4f'),
        ('external_cache_hit_rate', 'external KV cache hit rate', '.4f'),
        ('prefill_to_decode_ratio', 'computed prefill : gen tokens', '.1f'),
        ('pct_engine_work_prefill', 'frac of engine work = prefill', '.3f'),
        ('mean_tokens_per_step', 'mean tokens per engine step', '.1f'),
        ('gen_tokens_per_step', 'gen tokens per engine step', '.2f'),
        ('spec_accept_rate', 'spec-decode accept rate', '.4f'),
        ('spec_accepted_per_draft', 'spec tokens accepted per draft', '.3f'),
    ]:
        vals = [r['ratios'].get(k) for r in res]
        if any(v is not None for v in vals):
            P(f'{label:<34}' + col(vals, spec))

    if any(r.get('gpu') for r in res):
        P('\nGPU WORK (per GPU; compare against your accelerator peak)')
        P(f"{'':<34}" + ''.join(f'{i:>18}' for i in ivs))
        for k, label in [('per_gpu_tflops', 'TFLOP/s'), ('per_gpu_read_TBps', 'HBM read TB/s'),
                         ('per_gpu_write_TBps', 'HBM write TB/s')]:
            P(f'{label:<34}' + col([(r.get('gpu') or {}).get(k) for r in res], '.2f'))

    P('\nLATENCY (over each interval, not since boot)')
    for metric, label in LATENCY_HISTS:
        P(f'\n  {label}')
        P(f"    {'':<16}" + ''.join(f'{i:>18}' for i in ivs))
        for stat in ('count', 'mean', 'p50', 'p90', 'p99'):
            P(f'    {stat:<16}' + col([r['latency'][label][stat] for r in res]))

    P('\nREQUEST SHAPE')
    for metric, label in SHAPE_HISTS:
        P(f'\n  {label}')
        P(f"    {'':<16}" + ''.join(f'{i:>18}' for i in ivs))
        for stat in ('mean', 'p50', 'p90', 'p99'):
            P(f'    {stat:<16}' + col([r['latency'][label][stat] for r in res]))

    P('\nTIME DECOMPOSITION (mean seconds per request)')
    P(f"{'':<34}" + ''.join(f'{i:>18}' for i in ivs))
    base = {}
    for label in ('queue', 'prefill', 'decode', 'e2e_inference'):
        vals = [r['latency'][label]['mean'] for r in res]
        base[label] = vals
        P(f'{label:<34}' + col(vals, '.3f'))
    if all(v is not None for v in base['e2e_inference']):
        P(f"{'delta e2e vs first interval':<34}" + col([v - base['e2e_inference'][0] for v in base['e2e_inference']], '+.3f'))
        for label in ('queue', 'prefill', 'decode'):
            if all(v is not None for v in base[label]):
                P(f'{"  ...attributable to " + label:<34}' + col([v - base[label][0] for v in base[label]], '+.3f'))

    gen = [r['latency']['output_tokens']['mean'] for r in res]
    tpot = [r['latency']['TPOT']['mean'] for r in res]
    if all(v for v in gen + tpot):
        P('\nDECODE SLOWDOWN: longer answers or slower tokens?')
        P(f"{'':<34}" + ''.join(f'{i:>18}' for i in ivs))
        P(f"{'mean output tokens/request':<34}" + col(gen, '.1f'))
        P(f"{'  x vs first interval':<34}" + col([v / gen[0] for v in gen], '.3f'))
        P(f"{'per-stream tokens/sec (1/TPOT)':<34}" + col([1 / v for v in tpot], '.1f'))
        P(f"{'  x vs first interval':<34}" + col([tpot[0] / v for v in tpot], '.3f'))
        P('  If output tokens grew, the workload changed. If 1/TPOT fell, the engine slowed.')

    return '\n'.join(out), res


# -------------------------------------------------------------------- main ---
def fetch(url, timeout=15):
    with urlopen(url, timeout=timeout) as r:
        return r.read().decode('utf-8', 'replace')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--url', help='vLLM /metrics endpoint to scrape repeatedly')
    src.add_argument('--files', nargs='+', help='saved snapshot files, OLDEST FIRST')
    ap.add_argument('--samples', type=int, default=3, help='scrapes to take (--url only)')
    ap.add_argument('--interval', type=float, default=300, help='seconds between scrapes (--url only)')
    ap.add_argument('--gaps', help='comma-separated seconds between --files snapshots')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    snaps, raw_texts, derived_wall, walls = [], [], False, []

    if args.url:
        for i in range(args.samples):
            if i:
                time.sleep(args.interval)
            t = time.time()
            text = fetch(args.url)
            snaps.append({'label': f't{i}', 'data': parse(text), 't': t})
            raw_texts.append(text)
            print(f'[scrape {i+1}/{args.samples}] {time.strftime("%H:%M:%S")}', file=sys.stderr)
        walls = [snaps[i + 1]['t'] - snaps[i]['t'] for i in range(len(snaps) - 1)]
    else:
        for p in args.files:
            text = open(p).read()
            snaps.append({'label': os.path.basename(p)[:16], 'data': parse(text), 't': None})
            raw_texts.append(text)
        if args.gaps:
            walls = [float(x) for x in args.gaps.split(',')]
            if len(walls) != len(snaps) - 1:
                ap.error(f'--gaps needs {len(snaps)-1} values, got {len(walls)}')
        else:
            derived_wall = True
            walls = [little_law_wall(snaps[i]['data'], snaps[i + 1]['data']) for i in range(len(snaps) - 1)]

    # Split by engine process identity. A restart resets every counter, so
    # deltas across a restart are meaningless (and often negative).
    groups = defaultdict(list)
    for s in snaps:
        groups[round(get(s['data'], 'process_start_time_seconds') or 0, 2)].append(s)

    if len(groups) > 1 and args.files:
        print('!! WARNING: these files come from more than one engine process '
              '(process_start_time_seconds differs).', file=sys.stderr)
        print('!! Either the pod restarted, or snapshots from different pods got mixed together.',
              file=sys.stderr)
        for st, members in sorted(groups.items()):
            print(f'!!   start={st}: {[m["label"] for m in members]}', file=sys.stderr)
        print('!! Analyzing each process separately.\n', file=sys.stderr)

    cfg = cache_config(raw_texts[0])
    all_json = {}
    for st, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        idx = [snaps.index(m) for m in members]
        w = [walls[i] for i in idx[:-1]] if len(groups) == 1 else \
            [little_law_wall(members[i]['data'], members[i + 1]['data']) for i in range(len(members) - 1)]
        dw = derived_wall or len(groups) > 1
        text, res = report(f'ENGINE process_start={st}', members, w, cfg, dw)
        all_json[str(st)] = {'snapshots': [m['label'] for m in members], 'intervals': res}
        if not args.json:
            print(text)

    if args.json:
        print(json.dumps({'config': cfg, 'engines': all_json}, indent=2, default=str))


if __name__ == '__main__':
    main()
