# OTel Collector Configuration

## Pipeline

```
otlp (receivers)
  → memory limiter → batch → 
  → tempo exporter (traces)
  → prometheus exporter (metrics)
  → loki exporter (logs)
```

## Sampling

40% sampling rate for traces (dev mode).
