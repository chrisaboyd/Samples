FROM --platform=linux/amd64 python:3.12-alpine

RUN addgroup -S benchmark && adduser -S -G benchmark -u 10001 benchmark
WORKDIR /app
COPY --chown=benchmark:benchmark benchmark.py /app/benchmark.py
USER 10001
ENTRYPOINT ["python3", "/app/benchmark.py"]
