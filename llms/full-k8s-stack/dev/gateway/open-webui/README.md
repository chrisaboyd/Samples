# OpenWebUI Chat Interface

Chat UI for human interaction with the AI gateway.

## Purpose

User-facing chat interface that points to LiteLLM or Bifrost endpoint.

## Dependencies

Gateway: LiteLLM or Bifrost
Platform: PostgreSQL (for conversation persistence)

## What it exposes

Service: `open-webui.gateway.svc.cluster.local:8080`

## Ports / Services

| Service | Port |
|---------|------|
| open-webui | 8080 (UI) |
