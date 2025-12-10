# MCP Agent Template

A skeleton framework for building MCP (Model Context Protocol) servers with LLM agents.

## Overview

This template provides the foundational structure for creating AI-powered tools using:
- **MCP Servers**: Expose tools via the Model Context Protocol
- **Agents**: LLM-powered orchestrators that use MCP tools
- **Providers**: Pluggable LLM backends

## Quick Start

1. **Copy this template** to a new directory
2. **Rename** `your_project` references throughout
3. **Implement** your MCP server tools in `mcp_servers/your_server/tools/`
4. **Create** your agent in `agents/your_agent.py`
5. **Configure** your CLI commands in `cli.py`

## Directory Structure

```
template/
├── README.md                 # This file
├── pyproject.toml           # Project dependencies and metadata
├── cli.py                   # CLI entry point
│
├── mcp_servers/             # MCP server implementations
│   └── your_server/         # Replace with your server name
│       ├── server.py        # MCP server entry point
│       └── tools/           # Individual tool implementations
│
├── agents/                  # LLM agents
│   ├── base.py             # Base agent class (shared infrastructure)
│   ├── your_agent.py       # Your agent implementation
│   └── providers/          # LLM provider adapters
│       ├── base.py         # Provider interface
│       ├── poolside.py     # Poolside implementation
│       └── _template/      # Template for new providers
│
├── prompts/                 # System prompts for agents
│   └── your_agent.md       # Prompt for your agent
│
└── config/                  # Configuration files
    └── settings.yaml       # Runtime configuration
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLI (cli.py)                     │
│              User-facing commands                   │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                  Agent (agents/)                    │
│         LLM-powered task orchestration              │
│    ┌─────────────────────────────────────────┐      │
│    │        LLM Provider (providers/)        │      │
│    │   Poolside  / Ollama / etc.             │      │
│    └─────────────────────────────────────────┘      │
└────────────────────────┬────────────────────────────┘
                         │ MCP Protocol (stdio)
                         ▼
┌─────────────────────────────────────────────────────┐
│              MCP Server (mcp_servers/)              │
│         Tools exposed via Model Context Protocol    │
└─────────────────────────────────────────────────────┘
```

## How It Works

1. **User** invokes a CLI command
2. **CLI** creates an Agent with a task description
3. **Agent** connects to MCP Server(s) via stdio
4. **Agent** sends task to LLM with available tools
5. **LLM** decides which tools to call
6. **Agent** executes tool calls via MCP
7. **Agent** returns results to LLM
8. Loop continues until LLM completes the task

## Getting Started

See each folder's README.md for specific implementation guidance:

- [mcp_servers/README.md](mcp_servers/README.md) - How to build MCP servers and tools
- [agents/README.md](agents/README.md) - How to create agents
- [agents/providers/README.md](agents/providers/README.md) - How to add LLM providers
- [prompts/README.md](prompts/README.md) - How to write effective system prompts
- [config/README.md](config/README.md) - Configuration options

## Installation

```bash
# Install dependencies
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

## Usage

```bash
# Run your CLI
python cli.py --help

# Or if installed
your-cli --help
```

## Dependencies

Core dependencies:
- `mcp` - Model Context Protocol SDK
- `poolside` - Poolside API client (default provider)
- `click` - CLI framework
- `rich` - Terminal formatting
- `pydantic` - Data validation

## License

[Add your license here]
