# Configuration

This directory contains configuration files for your application.

## Configuration Options

Configuration can be provided via:
1. YAML files in this directory
2. Environment variables
3. CLI arguments (highest priority)

## Example: settings.yaml

```yaml
# Application settings
app:
  name: "Your App"
  version: "0.1.0"
  debug: false

# LLM Provider settings
provider:
  default: "poolside"
  max_tokens: 3276

# MCP Server settings
mcp:
  timeout: 30  # seconds
  retry_attempts: 3

# Logging
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

## Example: Scope/Allowlist Configuration

For tools that operate on external resources, use an allowlist:

```yaml
# targets.yaml - Example for a scanning application
allowed_targets:
  # IP addresses
  - "192.168.1.0/24"
  - "10.0.0.0/8"

  # Hostnames
  - "*.internal.example.com"
  - "test.example.com"

blocked_targets:
  - "production.example.com"
  - "*.prod.internal"
```

## Loading Configuration

```python
from pathlib import Path
import yaml

def load_config(name: str = "settings.yaml") -> dict:
    """Load configuration from YAML file."""
    config_path = Path(__file__).parent / name
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}

# Usage
config = load_config()
debug_mode = config.get("app", {}).get("debug", False)
```

## Environment Variables

Override config values with environment variables:

```python
import os

def get_config_value(yaml_value, env_var: str, default=None):
    """Get config value with environment variable override."""
    return os.environ.get(env_var, yaml_value or default)

# Usage
api_key = get_config_value(
    config.get("api_key"),
    "YOUR_API_KEY",
    default=None
)
```

## Sensitive Values

Never commit sensitive values to config files. Use environment variables:

```yaml
# settings.yaml - Reference env vars
api:
  key: "${API_KEY}"  # Loaded from environment

# Or just document that it's needed:
# api:
#   key: <set via API_KEY environment variable>
```

## Per-Environment Configuration

For different environments, use separate files or environment prefixes:

```
config/
├── settings.yaml          # Base settings
├── settings.dev.yaml      # Development overrides
├── settings.prod.yaml     # Production overrides
└── README.md
```

Load with environment detection:

```python
import os

def load_config() -> dict:
    env = os.environ.get("APP_ENV", "dev")
    base = load_yaml("settings.yaml")
    override = load_yaml(f"settings.{env}.yaml")
    return {**base, **override}  # Override wins
```
