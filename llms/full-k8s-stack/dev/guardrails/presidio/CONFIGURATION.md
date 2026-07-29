# Presidio Configuration

## Services

Analyzer and Anonymizer deployed as separate services.

## Settings

```yaml
PRESIDIO_ANALYZER_CONFIDENCE_LEVELS:
  - PERSON: 0.8
  - EMAIL_ADDRESS: 0.9
  - SSN: 0.95
```

## Supported Entities

Default entities + custom regex patterns for API keys.
