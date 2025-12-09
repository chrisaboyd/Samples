# LLM Providers package
from .base import LLMProvider, LLMResponse, ToolCall
from .anthropic import AnthropicProvider
from .poolside import PoolsideProvider

__all__ = [
    "LLMProvider",
    "LLMResponse",
    "ToolCall",
    "AnthropicProvider",
    "PoolsideProvider",
]


def get_provider(name: str, model: str | None = None) -> LLMProvider:
    """
    Factory function to get a provider by name.

    Args:
        name: Provider name ("anthropic", "poolside", etc.)
        model: Optional model override

    Returns:
        Configured LLMProvider instance
    """
    providers = {
        "anthropic": AnthropicProvider,
        "claude": AnthropicProvider,  # alias
        "poolside": PoolsideProvider,
        "malibu": PoolsideProvider,  # alias
    }

    if name.lower() not in providers:
        available = ", ".join(sorted(set(providers.keys())))
        raise ValueError(f"Unknown provider: {name}. Available: {available}")

    provider_class = providers[name.lower()]

    if model:
        return provider_class(model=model)
    return provider_class()
