from app.ai.providers.base import AIProvider
from app.ai.providers.heuristic import HeuristicProvider
from app.ai.providers.ollama import OllamaProvider
from app.ai.providers.openai import OpenAIProvider
from app.config import settings


def get_provider() -> AIProvider:
    mapping = {
        "rule": HeuristicProvider,
        "heuristic": HeuristicProvider,
        "openai": OpenAIProvider,
        "ollama": OllamaProvider,
    }
    cls = mapping.get(settings.AI_PROVIDER, HeuristicProvider)
    return cls()


providers_registry = {
    "rule": HeuristicProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
}


def available_providers() -> list[dict]:
    out = []
    for name, cls in providers_registry.items():
        p = cls()
        ok, reason = p.available()
        out.append({"name": name, "available": ok, "reason": reason})
    return out