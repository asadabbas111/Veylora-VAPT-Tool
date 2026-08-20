"""Ollama provider for local LLMs (llama3, mistral, etc.). Fully offline.
"""

import json
from typing import Any

import httpx

from app.ai.providers.base import AIProvider
from app.config import settings

_SYSTEM = _SYSTEM = (
    "You are a senior penetration-testing analyst. Analyze the structured security "
    "data provided. Only make claims backed by the data. Respond with a JSON object "
    "with these keys: severity, confidence, priority, priority_deadline, "
    "executive_summary, technical_explanation, risk_explanation, "
    "attack_path_explanation, false_positive_assessment, false_positive_likelihood, "
    "recommended_remediation, basis. Do not invent evidence."
)


class OllamaProvider(AIProvider):
    name = "ollama"

    def available(self) -> tuple[bool, str]:
        try:
            resp = httpx.get(f"{settings.AI_BASE_URL.rstrip('/')}/api/version", timeout=5)
            return resp.status_code < 300, "Ollama reachable"
        except Exception:  # pragma: no cover
            return False, "Ollama not reachable"

    def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        ok, msg = self.available()
        if not ok:
            raise RuntimeError(msg)
        url = f"{settings.AI_BASE_URL.rstrip('/')}/api/generate"
        prompt = (
            f"{_SYSTEM}\n\nStructured finding context:\n{json.dumps(context, default=str)}"
        )
        resp = httpx.post(url, json={"model": settings.AI_MODEL, "prompt": prompt, "stream": False}, timeout=90)
        resp.raise_for_status()
        text = resp.json()["response"]  # type: ignore[index]
        text = text.strip()
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Ollama response was not JSON")
        parsed = json.loads(text[start : end + 1])
        parsed["provider"] = self.name
        parsed["model"] = settings.AI_MODEL
        return parsed