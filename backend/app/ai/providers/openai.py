"""OpenAI-compatible chat provider (works with OpenAI, Azure OpenAI, or any
compatible endpoint). Only used when configured via AI_PROVIDER=openai.
"""

import json
from typing import Any

import httpx

from app.ai.providers.base import AIProvider
from app.config import settings

_SYSTEM = (
    "You are a senior penetration-testing analyst. Analyze the structured security "
    "data provided. Only make claims backed by the data. Return a single JSON object "
    "with these keys: severity, confidence, priority, priority_deadline, "
    "executive_summary, technical_explanation, risk_explanation, "
    "attack_path_explanation, false_positive_assessment, false_positive_likelihood, "
    "recommended_remediation, basis. Do not invent evidence."
)


class OpenAIProvider(AIProvider):
    name = "openai"

    def available(self) -> tuple[bool, str]:
        if not settings.AI_API_KEY:
            return False, "AI_API_KEY not configured"
        return True, "OpenAI provider configured"

    def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        ok, msg = self.available()
        if not ok:
            raise RuntimeError(msg)
        url = f"{settings.AI_BASE_URL.rstrip('/')}/v1/chat/completions"
        headers = {"Authorization": f"Bearer {settings.AI_API_KEY}"}
        payload = {
            "model": settings.AI_MODEL,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": json.dumps(context, default=str)},
            ],
            "temperature": 0.2,
        }
        resp = httpx.post(url, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]  # type: ignore[index]
        parsed = json.loads(text)
        parsed["provider"] = self.name
        parsed["model"] = settings.AI_MODEL
        return parsed