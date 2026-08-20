from abc import ABC, abstractmethod
from typing import Any


class AIProvider(ABC):
    """Base interface for any AI analysis provider.

    Providers receive a fully structured context (never raw scanner output) and
    must return a structured decision object. Providers must never invent
    evidence: every claim the provider makes should reference keys present in
    the provided context.
    """

    name: str = "base"

    @abstractmethod
    def available(self) -> tuple[bool, str]:
        """Return (available, reason)."""

    @abstractmethod
    def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        """Analyze a structured finding context and return a structured decision.

        Expected keys in the returned dict (all optional but at least one
        should be populated):
            - severity, confidence, priority, priority_deadline
            - executive_summary, technical_explanation, risk_explanation
            - attack_path_explanation, false_positive_assessment
            - false_positive_likelihood, recommended_remediation, basis
        """