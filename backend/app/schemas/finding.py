from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

FindingStatus = Literal[
    "open", "acknowledged", "in_progress", "fixed", "retest_required",
    "verified", "false_positive", "risk_accepted",
]


class EvidenceOut(BaseModel):
    id: int
    assessment_id: int
    finding_id: int | None = None
    category: str
    filename: str | None = None
    sha256: str
    source: str | None = None
    metadata_json: dict = {}
    captured_at: datetime
    immutable: bool

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    assessment_id: int
    asset_id: int
    title: str
    description: str | None = None
    cve: str | None = None
    cwe: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str
    affected_service: str | None = None
    affected_port: int | None = None
    risk_score: float
    risk_breakdown: dict = {}
    status: str
    confidence: float
    detection_source: str | None = None
    remediation: str | None = None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class FindingDetail(FindingOut):
    evidence: list[EvidenceOut] = []
    mitre_techniques: list[dict] = []
    ai_priority: str | None = None

    @field_validator("mitre_techniques", mode="before")
    @classmethod
    def _coerce_mitre(cls, v):
        if not v:
            return []
        out = []
        for t in v:
            d = getattr(t, "__dict__", None)
            if isinstance(d, dict):
                out.append(
                    {
                        "technique_id": d.get("technique_id"),
                        "name": d.get("name"),
                        "tactic": d.get("tactic"),
                    }
                )
            else:
                out.append(t)
        return out


class AIAnalysisOut(BaseModel):
    id: int
    finding_id: int
    analysis_type: str
    provider: str
    model: str | None = None
    severity: str | None = None
    confidence: float
    priority: str | None = None
    priority_deadline: str | None = None
    executive_summary: str | None = None
    technical_explanation: str | None = None
    risk_explanation: str | None = None
    attack_path_explanation: str | None = None
    false_positive_assessment: str | None = None
    false_positive_likelihood: float | None = None
    recommended_remediation: str | None = None
    basis: list = []
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class RemediationIn(BaseModel):
    plan: str = Field(min_length=3)
    assigned_to_name: str | None = None
    deadline: datetime | None = None


class RemediationOut(BaseModel):
    id: int
    finding_id: int
    assessment_id: int
    status: str
    assignee_name: str | None = None
    deadline: datetime | None = None
    remediation_plan: str | None = None
    retest_before_score: float | None = None
    retest_after_score: float | None = None
    retest_result: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ValidationTaskOut(BaseModel):
    id: int
    assessment_id: int
    finding_id: int
    level: int
    status: str
    verdict: str | None = None
    notes: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}