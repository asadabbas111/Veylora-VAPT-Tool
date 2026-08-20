from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.services.scope_service import classify_target


class ScopeIn(BaseModel):
    target: str
    target_type: str | None = None
    description: str | None = None

    @field_validator("target")
    @classmethod
    def _valid_target(cls, v: str) -> str:
        classify_target(v)  # raises if unrecognized
        return v.strip()


class ScopeOut(BaseModel):
    id: int
    assessment_id: int
    target: str
    target_type: str
    description: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class TargetIn(BaseModel):
    target: str
    target_type: str | None = None

    @field_validator("target")
    @classmethod
    def _valid_target(cls, v: str) -> str:
        classify_target(v)
        return v.strip()


class TargetOut(BaseModel):
    id: int
    assessment_id: int
    target: str
    target_type: str
    in_scope: bool
    validation_note: str | None = None
    added_at: datetime

    model_config = {"from_attributes": True}


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    description: str | None = None
    client_name: str | None = None
    assessment_type: str = "vulnerability_assessment"
    start_date: date
    end_date: date | None = None
    rules_of_engagement: str | None = None
    validation_level: int = 1


class AssessmentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    client_name: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    validation_level: int | None = None
    status: Literal["draft", "scoping", "running", "paused", "completed", "cancelled"] | None = None


class AssessmentOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    client_name: str | None = None
    assessment_type: str
    start_date: date
    end_date: date | None = None
    rules_of_engagement: str | None = None
    validation_level: int
    status: str
    progress: float
    stage: str
    stage_log: dict
    owner_id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssessmentDetail(AssessmentOut):
    scopes: list[ScopeOut] = []
    targets: list[TargetOut] = []


class JobOut(BaseModel):
    id: int
    assessment_id: int | None = None
    task_type: str
    status: str
    progress: float
    log: str
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


class WorkflowStart(BaseModel):
    """Start a workflow stage."""
    stage: Literal["asset_discovery", "service_enumeration", "vulnerability_scan", "risk_calculation",
                   "attack_path_analysis", "ai_analysis", "report_generation", "full"]
    adapters: list[str] | None = None