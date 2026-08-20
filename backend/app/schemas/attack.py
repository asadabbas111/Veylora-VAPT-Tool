from datetime import datetime

from pydantic import BaseModel


class PathNodeOut(BaseModel):
    id: str
    label: str
    source: str | None = None
    risk: float | None = None


class PathEdgeOut(BaseModel):
    from_node: str
    to_node: str
    rel: str


class AttackPathOut(BaseModel):
    id: int
    assessment_id: int
    name: str
    description: str | None = None
    start_node: str | None = None
    end_node: str | None = None
    end_node_type: str
    path_length: int
    cumulative_risk: float
    confidence: float
    vulnerability_count: int
    nodes_json: list = []
    edges_json: list = []
    created_at: datetime

    model_config = {"from_attributes": True}


class GraphSummaryOut(BaseModel):
    node_count: int
    edge_count: int
    path_count: int
    max_risk: float
    summary: str = ""


class ValidationRequest(BaseModel):
    level: int = 1  # 0 passive, 1 non-destructive, 2 controlled poc, 3 advanced


class ValidationApprove(BaseModel):
    approve: bool = True
    notes: str | None = None