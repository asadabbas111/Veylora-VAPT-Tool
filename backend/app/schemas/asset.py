from datetime import datetime

from pydantic import BaseModel


class ServiceOut(BaseModel):
    id: int
    asset_id: int
    port: int
    protocol: str
    service_name: str | None = None
    version: str | None = None
    product: str | None = None
    risk_score: float
    metadata_json: dict = {}
    state: str

    model_config = {"from_attributes": True}


class AssetOut(BaseModel):
    id: int
    assessment_id: int
    ip_address: str | None = None
    ip_version: str
    hostname: str | None = None
    mac_address: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    criticality: float
    risk_score: float
    last_seen: datetime | None = None
    first_seen: datetime

    model_config = {"from_attributes": True}


class AssetDetail(AssetOut):
    services: list[ServiceOut] = []


class AssetUpdate(BaseModel):
    criticality: float | None = None
    hostname: str | None = None
    os_name: str | None = None


class ServiceDetail(BaseModel):
    id: int
    port: int
    protocol: str
    service_name: str | None = None
    version: str | None = None
    risk_score: float
    findings_count: int = 0