from pydantic import BaseModel
from datetime import datetime
from app.models.scan import ScanStatus, Severity


class ScanRequest(BaseModel):
    target: str


class FindingResponse(BaseModel):
    id: str
    module: str
    severity: Severity
    title: str
    description: str
    recommendation: str | None

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    id: str
    target: str
    status: ScanStatus
    risk_score: int | None
    created_at: datetime
    completed_at: datetime | None
    findings: list[FindingResponse] = []

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    id: str
    target: str
    status: ScanStatus
    risk_score: int | None
    created_at: datetime
    completed_at: datetime | None
    findings_count: int = 0

    class Config:
        from_attributes = True
