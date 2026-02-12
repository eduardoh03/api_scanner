from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, computed_field
from app.models.scan import ScanStatus, Severity


class ScanRequest(BaseModel):
    target: str


class FindingResponse(BaseModel):
    id: UUID
    module: str
    severity: Severity | str
    title: str
    description: str
    recommendation: str | None = None

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    id: UUID
    target: str
    status: ScanStatus
    risk_score: int | None = None
    created_at: datetime
    completed_at: datetime | None = None

    findings: list[FindingResponse] = []

    class Config:
        from_attributes = True


    @computed_field
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if str(f.severity.value).lower() == "critical")

    @computed_field
    def high_count(self) -> int:
        return sum(1 for f in self.findings if str(f.severity.value).lower() == "high")

    @computed_field
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if str(f.severity.value).lower() == "medium")

    @computed_field
    def low_count(self) -> int:
        return sum(1 for f in self.findings if str(f.severity.value).lower() == "low")

    @computed_field
    def info_count(self) -> int:
        return sum(1 for f in self.findings if str(f.severity.value).lower() == "info")



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
