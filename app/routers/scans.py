from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.schemas.scan import ScanRequest, ScanResponse, ScanListResponse
from app.services.auth_service import get_current_user
from app.celery_app import celery_app

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Criar um novo scan de vulnerabilidades (processado em background)."""
    # Clean target
    target = scan_data.target.strip().lower()
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target não pode ser vazio",
        )

    scan = Scan(
        user_id=current_user.id,
        target=target,
    )
    db.add(scan)
    await db.commit()

    # Re-fetch with findings eagerly loaded
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan.id)
        .options(selectinload(Scan.findings))
    )
    scan = result.scalar_one()

    # Dispatch scan to Celery worker by task name
    celery_app.send_task("app.workers.scan_task.run_scan", args=[scan.id])

    return scan


@router.get("", response_model=list[ScanListResponse])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Listar todos os scans do usuário autenticado."""
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .options(selectinload(Scan.findings))
        .order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()

    return [
        ScanListResponse(
            id=scan.id,
            target=scan.target,
            status=scan.status,
            risk_score=scan.risk_score,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            findings_count=len(scan.findings),
        )
        for scan in scans
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Obter detalhes de um scan específico, incluindo findings."""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id, Scan.user_id == current_user.id)
        .options(selectinload(Scan.findings))
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan não encontrado",
        )

    return scan
