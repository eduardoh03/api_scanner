import asyncio
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.celery_app import celery_app
from app.config import get_settings
from app.models.scan import Scan, ScanStatus, Finding, Severity
from app.scanners import PortScanner, HeaderAnalyzer, SSLChecker, DNSRecon, CVELookup
from app.scanners.base import ScanFinding

settings = get_settings()

# Celery uses sync DB since it runs in its own process
sync_engine = create_engine(
    settings.SYNC_DATABASE_URL,
    echo=settings.DEBUG,
)
SyncSession = sessionmaker(sync_engine)

# All scanner modules
SCANNERS = [
    PortScanner(),
    HeaderAnalyzer(),
    SSLChecker(),
    DNSRecon(),
    CVELookup(),
]

SEVERITY_SCORES = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 0,
}


def calculate_risk_score(findings: list[ScanFinding]) -> int:
    """
    Calculate overall risk score (0-100) based on findings.
    Uses a weighted decay formula so multiple low severity findings don't
    artificially inflate the score to 100.
    """
    if not findings:
        return 0

    # Counts per severity
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    # Base weights
    score = 0.0

    # Critical: starts at 40, each additional adds less (decay 0.7)
    # 1 critical = 40, 2 = 68, 3 = 87...
    for i in range(counts["critical"]):
        score += 40 * (0.7**i)

    # High: starts at 20, decay 0.6
    for i in range(counts["high"]):
        score += 20 * (0.6**i)

    # Medium: starts at 8, decay 0.5
    for i in range(counts["medium"]):
        score += 8 * (0.5**i)

    # Low: starts at 2, decay 0.5
    for i in range(counts["low"]):
        score += 2 * (0.5**i)

    # Cap at 100
    return int(min(score, 100))


async def _run_scanners(target: str) -> list[ScanFinding]:
    """Run all scanner modules concurrently."""
    tasks = [scanner.scan(target) for scanner in SCANNERS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: list[ScanFinding] = []
    for result in results:
        if isinstance(result, Exception):
            all_findings.append(
                ScanFinding(
                    module="error",
                    severity="info",
                    title=f"Erro em módulo de scanning",
                    description=f"Um módulo encontrou um erro: {str(result)}",
                )
            )
        else:
            all_findings.extend(result)

    return all_findings


@celery_app.task(name="app.workers.scan_task.run_scan", bind=True, max_retries=2)
def run_scan(self, scan_id: str):
    """Execute all scanners for a given scan."""
    session: Session = SyncSession()

    try:
        # Update scan status to RUNNING
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {"error": f"Scan {scan_id} not found"}

        scan.status = ScanStatus.RUNNING
        session.commit()

        # Run all scanners
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            findings = loop.run_until_complete(_run_scanners(scan.target))
        finally:
            loop.close()

        # Map severity strings to enum
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        # Save findings to database
        for finding in findings:
            db_finding = Finding(
                scan_id=scan_id,
                module=finding.module,
                severity=severity_map.get(finding.severity, Severity.INFO),
                title=finding.title,
                description=finding.description,
                recommendation=finding.recommendation,
            )
            session.add(db_finding)

        # Update scan status and counts
        scan.status = ScanStatus.COMPLETED
        scan.risk_score = calculate_risk_score(findings)
        
        scan.completed_at = datetime.now(timezone.utc)
        session.commit()

        return {
            "scan_id": scan_id,
            "status": "completed",
            "findings_count": len(findings),
            "risk_score": scan.risk_score,
        }

    except Exception as e:
        session.rollback()
        # Update scan to failed
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            session.commit()
        raise self.retry(exc=e, countdown=30)

    finally:
        session.close()
