"""Audit Mode — GET /api/audit/evidence (live per-control evidence preview) and
POST /api/audit/report (generates + stores a timestamped PDF/JSON evidence pack), plus
GET /api/audit/reports (list) and GET /api/audit/reports/{id}/download (re-serve the
stored files) so generated packs are listable and reproducible.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.audit.aggregation import evidence_for_framework
from app.audit.report_builder import ReportContext, build_json_report, build_pdf_report
from app.dashboard.aggregation import CaseRow
from app.db.models import AuditReport, Case
from app.db.session import get_db
from app.mapping.framework_mapper import (
    LoadedFramework,
    framework_display_names,
    get_framework,
    resolve_framework_alias,
)
from app.models.schemas import (
    AuditCaseRef,
    AuditControlEvidence,
    AuditEvidenceResponse,
    AuditFramework,
    AuditReportListResponse,
    AuditReportRequest,
    AuditReportSummary,
)
from app.storage.audit_report_store import save_report_files

router = APIRouter(prefix="/api/audit", tags=["audit"])

DEFAULT_PERIOD_DAYS = 30


def _resolve_period(date_from: datetime | None, date_to: datetime | None) -> tuple[datetime, datetime]:
    period_end = date_to or datetime.utcnow()
    period_start = date_from or (period_end - timedelta(days=DEFAULT_PERIOD_DAYS))
    return period_start, period_end


def _to_case_row(case: Case) -> CaseRow:
    return CaseRow(
        id=str(case.id),
        created_at=case.created_at,
        verdict=case.verdict,
        indicators=case.indicators,
        framework_mappings=case.framework_mappings,
    )


def _load_framework_or_404(alias: AuditFramework) -> tuple[str, LoadedFramework]:
    framework_key = resolve_framework_alias(alias)
    framework = get_framework(framework_key)
    if framework is None:
        raise HTTPException(status_code=404, detail=f"Framework '{alias.value}' is not loaded.")
    return framework_key, framework


def _cases_in_period(db: Session, period_start: datetime, period_end: datetime) -> list[CaseRow]:
    cases_orm = (
        db.query(Case)
        .filter(Case.created_at >= period_start, Case.created_at <= period_end)
        .all()
    )
    return [_to_case_row(c) for c in cases_orm]


@router.get("/evidence", response_model=AuditEvidenceResponse)
async def get_audit_evidence(
    framework: AuditFramework,
    db: Session = Depends(get_db),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> AuditEvidenceResponse:
    framework_key, loaded = _load_framework_or_404(framework)
    period_start, period_end = _resolve_period(date_from, date_to)
    cases = _cases_in_period(db, period_start, period_end)

    evidence = evidence_for_framework(cases, loaded.controls_by_id, framework_key)

    return AuditEvidenceResponse(
        framework_key=framework_key,
        framework_name=loaded.name,
        period_start=period_start,
        period_end=period_end,
        controls=[
            AuditControlEvidence(
                control_id=e.control_id,
                control_name=e.control_name,
                detection_count=e.detection_count,
                operating=e.operating,
                sample_cases=[
                    AuditCaseRef(id=s.id, verdict=s.verdict, created_at=s.created_at)
                    for s in e.sample_cases
                ],
            )
            for e in evidence
        ],
        total_controls=len(evidence),
        operating_controls=sum(1 for e in evidence if e.operating),
    )


@router.post("/report", response_model=AuditReportSummary)
async def generate_audit_report(
    body: AuditReportRequest, db: Session = Depends(get_db)
) -> AuditReportSummary:
    framework_key, loaded = _load_framework_or_404(body.framework)
    period_start, period_end = _resolve_period(body.date_from, body.date_to)
    cases = _cases_in_period(db, period_start, period_end)

    evidence = evidence_for_framework(cases, loaded.controls_by_id, framework_key)
    operating_controls = sum(1 for e in evidence if e.operating)
    total_supporting_cases = len({cid for e in evidence for cid in e.supporting_case_ids})

    report_id = uuid.uuid4()
    generated_at = datetime.utcnow()
    ctx = ReportContext(
        framework_key=framework_key,
        framework_name=loaded.name,
        framework_version=loaded.version,
        period_start=period_start,
        period_end=period_end,
        generated_at=generated_at,
        controls=evidence,
        total_controls=len(evidence),
        operating_controls=operating_controls,
        total_supporting_cases=total_supporting_cases,
    )

    json_bytes = build_json_report(ctx)
    pdf_bytes = build_pdf_report(ctx)
    pdf_path, json_path = save_report_files(report_id, pdf_bytes, json_bytes)

    report = AuditReport(
        id=report_id,
        framework_key=framework_key,
        period_start=period_start,
        period_end=period_end,
        total_controls=len(evidence),
        operating_controls=operating_controls,
        total_supporting_cases=total_supporting_cases,
        pdf_path=pdf_path,
        json_path=json_path,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return AuditReportSummary(
        id=report.id,
        created_at=report.created_at,
        framework_key=report.framework_key,
        framework_name=loaded.name,
        period_start=report.period_start,
        period_end=report.period_end,
        total_controls=report.total_controls,
        operating_controls=report.operating_controls,
        total_supporting_cases=report.total_supporting_cases,
    )


@router.get("/reports", response_model=AuditReportListResponse)
async def list_audit_reports(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> AuditReportListResponse:
    query = db.query(AuditReport).order_by(AuditReport.created_at.desc())
    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()

    names = framework_display_names()
    items = [
        AuditReportSummary(
            id=row.id,
            created_at=row.created_at,
            framework_key=row.framework_key,
            framework_name=names.get(row.framework_key, row.framework_key),
            period_start=row.period_start,
            period_end=row.period_end,
            total_controls=row.total_controls,
            operating_controls=row.operating_controls,
            total_supporting_cases=row.total_supporting_cases,
        )
        for row in rows
    ]

    return AuditReportListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/reports/{report_id}/download")
async def download_audit_report(
    report_id: UUID, format: str = Query(..., pattern="^(pdf|json)$"), db: Session = Depends(get_db)
) -> Response:
    report = db.get(AuditReport, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")

    path = report.pdf_path if format == "pdf" else report.json_path
    media_type = "application/pdf" if format == "pdf" else "application/json"
    try:
        with open(path, "rb") as f:
            content = f.read()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Report file not found on disk.") from exc

    filename = f"aegis-audit-{report.framework_key}-{report_id}.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
