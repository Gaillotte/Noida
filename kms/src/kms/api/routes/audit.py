"""Audit log query routes.

Prefix: /api/v1/audit
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kms.api.deps import require_permission
from kms.api.schemas import AuditEventResponse, AuditStatsResponse
from kms.auth.rbac import Permission
from kms.db.models import AuditEvent, User
from kms.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=list[AuditEventResponse],
    summary="Query audit events with optional filters",
)
async def query_audit_events(
    actor: str | None = Query(None, description="Filter by actor username"),
    operation: str | None = Query(None, description="Filter by operation name"),
    result: str | None = Query(None, description="Filter by result (Success / Failure)"),
    object_id: str | None = Query(None, description="Filter by object UUID"),
    from_dt: datetime | None = Query(None, description="Start of time window (ISO-8601)"),
    to_dt: datetime | None = Query(None, description="End of time window (ISO-8601)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Records to skip"),
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.AUDIT_READ)),
) -> list[AuditEventResponse]:
    stmt = select(AuditEvent).order_by(AuditEvent.timestamp.desc())

    if actor:
        stmt = stmt.where(AuditEvent.actor == actor)
    if operation:
        stmt = stmt.where(AuditEvent.operation == operation)
    if result:
        stmt = stmt.where(AuditEvent.result == result)
    if object_id:
        stmt = stmt.where(AuditEvent.object_id == object_id)
    if from_dt:
        # Ensure timezone awareness
        if from_dt.tzinfo is None:
            from_dt = from_dt.replace(tzinfo=timezone.utc)
        stmt = stmt.where(AuditEvent.timestamp >= from_dt)
    if to_dt:
        if to_dt.tzinfo is None:
            to_dt = to_dt.replace(tzinfo=timezone.utc)
        stmt = stmt.where(AuditEvent.timestamp <= to_dt)

    stmt = stmt.offset(offset).limit(limit)

    db_result = await session.execute(stmt)
    events: list[AuditEvent] = list(db_result.scalars().all())
    return [AuditEventResponse.model_validate(e) for e in events]


# ---------------------------------------------------------------------------
# GET /stats
# ---------------------------------------------------------------------------


@router.get(
    "/stats",
    response_model=AuditStatsResponse,
    summary="Aggregate audit counts by operation and result for the last 24 hours",
)
async def audit_stats(
    hours: int = Query(24, ge=1, le=720, description="Look-back window in hours"),
    session: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.AUDIT_READ)),
) -> AuditStatsResponse:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Total count
    total_result = await session.execute(
        select(func.count(AuditEvent.id)).where(AuditEvent.timestamp >= since)
    )
    total: int = total_result.scalar_one() or 0

    # Breakdown by operation
    op_rows = await session.execute(
        select(AuditEvent.operation, func.count(AuditEvent.id))
        .where(AuditEvent.timestamp >= since)
        .group_by(AuditEvent.operation)
        .order_by(func.count(AuditEvent.id).desc())
    )
    by_operation: dict[str, int] = {row[0]: row[1] for row in op_rows.all()}

    # Breakdown by result
    res_rows = await session.execute(
        select(AuditEvent.result, func.count(AuditEvent.id))
        .where(AuditEvent.timestamp >= since)
        .group_by(AuditEvent.result)
    )
    by_result: dict[str, int] = {row[0]: row[1] for row in res_rows.all()}

    return AuditStatsResponse(
        total=total,
        by_operation=by_operation,
        by_result=by_result,
        window_hours=hours,
    )
