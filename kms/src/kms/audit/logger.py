import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from kms.db.models import AuditEvent

_log = logging.getLogger("kms.audit")


async def record(
    session: AsyncSession,
    *,
    actor: str,
    operation: str,
    result: str = "Success",
    protocol: str = "REST",
    actor_ip: Optional[str] = None,
    object_id: Optional[str] = None,
    result_reason: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> AuditEvent:
    event = AuditEvent(
        actor=actor,
        actor_ip=actor_ip,
        protocol=protocol,
        operation=operation,
        object_id=object_id,
        result=result,
        result_reason=result_reason,
        details=details,
    )
    session.add(event)
    # Flush so id is assigned; caller commits as part of the request transaction.
    await session.flush()

    _log.info(
        json.dumps(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "ip": actor_ip,
                "proto": protocol,
                "op": operation,
                "obj": object_id,
                "result": result,
                "reason": result_reason,
                **(details or {}),
            }
        )
    )
    return event
