"""
sinX Threat Hunter - SIEM API
Log ingestion, querying, and management
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from ..core.database import get_db
from ..core.security import get_current_user
from ..models.logs import Log
from ..models.users import User

router = APIRouter(prefix="/siem")


# Pydantic schemas
class LogCreate(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    message: str
    raw_log: Optional[str] = None
    parsed_data: Optional[dict] = None
    log_source: Optional[str] = None
    hostname: Optional[str] = None


class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: Optional[str]
    source_port: Optional[int]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    event_type: Optional[str]
    severity: Optional[str]
    message: str
    hostname: Optional[str]
    log_source: Optional[str]


class LogQueryRequest(BaseModel):
    query: str  # KQL-like query
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = 1000


@router.post("/ingest", status_code=201)
async def ingest_log(
    log_data: LogCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Ingest a single log entry"""

    new_log = Log(
        timestamp=log_data.timestamp or datetime.utcnow(),
        source_ip=log_data.source_ip,
        source_port=log_data.source_port,
        dest_ip=log_data.dest_ip,
        dest_port=log_data.dest_port,
        event_type=log_data.event_type,
        severity=log_data.severity or "info",
        message=log_data.message,
        raw_log=log_data.raw_log or log_data.message,
        parsed_data=log_data.parsed_data,
        log_source=log_data.log_source or "api",
        hostname=log_data.hostname,
    )

    db.add(new_log)
    await db.commit()
    await db.refresh(new_log)

    return {"id": new_log.id, "status": "ingested", "timestamp": new_log.timestamp}


@router.post("/ingest/batch", status_code=201)
async def ingest_logs_batch(
    logs: list[LogCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Batch ingest multiple log entries"""

    new_logs = []
    for log_data in logs:
        new_log = Log(
            timestamp=log_data.timestamp or datetime.utcnow(),
            source_ip=log_data.source_ip,
            source_port=log_data.source_port,
            dest_ip=log_data.dest_ip,
            dest_port=log_data.dest_port,
            event_type=log_data.event_type,
            severity=log_data.severity or "info",
            message=log_data.message,
            raw_log=log_data.raw_log or log_data.message,
            parsed_data=log_data.parsed_data,
            log_source=log_data.log_source or "api",
            hostname=log_data.hostname,
        )
        new_logs.append(new_log)

    db.add_all(new_logs)
    await db.commit()

    return {"count": len(new_logs), "status": "ingested"}


@router.get("/logs", response_model=list[LogResponse])
async def query_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    hostname: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 100
):
    """Query logs with filters"""

    query = select(Log)

    # Apply filters
    if event_type:
        query = query.where(Log.event_type == event_type)
    if severity:
        query = query.where(Log.severity == severity)
    if source_ip:
        query = query.where(Log.source_ip == source_ip)
    if hostname:
        query = query.where(Log.hostname == hostname)
    if start_time:
        query = query.where(Log.timestamp >= start_time)
    if end_time:
        query = query.where(Log.timestamp <= end_time)

    # Order and pagination
    query = query.order_by(desc(Log.timestamp)).offset(skip).limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()

    return logs


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get SIEM statistics"""

    # Total logs
    total_result = await db.execute(select(func.count(Log.id)))
    total_logs = total_result.scalar()

    # Count by severity
    severity_result = await db.execute(
        select(Log.severity, func.count(Log.id)).group_by(Log.severity)
    )
    severity_counts = {row[0]: row[1] for row in severity_result.all()}

    # Count by event type
    event_result = await db.execute(
        select(Log.event_type, func.count(Log.id)).group_by(Log.event_type).limit(10)
    )
    event_counts = {row[0]: row[1] for row in event_result.all()}

    return {
        "total_logs": total_logs,
        "severity_breakdown": severity_counts,
        "top_event_types": event_counts,
    }
